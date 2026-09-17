"""Supervisor-owned execution for Provider-generated gateway tool calls.

The transparent OpenAI proxy deliberately stops before executing a Provider tool
call.  This module is the explicit second half of that contract: it loads the
immutable gateway audit, verifies the Agent/session/provider binding, executes the
recorded call in the Agent-scoped local runtime, and appends a server-observed receipt.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from time import perf_counter
from typing import Any
from uuid import uuid4

from apps.api.agent_supervisor.domains.governance.integrity import (
    audit_hash,
    audit_signature_required,
    verify_audit_signature,
)
from apps.api.agent_supervisor.domains.governance.redaction import redact_sensitive
from apps.api.agent_supervisor.domains.governance.task_profiles import task_binding_mismatch_reason
from apps.api.agent_supervisor.domains.runtime.execution_receipts import (
    complete_execution,
    tool_call_hash,
    tool_result_hash,
    verify_execution_receipt,
)
from apps.api.agent_supervisor.domains.runtime.tools import RuntimePaths, default_runtime_paths, execute_tool
from apps.api.agent_supervisor.storage.database import (
    append_runtime_event,
    claim_gateway_execution,
    complete_gateway_execution_claim,
    load_audit_log,
    load_execution_receipt,
    load_gateway_execution_claim,
    load_gateway_request_audit_logs,
    mark_gateway_execution_claim_unknown,
)


class GatewayExecutionUncertainError(ValueError):
    """Raised when a side-effect boundary has no durable completion receipt."""


def execute_gateway_tool_call(
    audit_id: str,
    *,
    agent_id: str,
    session_id: str,
    provider_call_id: str = "",
    runtime: RuntimePaths | None = None,
) -> dict[str, Any]:
    """Execute one eligible Provider tool call using only its audit record.

    No tool name or argument is accepted from the caller.  If redaction or any
    other mutation means the persisted arguments no longer reproduce the original
    tool-call hash, execution stops instead of guessing what the Provider asked.
    """

    audit_log = load_audit_log(audit_id)
    if not audit_log:
        raise KeyError(audit_id)
    _verify_gateway_audit(audit_log, audit_id=audit_id, agent_id=agent_id, session_id=session_id)

    stage_context = audit_log.get("stage_context")
    if not isinstance(stage_context, dict):
        raise ValueError("网关审计缺少 Provider 阶段上下文")
    expected_call_id = str(stage_context.get("provider_call_id") or "").strip()
    if provider_call_id and provider_call_id != expected_call_id:
        raise ValueError("Provider tool_call_id 与网关审计不一致")

    existing = load_execution_receipt(audit_id)
    if existing:
        if not verify_execution_receipt(existing):
            raise ValueError("已有执行回执完整性校验失败，拒绝重复执行")
        # A receipt submitted through the generic execution endpoint is an
        # attestation from the caller.  It is intentionally not accepted as
        # proof for this server-owned path: otherwise a caller could submit a
        # forged/real-looking result first and make the managed gateway skip
        # the only execution that the supervisor actually observes.  The
        # append-only journal cannot replace that receipt with an observed one,
        # so fail closed and require the caller to use one execution contract.
        if existing.get("execution_evidence") != "server-observed" or existing.get("execution_observed_by_server") is not True:
            raise ValueError("已有回执是调用方声明，不能作为服务端托管执行的完成证据")
        replayed_content = _verified_replay_content(existing)
        return {
            "audit_id": audit_id,
            "idempotent": True,
            "provider_call_id": expected_call_id,
            "execution_evidence": existing.get("execution_evidence", "caller-declared"),
            "execution_observed_by_server": existing.get("execution_observed_by_server") is True,
            "execution_result": {"replayed": True, "status": existing.get("status", "")},
            "tool_result": replayed_content,
            "tool_result_hash": existing.get("result_hash", ""),
            "receipt": existing,
        }

    decision = str(audit_log.get("decision") or "")
    # The transparent gateway returns only a checked tool-call proposal.  This
    # endpoint is the explicit server-owned execution bridge, so it accepts
    # exactly the allow decision.  An isolated call is evidence for review, not
    # an implicit permission to replay a side effect from the console/API.
    if decision != "允许":
        raise ValueError(f"网关决策为 {decision or '未知'}，当前服务端执行入口仅接受允许调用")

    capability = str(audit_log.get("standard_capability") or "").strip()
    arguments = audit_log.get("standard_arguments")
    original_tool = str(audit_log.get("tool") or "").strip()
    original_arguments = audit_log.get("arguments")
    if not capability or not isinstance(arguments, dict) or not original_tool or not isinstance(original_arguments, dict):
        raise ValueError("网关审计缺少可执行的规范化工具调用")
    tool_call = {"tool": capability, "arguments": arguments}
    # The audit stores both the caller/provider tool name and the normalized
    # capability.  A custom MCP/OpenAI alias may map ``browser.open`` to
    # ``api.call``; hashing the normalized name here would make an otherwise
    # valid custom mapping impossible to execute.  Bind the receipt to the
    # original provider call while executing only the normalized capability.
    original_tool_call = {
        "tool": original_tool,
        "arguments": original_arguments,
        "risk_hint": str(audit_log.get("original_risk_hint") or audit_log.get("risk_hint") or ""),
    }
    expected_tool_hash = str(audit_log.get("tool_call_hash") or "")
    if not expected_tool_hash or tool_call_hash(original_tool_call) != expected_tool_hash:
        raise ValueError("网关审计参数已脱敏或发生变化，拒绝自动执行")
    task_reason = task_binding_mismatch_reason(stage_context, agent_id=agent_id, raw_tool_call=original_tool_call)
    if task_reason:
        raise ValueError(task_reason)

    claim_id = f"gateway-claim-{uuid4().hex}"
    claim = claim_gateway_execution(
        audit_id=audit_id,
        claim_id=claim_id,
        agent_id=agent_id,
        session_id=session_id,
        tool_call_hash=expected_tool_hash,
        created_at=datetime.now(timezone.utc).isoformat(),
    )
    if claim.get("status") == "unknown":
        raise GatewayExecutionUncertainError(
            "该网关工具调用的执行状态不确定，已冻结执行占用，需先完成核查"
        )
    if claim.get("status") == "completed":
        completed_receipt = load_execution_receipt(audit_id)
        if not completed_receipt or not verify_execution_receipt(completed_receipt):
            raise ValueError("已完成的网关执行占用缺少有效回执，拒绝重放")
        if (
            completed_receipt.get("execution_evidence") != "server-observed"
            or completed_receipt.get("execution_observed_by_server") is not True
        ):
            raise ValueError("网关执行占用缺少服务端观察证据，拒绝重放")
        replayed_content = _verified_replay_content(completed_receipt)
        return {
            "audit_id": audit_id,
            "idempotent": True,
            "provider_call_id": expected_call_id,
            "execution_evidence": completed_receipt.get("execution_evidence", "caller-declared"),
            "execution_observed_by_server": completed_receipt.get("execution_observed_by_server") is True,
            "execution_result": {"replayed": True, "status": completed_receipt.get("status", "")},
            "tool_result": replayed_content,
            "tool_result_hash": completed_receipt.get("result_hash", ""),
            "receipt": completed_receipt,
        }

    started = perf_counter()
    try:
        raw_result = execute_tool(
            tool_call,
            decision,
            # A managed gateway call is already bound to an authenticated Agent.
            # Derive the server-owned default from the authenticated identity so
            # files and queued effects cannot cross Agent boundaries.
            runtime=runtime or default_runtime_paths(agent_id),
            network_addresses=_network_addresses(stage_context),
            memory_namespace=agent_id,
        )
    except Exception as exc:
        _freeze_uncertain_claim(
            audit_id=audit_id,
            claim_id=claim_id,
            agent_id=agent_id,
            session_id=session_id,
            phase="tool-execution",
            error=exc,
        )
        raise GatewayExecutionUncertainError(
            "网关工具执行状态不确定，已冻结执行占用，需先完成核查"
        ) from exc
    duration_ms = round((perf_counter() - started) * 1000, 3)
    if not isinstance(raw_result, dict):
        raw_result = {"executed": False, "output": "执行器返回了无效结果。"}

    executed = bool(raw_result.get("executed"))
    timed_out = bool(raw_result.get("timed_out"))
    exit_code = raw_result.get("exit_code")
    completed = executed and not timed_out and exit_code in {None, 0}
    status = "completed" if completed else "failed" if executed else "not_executed"
    execution_target = str(raw_result.get("execution_target") or ("local-runtime" if executed else "none"))
    if status == "not_executed":
        execution_target = "none"
    tool_result_content = _tool_result_content(raw_result)
    result_hash = tool_result_hash(tool_result_content) if status in {"completed", "failed"} else ""
    try:
        receipt_result = complete_execution(
            audit_id,
            {
                "receipt_id": f"gateway-{uuid4().hex}",
                "agent_id": agent_id,
                "tool_call": original_tool_call,
                "status": status,
                "execution_target": execution_target,
                "result_hash": result_hash,
                "result_content": tool_result_content,
                "duration_ms": duration_ms,
                "error": "" if completed else str(raw_result.get("error") or raw_result.get("output") or ""),
            },
            server_observed=True,
        )
        receipt_payload = receipt_result.get("receipt")
        if not isinstance(receipt_payload, dict):
            raise ValueError("服务端执行已完成但未生成有效回执")
    except Exception as exc:
        _freeze_uncertain_claim(
            audit_id=audit_id,
            claim_id=claim_id,
            agent_id=agent_id,
            session_id=session_id,
            phase="receipt-persistence",
            error=exc,
        )
        raise GatewayExecutionUncertainError(
            "网关工具已越过执行边界，但回执状态不确定，已冻结执行占用，需先完成核查"
        ) from exc
    try:
        complete_gateway_execution_claim(
            audit_id=audit_id,
            claim_id=claim_id,
            receipt_id=str(receipt_payload.get("receipt_id") or ""),
            completed_at=datetime.now(timezone.utc).isoformat(),
        )
    except Exception as exc:
        _freeze_uncertain_claim(
            audit_id=audit_id,
            claim_id=claim_id,
            agent_id=agent_id,
            session_id=session_id,
            phase="claim-completion",
            error=exc,
        )
        raise GatewayExecutionUncertainError(
            "网关工具回执已写入，但执行占用状态不确定，已冻结执行占用，需先完成核查"
        ) from exc
    return {
        "audit_id": audit_id,
        "idempotent": bool(receipt_result.get("idempotent")),
        "provider_call_id": expected_call_id,
        "execution_evidence": "server-observed",
        "execution_observed_by_server": True,
        "execution_result": redact_sensitive(raw_result),
        "tool_result": tool_result_content,
        "tool_result_hash": result_hash,
        "receipt": receipt_payload,
    }


def _verify_gateway_audit(
    audit_log: dict[str, Any],
    *,
    audit_id: str,
    agent_id: str,
    session_id: str,
) -> None:
    if str(audit_log.get("id") or audit_id) != audit_id:
        raise ValueError("网关审计 ID 不一致")
    stored_hash = str(audit_log.get("audit_hash") or "")
    if not stored_hash or stored_hash != audit_hash(audit_log):
        raise ValueError("网关审计 Hash 校验失败")
    stored_signature = str(audit_log.get("audit_signature") or "")
    if audit_signature_required() and not stored_signature:
        raise ValueError("网关审计缺少必需的 HMAC 签名")
    if stored_signature and not verify_audit_signature(stored_hash, stored_signature):
        raise ValueError("网关审计签名校验失败")
    if str(audit_log.get("source_app") or "") != "openai-compatible-proxy":
        raise ValueError("该审计记录不是 OpenAI 网关产生的工具调用")
    if str(audit_log.get("agent_id") or "") != agent_id:
        raise ValueError("请求 Agent 与网关审计身份不一致")
    stage_context = audit_log.get("stage_context")
    if not isinstance(stage_context, dict) or str(stage_context.get("session_id") or "") != session_id:
        raise ValueError("请求会话与网关审计会话不一致")
    if stage_context.get("provider_called") is not True:
        raise ValueError("Provider 尚未产生可执行的工具调用")

    # A Provider response is an atomic decision unit.  If one sibling call in
    # the same response was rejected, asked for review, or isolated, executing
    # an otherwise-allowed sibling through the standalone endpoint would
    # bypass the gateway's all-or-nothing boundary.  The sibling lookup is
    # deliberately done against immutable audit payloads before any claim or
    # side effect is started.
    request_id = str(stage_context.get("request_id") or "").strip()
    siblings = load_gateway_request_audit_logs(
        request_id,
        agent_id=agent_id,
        session_id=session_id,
    )
    blocked_siblings = [
        item
        for item in siblings
        if str(item.get("id") or "") != str(audit_id)
        and str(item.get("decision") or "") != "允许"
    ]
    if blocked_siblings:
        raise ValueError("同一 Provider 响应包含受控工具调用，禁止执行其中的允许子调用")


def _network_addresses(stage_context: dict[str, Any]) -> list[str] | None:
    raw = stage_context.get("resolved_network_addresses")
    if not isinstance(raw, list):
        return None
    return [str(item) for item in raw if str(item).strip()]


def _freeze_uncertain_claim(
    *,
    audit_id: str,
    claim_id: str,
    agent_id: str,
    session_id: str,
    phase: str,
    error: Exception,
) -> None:
    """Persist an unknown side-effect boundary before surfacing the failure."""

    completed_at = datetime.now(timezone.utc).isoformat()
    try:
        mark_gateway_execution_claim_unknown(
            audit_id=audit_id,
            claim_id=claim_id,
            completed_at=completed_at,
        )
    except Exception as exc:
        raise GatewayExecutionUncertainError(
            "网关工具执行状态不确定，执行占用冻结记录失败，请检查审计存储"
        ) from exc
    claim = load_gateway_execution_claim(audit_id) or {}
    error_text = str(redact_sensitive(str(error)))[:2000]
    try:
        append_runtime_event(
            "gateway-execution-uncertain",
            {
                "audit_id": audit_id,
                "claim_id": claim_id,
                "agent_id": agent_id,
                "session_id": session_id,
                "phase": phase,
                "status": str(claim.get("status") or "unknown"),
                "error": error_text,
                "created_at": completed_at,
            },
            created_at=completed_at,
        )
    except Exception as exc:
        raise GatewayExecutionUncertainError(
            "网关工具执行状态不确定，未知状态已冻结但运行事件记录失败，请检查审计存储"
        ) from exc


def _tool_result_content(raw_result: dict[str, Any]) -> str:
    """Return bounded, redacted content suitable for a follow-up tool message."""

    redacted = redact_sensitive(raw_result.get("output", ""))
    if isinstance(redacted, str):
        return redacted[:12_000]
    return json.dumps(redacted, ensure_ascii=False, sort_keys=True, default=str)[:12_000]


def _verified_replay_content(receipt: dict[str, Any]) -> str:
    """Return a stored result only after proving it still matches its receipt."""

    status = str(receipt.get("status") or "")
    if status not in {"completed", "failed"}:
        return ""
    content = receipt.get("result_content")
    result_hash = str(receipt.get("result_hash") or "").strip().lower()
    if not isinstance(content, str) or not result_hash or tool_result_hash(content) != result_hash:
        raise GatewayExecutionUncertainError(
            "已有服务端回执未保留可校验的工具结果，拒绝把空结果回灌 Provider"
        )
    return content
