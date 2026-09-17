"""MCP Gateway 审计落库：把网关侧工具调用决策写入统一审计链。

复用 runtime/events 的 run 记录结构（scenario + audit_logs + alerts），
source_app 固定为 `mcp-gateway`，使网关拦截与外部事件可在
`GET /api/audit_logs` 中查询；`GET /api/alerts` 不再暴露历史实验告警。

落库语义：
- 放行并转发：execution_status=completed，execution_target=mcp-upstream，
  上游结果脱敏后写入 tool_output；
- 拒绝/隔离/询问：execution_status=not_executed，execution_target=none，
  上游从未收到该调用；
- 放行转发会追加服务端观察回执：结果既写入网关审计链，也写入统一
  execution-receipt 事件，供控制台和离线验证器复核。
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from apps.api.agent_supervisor.domains.governance.approvals import create_approval_review
from apps.api.agent_supervisor.domains.governance.integrity import attach_audit_hashes
from apps.api.agent_supervisor.domains.governance.redaction import redact_sensitive
from apps.api.agent_supervisor.domains.governance.supervisor import GuardDecision
from apps.api.agent_supervisor.domains.governance.task_profiles import TASK_CONTEXT_KEY
from apps.api.agent_supervisor.domains.runtime.execution_receipts import (
    complete_execution,
    tool_call_hash,
    tool_result_hash,
)
from apps.api.agent_supervisor.storage.database import get_connection, write_run

SOURCE_APP = "mcp-gateway"


def _execution_outcome(
    *,
    decision: GuardDecision,
    forwarded: bool,
    upstream_error: str | None,
    upstream_result: dict[str, Any] | None,
    result_quarantined: bool,
    execution_phase: str,
) -> str:
    """Return an explicit side-effect/context outcome.

    ``attack_success=False`` is retained for the legacy run schema, but it is
    not a meaningful MCP execution claim.  In particular, a tool may already
    have run while its result is quarantined.  This field is the authoritative
    transport-level distinction used by operators and the console.
    """

    if execution_phase == "intent":
        return "intent-recorded"
    if upstream_error and forwarded:
        return "upstream-failed"
    if result_quarantined and forwarded:
        return "executed-result-contained"
    if not forwarded or decision.decision in {"拒绝", "隔离", "询问"}:
        return "blocked-before-execution"
    if forwarded and upstream_result is not None:
        return "forwarded-and-completed"
    return "audit-uncertain"


def audit_backend_available() -> bool:
    """Return whether the local audit store can accept a gateway record.

    MCP tool calls have side effects.  A successful policy decision without a
    writable audit store would leave the operator unable to prove what ran.
    The gateway uses this inexpensive preflight before forwarding an allowed
    call; the actual write is still checked after the upstream response.
    """
    try:
        with get_connection() as connection:
            connection.execute("SELECT 1").fetchone()
        return True
    except Exception:  # noqa: BLE001 - availability is a fail-closed predicate
        return False


def record_gateway_tool_call(
    *,
    params: dict[str, Any],
    decision: GuardDecision,
    forwarded: bool,
    detection_latency_ms: float,
    agent_id: str = "mcp-gateway",
    session_id: str = "",
    client_request_id: Any = None,
    upstream_route: str = "default",
    upstream_error: str | None = None,
    upstream_result: dict[str, Any] | None = None,
    result_quarantined: bool = False,
    result_scan: dict[str, Any] | None = None,
    execution_phase: str = "result",
    intent_audit_id: str = "",
) -> dict[str, Any]:
    """把一次 tools/call 的意图或执行结果写入审计链，返回审计标识。

    ``intent`` is persisted before an allowed call crosses the MCP upstream
    boundary. The later ``result`` record is append-only evidence of what the
    upstream returned. Keeping the two phases separate makes a post-execution
    audit failure observable instead of silently turning it into a missing log.
    """
    if execution_phase not in {"intent", "result"}:
        raise ValueError("execution_phase 必须是 intent 或 result")
    tool_name = str(params.get("name") or "")
    raw_arguments = params.get("arguments")
    arguments = raw_arguments if isinstance(raw_arguments, dict) else {"_raw_arguments": raw_arguments}
    raw_task_context = params.get(TASK_CONTEXT_KEY)
    task_context = raw_task_context if isinstance(raw_task_context, dict) else {}
    task_context = {
        key: task_context[key]
        for key in ("task_id", "task_profile_fingerprint", "policy_revision", "task_scope", "task_profile_required")
        if key in task_context
    }
    audit_arguments = redact_sensitive(arguments)
    run_id = str(uuid4())
    audit_id = str(uuid4())
    created_at = datetime.now(timezone.utc).isoformat()
    blocked = decision.decision in {"拒绝", "隔离", "询问"}
    scan = result_scan if isinstance(result_scan, dict) else {}

    is_intent = execution_phase == "intent"
    execution_outcome = _execution_outcome(
        decision=decision,
        forwarded=forwarded,
        upstream_error=upstream_error,
        upstream_result=upstream_result,
        result_quarantined=result_quarantined,
        execution_phase=execution_phase,
    )
    tool_output: dict[str, Any]
    if is_intent:
        tool_output = {
            "executed": False,
            "execution_phase": "intent",
            "execution_outcome": execution_outcome,
            "output": "MCP Gateway 已记录执行意图；上游结果尚未产生。",
        }
    elif result_quarantined:
        tool_output = {
            "executed": bool(forwarded and upstream_result is not None),
            "execution_outcome": execution_outcome,
            "is_error": bool((upstream_result or {}).get("isError")),
            "result_quarantined": True,
            "context_hash": str(scan.get("context_hash") or ""),
            "signals": [str(item) for item in scan.get("signals", []) if item],
            "output": "上游工具结果已执行，但其模型可见内容被网关隔离；原始内容未写入审计日志。",
        }
    elif blocked:
        tool_output = {
            "executed": False,
            "execution_outcome": execution_outcome,
            "output": f"MCP Gateway 阻断（{decision.decision}）：{decision.reason}",
        }
    elif upstream_error:
        tool_output = {
            "executed": False,
            "execution_outcome": execution_outcome,
            "output": f"上游错误：{upstream_error}",
        }
    else:
        tool_output = {
            "executed": True,
            "execution_outcome": execution_outcome,
            "is_error": bool((upstream_result or {}).get("isError")),
            "output": redact_sensitive(upstream_result or {}),
        }

    audit_log = {
        "id": audit_id,
        "run_id": run_id,
        "step": 1,
        "tool": tool_name,
        "arguments": audit_arguments,
        "tool_call_hash": tool_call_hash({"tool": tool_name, "arguments": arguments}),
        "standard_capability": tool_name,
        "standard_arguments": audit_arguments,
        "tool_mapping": None,
        "execution_receipt_expected": bool(is_intent or forwarded),
        "execution_evidence": "server-observed" if forwarded and not is_intent else "not-executed-observed",
        "execution_observed_by_server": bool(forwarded and not is_intent),
        "execution_status": (
            "pending"
            if is_intent
            else "failed"
            if upstream_error and forwarded
            else "completed"
            if (forwarded and upstream_result is not None)
            else "not_executed"
        ),
        "execution_outcome": execution_outcome,
        "execution_target": "mcp-upstream" if (forwarded or is_intent) else "none",
        "execution_phase": execution_phase,
        "intent_audit_id": str(intent_audit_id or ""),
        "risk_hint": "",
        "decision": decision.decision,
        "risk_level": decision.risk_level,
        "policy_id": decision.policy_id,
        "reason": decision.reason,
        "recommendation": decision.recommendation,
        "risk_score": decision.risk_score,
        "risk_factors": decision.risk_factors,
        "anomaly_score": decision.anomaly_score,
        "anomaly_signals": decision.anomaly_signals,
        "tool_output": tool_output,
        "execution_duration_ms": 0.0,
        "stage_context": {
            "channel": "mcp-gateway",
            "execution_phase": execution_phase,
            "intent_audit_id": str(intent_audit_id or ""),
            "session_id": session_id,
            "upstream_route": upstream_route,
            "client_request_id": str(client_request_id),
            "upstream_error": upstream_error or "",
            "result_quarantined": result_quarantined,
            "result_context_hash": str(scan.get("context_hash") or ""),
            **task_context,
        },
        "timestamp": created_at,
        "source_app": SOURCE_APP,
        "conversation_id": session_id or f"mcp:{client_request_id if client_request_id is not None else run_id}",
        "agent_id": agent_id,
    }
    attach_audit_hashes([audit_log], seed=f"{run_id}:{created_at}")

    alert = None
    if blocked:
        alert = {
            "id": str(uuid4()),
            "run_id": run_id,
            "severity": decision.risk_level,
            "title": f"MCP Gateway - {decision.decision}",
            "decision": decision.decision,
            "evidence": decision.reason,
            "risk_score": decision.risk_score,
            "risk_factors": decision.risk_factors,
            "anomaly_score": decision.anomaly_score,
            "anomaly_signals": decision.anomaly_signals,
            "created_at": created_at,
        }

    scenario = {
        "id": f"MCP-GATEWAY-{tool_name.upper().replace('.', '-') or 'UNKNOWN'}",
        "surface_id": "tool-call-hijack",
        "title": f"MCP Gateway 工具调用：{tool_name or '（未命名）'}",
        "severity": decision.risk_level,
        "target": tool_name,
        "adversarial_prompt": "",
        "jailbreak_case": "MCP Gateway 代理的工具调用事件，由工具名、参数与上游路由共同构成。",
        "expected_risk": decision.reason,
        "defense": decision.recommendation,
        "script_steps": [
            "Agent 通过 MCP Gateway 发起 tools/call",
            "网关在转发前调用行为监督器决策",
            "放行则转发上游并回传结果；拒绝/隔离/询问则不转发",
            "先记录执行意图，再记录上游结果；异常时保留待核查状态",
        ],
        "attack_path": ["MCP 客户端", "MCP Gateway", "行为监督器", "上游 MCP Server" if forwarded else "（未转发）"],
        "detection_points": [f"网关拦截策略：{decision.policy_id}"],
        "success_criteria": [
            "网关返回明确决策与策略命中原因",
            "被阻断的调用不会到达上游",
            "审计日志可在监督端查询",
        ],
        "safety_boundary": "MCP Gateway 是强制式接入：监督器未放行的调用一律不转发上游。",
        "tags": ["mcp-gateway", decision.policy_id],
        "tool_calls": [{"tool": tool_name, "arguments": audit_arguments}],
    }

    result = {
        "run_id": run_id,
        "created_at": created_at,
        "scenario": scenario,
        "guard_enabled": True,
        "model_result": {
            "provider": "mcp-gateway",
            "scenario_id": scenario["id"],
            "content": "",
            "risk_observation": decision.reason,
        },
        "agent_trace": [
            {
                "agent": "MCP 客户端",
                "role": "agent",
                "message": f"请求调用工具 `{tool_name}`（路由 {upstream_route}）。",
            },
            {
                "agent": "MCP Gateway",
                "role": "guard",
                "message": f"监督决策 `{decision.decision}`：{decision.reason}",
            },
        ],
        "audit_logs": [audit_log],
        "alerts": [alert] if alert else [],
        "attack_success": False,
        "attack_outcome": {
            "attack_success": False,
            "execution_outcome": execution_outcome,
            "attack_success_semantics": "not_assessed_by_mcp_transport",
            "source": "mcp-gateway-result-quarantined"
            if result_quarantined
            else "mcp-gateway-intent"
            if is_intent
            else "mcp-gateway-enforced"
            if blocked
            else "mcp-gateway-forwarded",
            "assertions": [],
        },
        "metrics": {
            "attack_success_rate": 0,
            "blocked_count": 1 if decision.decision == "拒绝" else 0,
            "asked_count": 1 if decision.decision == "询问" else 0,
            "isolated_count": 1 if decision.decision == "隔离" else 0,
            "detection_latency_ms": detection_latency_ms,
            "false_positive_rate": 0,
            "false_positive_applicable": False,
        },
    }
    write_run(result)

    approval_review = create_approval_review(
        {
            "conversation_id": audit_log["conversation_id"],
            "agent_id": agent_id,
            "source_app": SOURCE_APP,
            "tool_call": {"tool": tool_name, "arguments": arguments},
        },
        {
            "decision": decision.decision,
            "risk_level": decision.risk_level,
            "policy_id": decision.policy_id,
            "risk_score": decision.risk_score,
            "risk_factors": decision.risk_factors,
            "anomaly_score": decision.anomaly_score,
            "anomaly_signals": decision.anomaly_signals,
            "reason": decision.reason,
            "recommendation": decision.recommendation,
            "run_id": run_id,
            "audit_log": audit_log,
        },
    )

    receipt: dict[str, Any] | None = None
    if execution_phase == "result" and forwarded:
        receipt_status = "failed" if upstream_error else "completed"
        receipt_content = _receipt_content(upstream_result, upstream_error)
        receipt_result = complete_execution(
            audit_id,
            {
                "receipt_id": f"mcp-{uuid4().hex}",
                "agent_id": agent_id,
                "tool_call": {"tool": tool_name, "arguments": arguments},
                "status": receipt_status,
                "execution_target": "external",
                "result_hash": tool_result_hash(receipt_content),
                "result_content": receipt_content,
                "duration_ms": 0,
                "error": upstream_error or "",
            },
            server_observed=True,
        )
        receipt = receipt_result.get("receipt")
        if not isinstance(receipt, dict):
            raise ValueError("MCP 工具已执行但未生成有效服务端回执")

    return {
        "run_id": run_id,
        "audit_id": audit_id,
        "intent_audit_id": str(intent_audit_id or ""),
        "execution_outcome": execution_outcome,
        "persisted": True,
        "source_app": SOURCE_APP,
        "receipt_id": str(receipt.get("receipt_id") or "") if receipt else "",
        "receipt_hash": str(receipt.get("receipt_hash") or "") if receipt else "",
        "receipt_signature": str(receipt.get("receipt_signature") or "") if receipt else "",
        "approval_review_id": str((approval_review or {}).get("id") or ""),
    }


def _receipt_content(upstream_result: dict[str, Any] | None, upstream_error: str | None) -> str:
    """Serialize bounded, redacted MCP result content for the signed receipt."""

    payload: Any = redact_sensitive(upstream_result) if upstream_result is not None else {"error": upstream_error or ""}
    serialized = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str, separators=(",", ":"))
    return serialized[:12_000]
