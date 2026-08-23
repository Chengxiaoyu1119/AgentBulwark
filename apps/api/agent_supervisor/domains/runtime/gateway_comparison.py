"""Same-request baseline/protected comparison for the LLM gateway.

The default ``observation`` mode compares Provider protocol output without
crossing a side-effect boundary.  The explicit ``sandbox-causal`` mode is the
stronger proof path: it executes the baseline tool call in one isolated local
sandbox and executes the protected call only when the gateway allows it.  The
two modes are deliberately separate so an observation cannot be reported as a
causal side-effect claim.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from apps.api.agent_supervisor.adapters.models.model_adapter import (
    ModelProviderUnavailableError,
    forward_openai_chat_completion,
)
from apps.api.agent_supervisor.adapters.proxy.openai_proxy import (
    PROXY_TOOL_NAME_MAP,
    prepare_openai_provider_payload,
    run_openai_proxy_completion,
    validate_openai_proxy_request,
)
from apps.api.agent_supervisor.adapters.proxy.resource_governance import (
    ProxyResourceLimitError,
    acquire_resource_lease,
    estimate_request_plan,
)
from apps.api.agent_supervisor.domains.governance.integrity import audit_signature
from apps.api.agent_supervisor.domains.governance.redaction import redact_sensitive
from apps.api.agent_supervisor.domains.runtime.execution_receipts import tool_call_hash
from apps.api.agent_supervisor.domains.runtime.gateway_execution import execute_gateway_tool_call
from apps.api.agent_supervisor.domains.runtime.tools import SandboxPaths, execute_tool, init_sandbox
from apps.api.agent_supervisor.paths import SANDBOX_RUNTIME_DIR
from apps.api.agent_supervisor.storage.database import append_runtime_event, load_audit_log

CONTROLLED_DECISIONS = frozenset({"拒绝", "询问", "隔离"})
PRE_PROVIDER_STAGES = frozenset(
    {"pre-provider-input", "pre-provider-context", "tool-definition", "input-review", "tool-result-review"}
)
COMPARISON_EXECUTION_MODES = frozenset({"observation", "sandbox-causal"})


def _provider_tool_calls(response: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str]]:
    """Parse Provider tool calls into the exact shape the local executor accepts.

    The baseline is intentionally unguarded, but it is still a measurement
    harness rather than an arbitrary JSON executor.  Malformed calls are
    recorded as evidence and never reach the fixture tool layer.
    """

    calls: list[dict[str, Any]] = []
    issues: list[str] = []
    choices = response.get("choices")
    if not isinstance(choices, list):
        return calls, ["Provider 响应缺少 choices"]
    for choice_index, choice in enumerate(choices[:8]):
        if not isinstance(choice, dict):
            issues.append(f"choice[{choice_index}] 不是对象")
            continue
        message = choice.get("message")
        if not isinstance(message, dict):
            continue
        raw_calls = message.get("tool_calls")
        if raw_calls is None and isinstance(message.get("function_call"), dict):
            raw_calls = [{"id": f"legacy-{choice_index}", "type": "function", "function": message["function_call"]}]
        if raw_calls is None:
            continue
        if not isinstance(raw_calls, list):
            issues.append(f"choice[{choice_index}] tool_calls 不是数组")
            continue
        for call_index, raw_call in enumerate(raw_calls[:16]):
            if not isinstance(raw_call, dict) or not isinstance(raw_call.get("function"), dict):
                issues.append(f"choice[{choice_index}].tool_calls[{call_index}] 结构无效")
                continue
            function = raw_call["function"]
            tool = str(function.get("name") or "").strip()
            raw_arguments = function.get("arguments", {})
            if isinstance(raw_arguments, str):
                try:
                    arguments = json.loads(raw_arguments)
                except (TypeError, ValueError, json.JSONDecodeError):
                    issues.append(f"choice[{choice_index}].tool_calls[{call_index}] 参数不是 JSON")
                    continue
            else:
                arguments = raw_arguments
            if not tool or not isinstance(arguments, dict):
                issues.append(f"choice[{choice_index}].tool_calls[{call_index}] 缺少工具名或对象参数")
                continue
            calls.append(
                {
                    "id": str(raw_call.get("id") or f"provider-{choice_index}-{call_index}"),
                    "tool": tool,
                    "arguments": arguments,
                    "risk_hint": "",
                }
            )
    return calls, issues


def _comparison_sandbox(comparison_id: str, branch: str) -> SandboxPaths:
    root = SANDBOX_RUNTIME_DIR / "gateway_comparisons" / comparison_id / branch
    return SandboxPaths(
        workspace=root / "workspace",
        outbox=root / "outbox",
        memory=root / "memory",
        fixtures=SANDBOX_RUNTIME_DIR.parent / "fixtures" / "workspace",
        target_state=root / "target-state.json",
    )


def _sandbox_state_hash(sandbox: SandboxPaths) -> str:
    """Hash observable fixture state without persisting raw tool output."""

    digest = hashlib.sha256()
    for label, root in {
        "workspace": sandbox.workspace,
        "outbox": sandbox.outbox,
        "memory": sandbox.memory,
    }.items():
        if not root.exists():
            continue
        for path in sorted(item for item in root.rglob("*") if item.is_file()):
            digest.update(f"{label}:{path.relative_to(root).as_posix()}\0".encode("utf-8"))
            digest.update(path.read_bytes())
    if sandbox.target_state and sandbox.target_state.exists():
        digest.update(b"target-state\0")
        try:
            value = json.loads(sandbox.target_state.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            digest.update(sandbox.target_state.read_bytes())
        else:
            digest.update(_payload_bytes(_without_volatile_timestamps(value)))
    return digest.hexdigest()


def _payload_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str, separators=(",", ":")).encode("utf-8")


def _without_volatile_timestamps(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _without_volatile_timestamps(item)
            for key, item in value.items()
            if key not in {"created_at", "updated_at", "timestamp"}
        }
    if isinstance(value, list):
        return [_without_volatile_timestamps(item) for item in value]
    return value


def _execution_summary(
    *,
    sandbox: SandboxPaths,
    before_hash: str,
    results: list[dict[str, Any]],
    skipped_reason: str = "",
    unknown: bool = False,
) -> dict[str, Any]:
    executed = [item for item in results if item.get("executed") is True]
    completed = [item for item in executed if not item.get("timed_out") and item.get("exit_code") in {None, 0}]
    redaction_count = 0
    output_hashes: list[str] = []
    for item in executed:
        raw_output = str(item.get("output") or "")
        safe_output = redact_sensitive(raw_output)
        if safe_output != raw_output:
            redaction_count += 1
        output_hashes.append(hashlib.sha256(str(safe_output).encode("utf-8")).hexdigest())
    after_hash = _sandbox_state_hash(sandbox)
    return {
        "execution_observed": bool(executed),
        "attempted_count": len(results),
        "executed_count": len(executed),
        "completed_count": len(completed),
        "failed_count": max(0, len(executed) - len(completed)),
        "state_changed": before_hash != after_hash,
        "state_hash_before": before_hash,
        "state_hash_after": after_hash,
        "redacted_output_count": redaction_count,
        "output_hashes": output_hashes[:32],
        "skipped_reason": skipped_reason,
        "unknown": unknown,
    }


def _execution_evidence_summary(value: dict[str, Any]) -> dict[str, Any]:
    """Keep comparison events bounded and free of executor output."""

    return {
        key: value.get(key)
        for key in (
            "execution_observed",
            "attempted_count",
            "executed_count",
            "completed_count",
            "failed_count",
            "state_changed",
            "skipped_reason",
            "unknown",
        )
    }


def _run_baseline_execution(calls: list[dict[str, Any]], sandbox: SandboxPaths) -> dict[str, Any]:
    init_sandbox(sandbox)
    before_hash = _sandbox_state_hash(sandbox)
    results = [
        execute_tool(
            {**call, "tool": PROXY_TOOL_NAME_MAP.get(str(call.get("tool") or ""), str(call.get("tool") or ""))},
            "允许",
            sandbox=sandbox,
        )
        for call in calls
    ]
    return _execution_summary(sandbox=sandbox, before_hash=before_hash, results=results)


def _canonical_comparison_tool_call(call: dict[str, Any]) -> dict[str, Any]:
    """Project Provider tool aliases to the gateway capability before hashing.

    OpenAI-compatible Providers commonly return framework names such as
    ``file_read`` while the gateway audit stores the canonical capability
    ``file.read``.  The execution path already maps the alias before running a
    fixture tool; the causal comparison must apply the same projection before
    calculating ``tool_call_hash`` or it can report a false negative for an
    otherwise identical call.
    """

    raw_tool = str(call.get("tool") or "").strip()
    canonical_tool = PROXY_TOOL_NAME_MAP.get(raw_tool, raw_tool)
    if canonical_tool == raw_tool:
        return call
    return {**call, "tool": canonical_tool}


def _pre_provider_tool_call_bound(
    provider_payload: dict[str, Any],
    baseline_calls: list[dict[str, Any]],
) -> bool:
    """Bind a baseline call to a declared tool when the guard stops early.

    A poisoned tool definition is rejected before the guarded Provider call,
    so there is intentionally no guarded ``tool_decisions`` hash to compare.
    Binding the baseline call to the shared request's declared tool keeps that
    early-block evidence causal without pretending a guarded Provider call
    existed.
    """

    if not baseline_calls:
        return False
    declared: set[str] = set()
    raw_tools = provider_payload.get("tools")
    if isinstance(raw_tools, list):
        for item in raw_tools[:32]:
            if not isinstance(item, dict):
                continue
            function = item.get("function")
            if isinstance(function, dict):
                raw_name = str(function.get("name") or "").strip()
                if raw_name:
                    declared.add(raw_name)
                    declared.add(PROXY_TOOL_NAME_MAP.get(raw_name, raw_name))
    raw_functions = provider_payload.get("functions")
    if isinstance(raw_functions, list):
        for item in raw_functions[:32]:
            if isinstance(item, dict):
                raw_name = str(item.get("name") or "").strip()
                if raw_name:
                    declared.add(raw_name)
                    declared.add(PROXY_TOOL_NAME_MAP.get(raw_name, raw_name))
    return bool(declared) and all(
        str(call.get("tool") or "").strip() in declared
        for call in baseline_calls
    )


def _guarded_audit_calls(metadata: dict[str, Any]) -> tuple[list[str], list[str]]:
    hashes: list[str] = []
    issues: list[str] = []
    decisions = metadata.get("tool_decisions")
    if not isinstance(decisions, list):
        return hashes, issues
    for index, decision in enumerate(decisions[:32]):
        if not isinstance(decision, dict):
            issues.append(f"网关 tool_decisions[{index}] 不是对象")
            continue
        audit_id = str(decision.get("audit_id") or "").strip()
        if not audit_id:
            issues.append(f"网关 tool_decisions[{index}] 缺少 audit_id")
            continue
        audit = load_audit_log(audit_id)
        if not isinstance(audit, dict):
            issues.append(f"网关审计 {audit_id} 不存在")
            continue
        stored_hash = str(audit.get("tool_call_hash") or "").strip()
        if not stored_hash:
            issues.append(f"网关审计 {audit_id} 缺少 tool_call_hash")
            continue
        hashes.append(stored_hash)
    return hashes, issues


def _run_guarded_execution(
    metadata: dict[str, Any],
    *,
    agent_id: str,
    session_id: str,
    sandbox: SandboxPaths,
) -> dict[str, Any]:
    init_sandbox(sandbox)
    before_hash = _sandbox_state_hash(sandbox)
    decisions = metadata.get("tool_decisions")
    if not isinstance(decisions, list) or not decisions:
        return _execution_summary(
            sandbox=sandbox,
            before_hash=before_hash,
            results=[],
            skipped_reason="网关未返回可执行 tool call",
        )
    if any(str(item.get("decision") or "") in CONTROLLED_DECISIONS for item in decisions if isinstance(item, dict)):
        return _execution_summary(
            sandbox=sandbox,
            before_hash=before_hash,
            results=[],
            skipped_reason="网关采用同响应全有或全无策略，存在受控调用",
        )
    results: list[dict[str, Any]] = []
    for item in decisions[:32]:
        if not isinstance(item, dict) or str(item.get("decision") or "") != "允许":
            continue
        audit_id = str(item.get("audit_id") or "").strip()
        if not audit_id:
            continue
        try:
            execution = execute_gateway_tool_call(
                audit_id,
                agent_id=agent_id,
                session_id=session_id,
                provider_call_id=str(item.get("call_id") or ""),
                sandbox=sandbox,
            )
            results.append(dict(execution.get("execution_result") or {}))
        except Exception:
            return _execution_summary(
                sandbox=sandbox,
                before_hash=before_hash,
                results=results,
                skipped_reason="服务端执行或回执失败",
                unknown=True,
            )
    return _execution_summary(sandbox=sandbox, before_hash=before_hash, results=results)


def run_gateway_comparison(
    payload: dict[str, Any],
    *,
    security_context: dict[str, Any],
) -> dict[str, Any]:
    """Compare one unprotected Provider response with one protected response.

    This endpoint is intentionally single-turn.  Accepting caller-authored
    ``role=tool`` messages would let a comparison request smuggle an unverified
    tool result directly into the baseline Provider branch.  ``sandbox-causal``
    is restricted to admin because it intentionally runs the baseline tool in a
    server-owned fixture sandbox; it never connects that proof path to a real
    external connector.
    """

    role = str(security_context.get("role") or "").strip().lower()
    if role not in {"analyst", "admin"}:
        raise ValueError("同请求对照仅供 analyst 或 admin 使用")
    if not isinstance(payload, dict):
        raise ValueError("同请求对照必须提交 OpenAI JSON 对象")
    if payload.get("stream") is True:
        raise ValueError("同请求对照只接受非流式请求")
    raw_extension = payload.get("agent_supervisor")
    extension = raw_extension if isinstance(raw_extension, dict) else {}
    execution_mode = str(extension.get("comparison_mode") or "observation").strip().lower()
    if execution_mode not in COMPARISON_EXECUTION_MODES:
        raise ValueError("同请求对照 comparison_mode 必须是 observation 或 sandbox-causal")
    if execution_mode == "sandbox-causal" and role != "admin":
        raise ValueError("sandbox-causal 同请求对照仅供 admin 使用")
    messages = payload.get("messages")
    if isinstance(messages, list) and any(
        isinstance(message, dict) and str(message.get("role") or "").strip().lower() == "tool"
        for message in messages
    ):
        raise ValueError("同请求对照不接受调用方提交的 role=tool 消息")

    # Baseline and protected branches must observe the same effective
    # Provider payload.  The projection removes unknown top-level extensions
    # that the gateway refuses to forward as hidden instruction channels.
    provider_payload = prepare_openai_provider_payload(payload)
    provider_payload["stream"] = False
    guarded_payload = dict(provider_payload)
    guarded_payload["agent_supervisor"] = {"mode": "transparent"}

    comparison_id = f"gateway-compare-{uuid4().hex}"

    # Validate the contract before the intentionally unprotected observation
    # request. Baseline-first is deliberate: if the protected branch fails,
    # the evidence still contains the model behavior this comparison was
    # created to observe. The endpoint is analyst/admin-only by contract.
    validate_openai_proxy_request(provider_payload)
    resource_agent_id = str(security_context.get("agent_id") or "").strip() or "openai-compatible-proxy"
    baseline_plan = estimate_request_plan(
        provider_payload,
        agent_id=resource_agent_id,
        mode="transparent",
    )
    baseline_result: dict[str, Any] = {}
    baseline_response: dict[str, Any] = {}
    baseline_settlement: dict[str, Any] = {"settled": False, "provider_called": False}
    baseline_error: dict[str, Any] = {}
    try:
        with acquire_resource_lease(baseline_plan) as baseline_lease:
            baseline_result = forward_openai_chat_completion(provider_payload, provider_profile="target")
            candidate_response = baseline_result.get("response")
            if not isinstance(candidate_response, dict):
                raise ValueError("基线 Provider 响应缺少 JSON 对象")
            baseline_response = candidate_response
            baseline_settlement = baseline_lease.settle(
                actual_tokens=_usage_tokens(baseline_response),
                provider_called=True,
            )
    except ProxyResourceLimitError:
        raise
    except ModelProviderUnavailableError as exc:
        baseline_error = {
            "kind": "provider-unavailable",
            "message": "基线 Provider 未完成；原始错误仅保留在失败证据中。",
            "failure_count": len(exc.failures),
        }
    except ValueError as exc:
        baseline_error = {
            "kind": "provider-response-contract",
            "message": "基线 Provider 响应未通过网关协议校验。",
            "error_hash": hashlib.sha256(str(exc).encode("utf-8")).hexdigest(),
        }

    baseline_calls: list[dict[str, Any]] = []
    baseline_call_issues: list[str] = []
    baseline_execution: dict[str, Any] = {
        "execution_observed": False,
        "attempted_count": 0,
        "executed_count": 0,
        "completed_count": 0,
        "failed_count": 0,
        "state_changed": False,
        "skipped_reason": "仅观察模式；基线工具调用未执行",
        "unknown": False,
    }
    baseline_sandbox: SandboxPaths | None = None
    if execution_mode == "sandbox-causal" and baseline_response:
        baseline_calls, baseline_call_issues = _provider_tool_calls(baseline_response)
        baseline_sandbox = _comparison_sandbox(comparison_id, "baseline")
        baseline_execution = _run_baseline_execution(baseline_calls, baseline_sandbox)

    # Always attempt the guarded branch after baseline observation. A Provider
    # failure here still propagates through the HTTP route, but no longer
    # prevents the baseline branch from being exercised.
    guarded_response = run_openai_proxy_completion(guarded_payload, security_context=security_context)
    guarded_metadata = guarded_response.get("agent_supervisor")
    guarded_metadata = guarded_metadata if isinstance(guarded_metadata, dict) else {}

    request_hash = _payload_hash(provider_payload)
    baseline_request_hash = str(baseline_result.get("request_hash") or "")
    guarded_provider_called = guarded_metadata.get("provider_called") is True
    guarded_provider_request_hash = str(guarded_metadata.get("provider_request_hash") or "")
    baseline_shape = _response_shape(baseline_response) if baseline_response else _empty_response_shape()
    guarded_shape = _response_shape(guarded_response)
    decision = str(guarded_metadata.get("decision") or "")
    controlled = decision in CONTROLLED_DECISIONS
    guarded_stage = str(guarded_metadata.get("request_stage") or "")
    guarded_pre_provider = guarded_metadata.get("provider_called") is False and guarded_stage in PRE_PROVIDER_STAGES
    same_provider_request = (
        not baseline_error
        and baseline_request_hash == request_hash
        and (guarded_provider_request_hash == request_hash if guarded_provider_called else guarded_pre_provider)
    )
    baseline_provider = str(baseline_result.get("provider") or "")
    guarded_provider = str(guarded_metadata.get("provider") or "")
    same_provider = baseline_provider == guarded_provider if guarded_provider_called else None
    baseline_response_model = str(baseline_response.get("model") or baseline_result.get("model") or "")
    guarded_response_model = str(guarded_response.get("model") or guarded_metadata.get("model") or "")
    same_observed_model = (
        baseline_response_model == guarded_response_model if guarded_provider_called and baseline_response_model else None
    )
    baseline_tool_call_observed = baseline_shape["returned_tool_call_count"] > 0
    guarded_tool_call_withheld = controlled and guarded_shape["returned_tool_call_count"] == 0
    enforced_before_execution = guarded_metadata.get("decision_enforced_before_tool_execution") is True
    guarded_call_hashes, guarded_call_issues = _guarded_audit_calls(guarded_metadata)
    baseline_call_hashes = [tool_call_hash(_canonical_comparison_tool_call(call)) for call in baseline_calls]
    same_tool_call = bool(baseline_call_hashes) and baseline_call_hashes == guarded_call_hashes
    pre_provider_tool_bound = (
        guarded_pre_provider
        and not guarded_call_hashes
        and _pre_provider_tool_call_bound(provider_payload, baseline_calls)
    )
    # A post-Provider call is bound by the immutable audit hash.  A call
    # stopped before Provider dispatch is bound to the shared tool definition
    # plus the unprotected Provider's observed call instead.
    tool_call_bound = same_tool_call or pre_provider_tool_bound
    guarded_execution: dict[str, Any] = {
        "execution_observed": False,
        "attempted_count": 0,
        "executed_count": 0,
        "completed_count": 0,
        "failed_count": 0,
        "state_changed": False,
        "skipped_reason": "仅观察模式；受保护工具调用未执行",
        "unknown": False,
    }
    guarded_sandbox: SandboxPaths | None = None
    if execution_mode == "sandbox-causal":
        guarded_sandbox = _comparison_sandbox(comparison_id, "guarded")
        guarded_execution = _run_guarded_execution(
            guarded_metadata,
            agent_id=resource_agent_id,
            session_id=str(security_context.get("session_id") or comparison_id),
            sandbox=guarded_sandbox,
        )
    causal_control_observed = bool(
        execution_mode == "sandbox-causal"
        and
        baseline_tool_call_observed
        and guarded_tool_call_withheld
        and enforced_before_execution
        and same_provider_request
        and (same_provider is not False)
        and (same_observed_model is not False)
        and tool_call_bound
        and baseline_execution.get("completed_count", 0) > 0
        and guarded_execution.get("completed_count", 0) == 0
        and guarded_execution.get("unknown") is False
    )
    causal_execution_complete = bool(
        execution_mode == "sandbox-causal"
        and not baseline_call_issues
        and not guarded_call_issues
        and baseline_execution.get("unknown") is False
        and guarded_execution.get("unknown") is False
        and tool_call_bound
    )
    baseline_state_changed = baseline_execution.get("state_changed") is True
    guarded_state_changed = guarded_execution.get("state_changed") is True
    # Tool-call suppression and side-effect suppression are different claims.
    # The former can be proven with a withheld response; the latter requires a
    # completed baseline mutation plus an unchanged protected sandbox. Keep the
    # stronger claim explicit so a read-only fixture cannot be presented as a
    # successful attack that was later prevented.
    side_effect_suppressed = bool(
        causal_control_observed
        and baseline_state_changed
        and not guarded_state_changed
        and baseline_execution.get("completed_count", 0) > 0
        and guarded_execution.get("executed_count", 0) == 0
        and guarded_execution.get("unknown") is False
    )

    audit_ids = _audit_ids(guarded_metadata)
    event_payload = {
        "comparison_id": comparison_id,
        "agent_id": resource_agent_id,
        "session_id": str(security_context.get("session_id") or ""),
        "gateway_source_fingerprint": str(guarded_metadata.get("gateway_source_fingerprint") or ""),
        "gateway_code_fingerprint": str(guarded_metadata.get("gateway_code_fingerprint") or ""),
        "request_hash": request_hash,
        "baseline_provider": baseline_provider,
        "baseline_response_hash": str(baseline_result.get("provider_response_hash") or ""),
        "baseline_tool_call_count": baseline_shape["returned_tool_call_count"],
        "baseline_error": baseline_error,
        "guarded_provider_called": guarded_metadata.get("provider_called"),
        "guarded_provider": guarded_provider,
        "guarded_provider_response_hash": str(guarded_metadata.get("provider_response_hash") or ""),
        "guarded_decision": decision,
        "guarded_stage": guarded_stage,
        "guarded_tool_call_count": guarded_shape["returned_tool_call_count"],
        "guarded_audit_ids": audit_ids,
        "same_provider_request": same_provider_request,
        "same_provider": same_provider,
        "same_observed_model": same_observed_model,
        "same_tool_call": same_tool_call,
        "tool_call_bound": tool_call_bound,
        "tool_call_binding": (
            "definition-bound-pre-provider"
            if pre_provider_tool_bound
            else "provider-audit-hash"
            if same_tool_call
            else "unbound"
        ),
        "baseline_execution": _execution_evidence_summary(baseline_execution),
        "guarded_execution": _execution_evidence_summary(guarded_execution),
        "baseline_state_changed": baseline_state_changed,
        "guarded_state_changed": guarded_state_changed,
        "side_effect_suppressed": side_effect_suppressed,
        "baseline_call_issues": baseline_call_issues,
        "guarded_call_issues": guarded_call_issues,
        "causal_control_observed": causal_control_observed,
    }
    evidence_hash = _payload_hash(event_payload)
    event_payload["evidence_hash"] = evidence_hash
    event_payload["evidence_signature"] = audit_signature(evidence_hash)
    try:
        persisted_event = append_runtime_event("gateway-comparison", event_payload)
        event_id = int(persisted_event.get("event_id") or 0)
        event_persisted = event_id > 0
    except (OSError, sqlite3.Error):
        event_id = 0
        event_persisted = False

    return {
        "schema_version": "agent-supervisor.gateway-comparison.v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "comparison_id": comparison_id,
        "request_hash": request_hash,
        "mode": f"same-provider-{execution_mode}",
        "execution_mode": execution_mode,
        "baseline": {
            "provider_called": not bool(baseline_error),
            "provider": baseline_provider,
            "requested_model": str(provider_payload.get("model") or ""),
            "response_model": baseline_response_model,
            "request_hash": baseline_request_hash,
            "provider_response_hash": str(baseline_result.get("provider_response_hash") or ""),
            "response_shape": baseline_shape,
            "tool_execution": (
                "sandbox-observed-unprotected"
                if execution_mode == "sandbox-causal"
                else "not-executed-observation-only"
            ),
            "execution": baseline_execution,
            "response": _safe_provider_response(baseline_response),
            "error": baseline_error,
            "resource_settlement": baseline_settlement,
        },
        "guarded": {
            "provider_called": guarded_metadata.get("provider_called"),
            "provider": guarded_provider,
            "requested_model": str(provider_payload.get("model") or ""),
            "response_model": guarded_response_model,
            "provider_request_hash": guarded_provider_request_hash,
            "provider_response_hash": str(guarded_metadata.get("provider_response_hash") or ""),
            "decision": decision,
            "request_stage": guarded_stage,
            "policy_id": str(guarded_metadata.get("policy_id") or ""),
            "reason": str(guarded_metadata.get("reason") or "")[:1000],
            "response_shape": guarded_shape,
            "decision_enforced_before_tool_execution": enforced_before_execution,
            "execution_boundary": str(guarded_metadata.get("execution_boundary") or ""),
            "execution": guarded_execution,
            "audit_ids": audit_ids,
            "response": _safe_provider_response(guarded_response),
        },
        "invariants": {
            "gateway_options_removed_from_provider_payload": True,
            "same_provider_request": same_provider_request,
            "same_provider": same_provider,
            "same_observed_model": same_observed_model,
            "same_tool_call": same_tool_call,
            "tool_call_bound": tool_call_bound,
            "tool_call_binding": (
                "definition-bound-pre-provider"
                if pre_provider_tool_bound
                else "provider-audit-hash"
                if same_tool_call
                else "unbound"
            ),
            "baseline_tool_execution_attempted": baseline_execution.get("attempted_count", 0) > 0,
            "guarded_tool_execution_attempted": guarded_execution.get("attempted_count", 0) > 0,
            "side_effect_state_compared": execution_mode == "sandbox-causal",
            "execution_mode": execution_mode,
        },
        "verdict": {
            "baseline_tool_call_observed": baseline_tool_call_observed,
            "guarded_controlled": controlled,
            "guarded_tool_call_withheld": guarded_tool_call_withheld,
            "tool_call_bound": tool_call_bound,
            "tool_call_binding": (
                "definition-bound-pre-provider"
                if pre_provider_tool_bound
                else "provider-audit-hash"
                if same_tool_call
                else "unbound"
            ),
            "causal_control_observed": causal_control_observed,
            "causal_execution_complete": causal_execution_complete,
            "baseline_state_changed": baseline_state_changed,
            "guarded_state_changed": guarded_state_changed,
            "side_effect_suppressed": side_effect_suppressed,
            "evidence_complete": event_persisted
            and same_provider_request
            and (execution_mode == "observation" or causal_execution_complete),
        },
        "evidence": {
            "event_id": event_id,
            "persisted": event_persisted,
            "hash": evidence_hash,
            "signature": str(event_payload.get("evidence_signature") or ""),
        },
    }


def _usage_tokens(response: dict[str, Any]) -> int | None:
    usage = response.get("usage")
    if not isinstance(usage, dict):
        return None
    total = usage.get("total_tokens")
    if isinstance(total, (int, float)) and not isinstance(total, bool) and total >= 0:
        return int(total)
    return None


def _payload_hash(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _response_shape(response: dict[str, Any]) -> dict[str, Any]:
    choices = response.get("choices")
    returned_tool_call_count = 0
    finish_reasons: list[str] = []
    if isinstance(choices, list):
        for choice in choices[:8]:
            if not isinstance(choice, dict):
                continue
            finish_reasons.append(str(choice.get("finish_reason") or ""))
            message = choice.get("message")
            if not isinstance(message, dict):
                continue
            tool_calls = message.get("tool_calls")
            if isinstance(tool_calls, list):
                returned_tool_call_count += len(tool_calls)
            if isinstance(message.get("function_call"), dict):
                returned_tool_call_count += 1
    return {
        "choice_count": len(choices) if isinstance(choices, list) else 0,
        "returned_tool_call_count": returned_tool_call_count,
        "finish_reasons": finish_reasons,
    }


def _empty_response_shape() -> dict[str, Any]:
    """Keep a failed baseline comparable without inventing a Provider result."""

    return {"choice_count": 0, "returned_tool_call_count": 0, "finish_reasons": []}


def _safe_provider_response(response: dict[str, Any]) -> dict[str, Any]:
    safe_choices: list[dict[str, Any]] = []
    raw_choices = response.get("choices")
    if isinstance(raw_choices, list):
        for index, raw_choice in enumerate(raw_choices[:8]):
            if not isinstance(raw_choice, dict):
                continue
            raw_message = raw_choice.get("message")
            message = raw_message if isinstance(raw_message, dict) else {}
            safe_message: dict[str, Any] = {
                "role": str(message.get("role") or "assistant")[:32],
                "content": _bounded_redacted(message.get("content"), 4000),
            }
            raw_tool_calls = message.get("tool_calls")
            if isinstance(raw_tool_calls, list):
                safe_message["tool_calls"] = [
                    safe_call
                    for item in raw_tool_calls[:16]
                    if (safe_call := _safe_tool_call(item)) is not None
                ]
            if isinstance(message.get("function_call"), dict):
                safe_message["function_call"] = _safe_function(message["function_call"])
            safe_choices.append(
                {
                    "index": raw_choice.get("index", index),
                    "message": safe_message,
                    "finish_reason": str(raw_choice.get("finish_reason") or "")[:80],
                }
            )
    usage = response.get("usage")
    return {
        "id": str(response.get("id") or "")[:200],
        "object": str(response.get("object") or "")[:80],
        "created": response.get("created"),
        "model": str(response.get("model") or "")[:200],
        "choices": safe_choices,
        "usage": redact_sensitive(usage) if isinstance(usage, dict) else {},
    }


def _safe_tool_call(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    function = value.get("function")
    if not isinstance(function, dict):
        return None
    return {
        "id": str(value.get("id") or "")[:200],
        "type": str(value.get("type") or "function")[:40],
        "function": _safe_function(function),
    }


def _safe_function(value: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": str(value.get("name") or "")[:256],
        "arguments": _bounded_redacted(value.get("arguments"), 8000),
    }


def _bounded_redacted(value: Any, limit: int) -> Any:
    redacted = redact_sensitive(value)
    if isinstance(redacted, str):
        return redacted[:limit]
    encoded = json.dumps(redacted, ensure_ascii=False, sort_keys=True, default=str)
    return encoded[:limit]


def _audit_ids(metadata: dict[str, Any]) -> list[str]:
    values: list[str] = []

    def append(value: Any) -> None:
        normalized = str(value or "").strip()
        if normalized and normalized not in values:
            values.append(normalized[:200])

    append(metadata.get("audit_id"))
    append(metadata.get("gateway_audit_id"))
    raw_ids = metadata.get("audit_ids")
    if isinstance(raw_ids, list):
        for item in raw_ids[:32]:
            append(item)
    raw_decisions = metadata.get("tool_decisions")
    if isinstance(raw_decisions, list):
        for item in raw_decisions[:32]:
            if isinstance(item, dict):
                append(item.get("audit_id"))
    return values[:32]
