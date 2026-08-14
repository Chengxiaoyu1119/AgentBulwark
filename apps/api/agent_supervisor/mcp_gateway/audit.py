"""MCP Gateway 审计落库：把网关侧工具调用决策写入统一审计链。

复用 runtime/events 的 run 记录结构（scenario + audit_logs + alerts），
source_app 固定为 `mcp-gateway`，使网关拦截与外部事件在
`GET /api/audit_logs` / `GET /api/alerts` 中统一可查。

落库语义：
- 放行并转发：execution_status=completed，execution_target=mcp-upstream，
  上游结果脱敏后写入 tool_output；
- 拒绝/隔离/询问：execution_status=not_executed，execution_target=none，
  上游从未收到该调用；
- 回执不外发（execution_receipt_expected=False）：网关自身完成了
  转发闭环，结果已内联在审计记录中，无需接入方补交回执。
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from apps.api.agent_supervisor.domains.governance.integrity import attach_audit_hashes
from apps.api.agent_supervisor.domains.governance.redaction import redact_sensitive
from apps.api.agent_supervisor.domains.governance.supervisor import GuardDecision
from apps.api.agent_supervisor.domains.runtime.execution_receipts import tool_call_hash
from apps.api.agent_supervisor.storage.database import write_run

SOURCE_APP = "mcp-gateway"


def record_gateway_tool_call(
    *,
    params: dict[str, Any],
    decision: GuardDecision,
    forwarded: bool,
    detection_latency_ms: float,
    agent_id: str = "mcp-gateway",
    client_request_id: Any = None,
    upstream_route: str = "default",
    upstream_error: str | None = None,
    upstream_result: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """把一次 tools/call 的决策与执行结果写入审计链，返回审计标识。"""
    tool_name = str(params.get("name") or "")
    raw_arguments = params.get("arguments")
    arguments = raw_arguments if isinstance(raw_arguments, dict) else {"_raw_arguments": raw_arguments}
    audit_arguments = redact_sensitive(arguments)
    run_id = str(uuid4())
    audit_id = str(uuid4())
    created_at = datetime.now(timezone.utc).isoformat()
    blocked = decision.decision in {"拒绝", "隔离", "询问"}

    tool_output: dict[str, Any]
    if blocked:
        tool_output = {
            "executed": False,
            "output": f"MCP Gateway 阻断（{decision.decision}）：{decision.reason}",
        }
    elif upstream_error:
        tool_output = {"executed": False, "output": f"上游错误：{upstream_error}"}
    else:
        tool_output = {
            "executed": True,
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
        "execution_receipt_expected": False,
        "execution_status": "completed" if (forwarded and upstream_result is not None) else "not_executed",
        "execution_target": "mcp-upstream" if forwarded else "none",
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
            "upstream_route": upstream_route,
            "client_request_id": str(client_request_id),
            "upstream_error": upstream_error or "",
        },
        "timestamp": created_at,
        "source_app": SOURCE_APP,
        "conversation_id": f"mcp:{client_request_id if client_request_id is not None else run_id}",
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
            "决策与执行结果写入统一审计链",
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
            "source": "mcp-gateway-enforced" if blocked else "mcp-gateway-forwarded",
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
    return {
        "run_id": run_id,
        "audit_id": audit_id,
        "persisted": True,
        "source_app": SOURCE_APP,
    }
