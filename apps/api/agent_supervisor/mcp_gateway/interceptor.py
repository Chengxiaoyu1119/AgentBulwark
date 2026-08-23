"""工具调用拦截：所有 MCP tools/call 经 supervisor.decide()，非放行即阻断。"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from apps.api.agent_supervisor.domains.governance.supervisor import GuardDecision, decide
from apps.api.agent_supervisor.domains.governance.tool_contract import validate_json_schema_instance

# 允许之外的决策（拒绝/隔离/询问）一律不转发上游。询问在网关侧同样阻断，
# 等待人工复核后由 Agent 重新发起。
BLOCKED_DECISIONS = {"拒绝", "隔离", "询问"}


def validate_tool_arguments(tool_definition: dict[str, Any] | None, arguments: Any) -> str | None:
    """Validate an MCP ``tools/call`` payload against the advertised schema.

    MCP tool descriptions are untrusted input, but once a tool is selected the
    gateway must still enforce its contract before forwarding arguments to the
    upstream.  This intentionally implements the security-relevant JSON Schema
    subset (object shape, required fields, primitive types and enum values)
    without pretending to be a complete schema validator.
    """
    if tool_definition is None:
        return None
    if not isinstance(arguments, dict):
        return "MCP tools/call 的 arguments 必须是对象。"
    schema = tool_definition.get("inputSchema")
    if schema is None:
        schema = tool_definition.get("parameters")
    if schema is None:
        return None
    issue = validate_json_schema_instance(arguments, schema)
    if issue:
        return f"MCP 工具调用参数契约校验失败：{issue}。"
    return None


def evaluate_tools_call(
    params: dict[str, Any],
    *,
    prompt: str = "",
    agent_id: str = "mcp-gateway",
) -> GuardDecision:
    """评估 tools/call 参数，始终返回完整决策（供拦截与审计共用）。

    缺少工具名时返回合成的拒绝决策——网关不允许匿名工具调用。
    """
    tool_name = str(params.get("name") or "")
    if not tool_name:
        return GuardDecision(
            decision="拒绝",
            risk_level="high",
            policy_id="mcp-gateway-contract",
            reason="tools/call 缺少工具名称参数 name。",
            recommendation="按 MCP 规范传入非空 name 后重试。",
        )
    arguments = params.get("arguments")
    if not isinstance(arguments, dict):
        arguments = {"_raw_arguments": arguments}
    tool_call = {"tool": tool_name, "arguments": arguments}
    return decide(tool_call, guard_enabled=True, prompt=prompt, agent_id=agent_id)


def inspect_tools_call(
    params: dict[str, Any],
    *,
    prompt: str = "",
    agent_id: str = "mcp-gateway",
) -> GuardDecision | None:
    """评估 tools/call 参数；返回 None 表示放行，否则返回阻断决策。"""
    decision = evaluate_tools_call(params, prompt=prompt, agent_id=agent_id)
    if decision.decision in BLOCKED_DECISIONS:
        return decision
    return None


def build_blocked_result(decision: GuardDecision) -> dict[str, Any]:
    """构造 MCP tools/call 阻断结果（isError=true，附带决策元数据）。

    ``GuardDecision.reason`` may contain the original tool name, path, endpoint
    or other caller/provider-controlled text. Returning it verbatim to the
    Agent creates a second prompt-injection channel exactly at the point where
    the gateway is supposed to stop the call. Keep the model-visible response
    fixed and leave the detailed reason in the signed audit record.
    """
    reason_text = str(decision.reason or "")
    reason_hash = hashlib.sha256(
        json.dumps(reason_text, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    text = (
        f"[智安哨] 工具调用已被{decision.decision}（策略 {decision.policy_id}）阻断。"
        "详细原因仅保存在审计记录中，请通过 audit_id 复核。"
    )
    metadata = {
        "blocked": True,
        "decision": decision.decision,
        "policy_id": decision.policy_id,
        "risk_level": decision.risk_level,
        "risk_score": decision.risk_score,
        "anomaly_score": decision.anomaly_score,
        "reason": "详细原因已隐藏，避免把不可信输入回灌给 Agent。",
        "recommendation": "使用审计记录中的 audit_id 进行人工复核。",
        "reason_hash": reason_hash,
    }
    return {
        "content": [{"type": "text", "text": text}],
        "isError": True,
        "structuredContent": metadata,
        "zhiAnSentinel": metadata,
    }


def build_blocked_response(client_id: Any, decision: GuardDecision) -> dict[str, Any]:
    """构造完整 JSON-RPC 响应：工具被阻断且未到达上游。"""
    return {
        "jsonrpc": "2.0",
        "id": client_id,
        "result": build_blocked_result(decision),
    }
