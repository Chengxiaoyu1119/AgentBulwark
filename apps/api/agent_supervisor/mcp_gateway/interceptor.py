"""工具调用拦截：所有 MCP tools/call 经 supervisor.decide()，非放行即阻断。"""

from __future__ import annotations

from typing import Any

from apps.api.agent_supervisor.domains.governance.supervisor import GuardDecision, decide

# 允许之外的决策（拒绝/隔离/询问）一律不转发上游。询问在网关侧同样阻断，
# 等待人工复核后由 Agent 重新发起。
BLOCKED_DECISIONS = {"拒绝", "隔离", "询问"}


def inspect_tools_call(
    params: dict[str, Any],
    *,
    prompt: str = "",
    agent_id: str = "mcp-gateway",
) -> GuardDecision | None:
    """评估 tools/call 参数；返回 None 表示放行，否则返回阻断决策。"""
    tool_name = str(params.get("name") or "")
    if not tool_name:
        return None
    arguments = params.get("arguments")
    if not isinstance(arguments, dict):
        arguments = {"_raw_arguments": arguments}
    tool_call = {"tool": tool_name, "arguments": arguments}
    decision = decide(tool_call, guard_enabled=True, prompt=prompt, agent_id=agent_id)
    if decision.decision in BLOCKED_DECISIONS:
        return decision
    return None


def build_blocked_result(decision: GuardDecision) -> dict[str, Any]:
    """构造 MCP tools/call 阻断结果（isError=true，附带决策元数据）。"""
    text = (
        f"[智安哨] 工具调用被{decision.decision}（策略 {decision.policy_id}）：{decision.reason} "
        f"建议：{decision.recommendation}"
    )
    metadata = {
        "blocked": True,
        "decision": decision.decision,
        "policy_id": decision.policy_id,
        "risk_level": decision.risk_level,
        "risk_score": decision.risk_score,
        "anomaly_score": decision.anomaly_score,
        "reason": decision.reason,
        "recommendation": decision.recommendation,
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
