from __future__ import annotations

from datetime import datetime, timezone
from textwrap import dedent
from typing import Any


def build_agent_integration_bundle() -> dict[str, Any]:
    examples = [
        {
            "id": "generic-http-webhook",
            "name": "通用 HTTP Webhook",
            "framework": "任意 Agent 框架",
            "runtime_stage": "工具执行前",
            "endpoint": "POST /api/runtime/evaluate",
            "status": "ready",
            "code": _generic_http_example(),
        },
        {
            "id": "openai-agents-sdk",
            "name": "OpenAI Agents SDK 接入示例",
            "framework": "OpenAI Agents SDK",
            "runtime_stage": "tool wrapper / handoff 前",
            "endpoint": "POST /api/runtime/evaluate",
            "status": "reference",
            "code": _openai_agents_example(),
        },
        {
            "id": "langchain-tool-wrapper",
            "name": "LangChain Tool Wrapper",
            "framework": "LangChain",
            "runtime_stage": "BaseTool 调用前",
            "endpoint": "POST /api/runtime/evaluate",
            "status": "reference",
            "code": _langchain_example(),
        },
        {
            "id": "langgraph-policy-node",
            "name": "LangGraph Policy Node",
            "framework": "LangGraph",
            "runtime_stage": "tool node 前置策略节点",
            "endpoint": "POST /api/runtime/evaluate",
            "status": "reference",
            "code": _langgraph_example(),
        },
    ]
    return {
        "name": "智安哨通用 Agent Runtime 接入包",
        "version": "0.3.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "purpose": "把任意 Agent 框架的工具调用统一转成智安哨事件，由监督器返回允许、询问、拒绝或隔离。",
        "enforcement_mode": {
            "current": "建议式（advisory）",
            "description": (
                "通用 HTTP 接入（POST /api/runtime/evaluate）属于建议式 API："
                "智安哨返回决策和审计编号，但是否遵守决策由接入方自行控制。"
                "如果接入方忽略拒绝/隔离决策继续执行工具，智安哨无法在运行时强制阻断。"
            ),
            "forced_mode": (
                "需要强制阻断时，请使用 OpenClaw 插件（before_tool_call 钩子强制 block）"
                "或 MCP Gateway（开源版本提供，工具调用经 Gateway 代理）。"
            ),
            "decision_compliance_expectation": (
                "接入方必须实现：仅当 decision === '允许' 时才执行真实工具；"
                "'拒绝'和'隔离'不执行；'询问'暂停等待人工。"
                "智安哨通过执行回执（/api/runtime/executions/{audit_id}/complete）校验合规性。"
            ),
        },
        "decision_contract": {
            "允许": "上游可以继续执行工具，但必须保留审计编号。",
            "询问": "暂停执行，创建人工复核单，等待安全分析员处理。",
            "拒绝": "禁止执行工具调用。",
            "隔离": "只允许在沙箱或低权限环境执行。",
        },
        "event_contract": {
            "required_fields": ["tool_call.tool", "tool_call.arguments"],
            "recommended_fields": ["conversation_id", "agent_id", "source_app", "model_input", "model_output"],
            "safe_default": "外部事件默认只判定和审计，不替上游真实执行工具。",
            "identity_binding": "生产接口要求 Bearer Token 在服务端绑定到同名 agent_id。",
            "execution_receipt": "完成决策处置后调用 /api/runtime/executions/{audit_id}/complete，回传实际执行状态。",
            "custom_tool_mapping": "管理员可在运行治理中心把 browser.open 等原始工具映射到 api.call 等标准能力；审计同时保留两者。",
        },
        "examples": examples,
        "acceptance": [
            "工具调用前必须调用 /api/runtime/evaluate。",
            "每个生产 Agent 使用独立 Token，且请求 agent_id 必须与服务端 Token 映射一致。",
            "接入方必须通过 Bearer Token 或 X-Agent-Supervisor-Api-Token 完成鉴权。",
            "上游必须按 decision 执行允许、询问、拒绝或隔离。",
            "只有精确的“允许”可以进入真实执行器，未知值或缺少 run_id/audit_id 时保持暂停。",
            "询问类结果必须把 approval_review.id 展示给人工复核人员。",
            "人工批准后调用 AgentToolGuard.resume_approved，原始工具调用只允许领取和执行一次。",
            "每次真实接入都要保留 run_id、audit_id、audit_hash、result_hash 和 receipt_hash。",
            "使用 /api/integrations/agents/model_driven_demo 验证模型实际生成 tool_call、执行回执和工具结果回灌，不以硬编码调用代替。",
        ],
    }


def build_agent_integration_markdown(data: dict[str, Any] | None = None) -> str:
    data = data or build_agent_integration_bundle()
    lines = [
        f"# {data['name']}",
        "",
        data["purpose"],
        "",
        "## 决策合约",
        "",
    ]
    for decision, meaning in data["decision_contract"].items():
        lines.append(f"- {decision}：{meaning}")
    lines.extend(["", "## 接入示例", ""])
    for example in data["examples"]:
        lines.extend(
            [
                f"### {example['name']}",
                "",
                f"- 框架：{example['framework']}",
                f"- 位置：{example['runtime_stage']}",
                f"- 接口：`{example['endpoint']}`",
                "",
                "```python",
                example["code"].strip(),
                "```",
                "",
            ]
        )
    lines.extend(["## 验收标准", ""])
    lines.extend([f"- {item}" for item in data["acceptance"]])
    return "\n".join(lines)


def _generic_http_example() -> str:
    return dedent(
        """
        import hashlib
        import json
        import os
        import uuid
        import requests

        def guard_tool_call(tool_name, arguments, model_input=""):
            token = os.environ["AGENT_SUPERVISOR_AGENT_TOKEN"]
            response = requests.post(
                "http://127.0.0.1:8012/api/runtime/evaluate",
                headers={"Authorization": f"Bearer {token}"},
                json={
                    "conversation_id": "prod-conversation-id",
                    "agent_id": "agent-1",
                    "source_app": "generic-agent",
                    "model_input": model_input,
                    "tool_call": {"tool": tool_name, "arguments": arguments},
                    "execute_in_sandbox": False,
                },
                timeout=5,
            )
            response.raise_for_status()
            result = response.json()
            if result.get("decision") not in {"允许", "拒绝", "询问", "隔离"}:
                raise RuntimeError("invalid supervisor decision")
            if not result.get("run_id") or not result.get("audit_id"):
                raise RuntimeError("missing supervisor evidence id")
            return result

        def report_execution(decision, tool_call, status, target, result=None, error=""):
            token = os.environ["AGENT_SUPERVISOR_AGENT_TOKEN"]
            result_hash = ""
            if status in {"completed", "failed"}:
                encoded = json.dumps(result, ensure_ascii=False, sort_keys=True, default=str).encode()
                result_hash = hashlib.sha256(encoded).hexdigest()
            response = requests.post(
                f"http://127.0.0.1:8012/api/runtime/executions/{decision['audit_id']}/complete",
                headers={"Authorization": f"Bearer {token}"},
                json={
                    "receipt_id": str(uuid.uuid4()),
                    "agent_id": "agent-1",
                    "tool_call": tool_call,
                    "status": status,
                    "execution_target": target,
                    "result_hash": result_hash,
                    "error": error,
                },
                timeout=5,
            )
            response.raise_for_status()
            return response.json()
        """
    )


def _openai_agents_example() -> str:
    return dedent(
        """
        # 示例代码表达接入位置：在真实工具函数执行前调用智安哨。
        def supervised_tool(tool_name, raw_tool_func):
            def wrapper(**kwargs):
                tool_call = {"tool": tool_name, "arguments": kwargs}
                decision = guard_tool_call(tool_name, kwargs, model_input="agent trace excerpt")
                if decision["decision"] == "拒绝":
                    report_execution(decision, tool_call, "not_executed", "none")
                    raise RuntimeError(decision["reason"])
                if decision["decision"] == "询问":
                    report_execution(decision, tool_call, "not_executed", "none")
                    return {"pending_review": decision["approval_review"]["id"]}
                if decision["decision"] == "隔离":
                    report_execution(decision, tool_call, "not_executed", "none")
                    return {"sandbox_only": True, "audit_id": decision["audit_id"]}
                if decision["decision"] != "允许":
                    raise RuntimeError("invalid supervisor decision")
                try:
                    result = raw_tool_func(**kwargs)
                except Exception as exc:
                    report_execution(decision, tool_call, "failed", "real", {"error": str(exc)}, str(exc))
                    raise
                report_execution(decision, tool_call, "completed", "real", result)
                return result
            return wrapper
        """
    )


def _langchain_example() -> str:
    return dedent(
        """
        class SupervisedTool:
            def __init__(self, name, raw_tool):
                self.name = name
                self.raw_tool = raw_tool

            def invoke(self, arguments):
                tool_call = {"tool": self.name, "arguments": arguments}
                decision = guard_tool_call(self.name, arguments)
                if decision["decision"] in {"拒绝", "询问"}:
                    report_execution(decision, tool_call, "not_executed", "none")
                    return {"blocked": True, "decision": decision}
                if decision["decision"] == "隔离":
                    report_execution(decision, tool_call, "not_executed", "none")
                    return {"sandbox_only": True, "decision": decision}
                if decision["decision"] != "允许":
                    return {"blocked": True, "decision": "invalid-supervisor-response"}
                try:
                    result = self.raw_tool.invoke(arguments)
                except Exception as exc:
                    report_execution(decision, tool_call, "failed", "real", {"error": str(exc)}, str(exc))
                    raise
                report_execution(decision, tool_call, "completed", "real", result)
                return result
        """
    )


def _langgraph_example() -> str:
    return dedent(
        """
        def policy_node(state):
            tool_call = state["next_tool_call"]
            decision = guard_tool_call(tool_call["tool"], tool_call.get("arguments", {}))
            state["supervisor_decision"] = decision
            if decision["decision"] == "允许":
                state["next"] = "tool_node"
            elif decision["decision"] == "隔离":
                state["next"] = "sandbox_tool_node"
            else:
                state["next"] = "human_review_node"
            return state
        """
    )
