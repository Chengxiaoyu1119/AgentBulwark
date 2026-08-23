from __future__ import annotations

from datetime import datetime, timezone
from textwrap import dedent
from typing import Any


def build_agent_integration_bundle() -> dict[str, Any]:
    examples = [
        {
            "id": "openai-compatible-security-gateway",
            "name": "OpenAI 兼容 LLM API 网关",
            "framework": "OpenAI SDK / 任意兼容客户端",
            "runtime_stage": "模型请求与 tool call 返回之间",
            "endpoint": "POST /v1/chat/completions",
            "status": "ready",
            "code": _openai_gateway_example(),
        },
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
            "id": "server-execution-gateway",
            "name": "服务端隔离执行器",
            "framework": "任意 Agent 框架",
            "runtime_stage": "工具调用提交后由智安哨托管执行",
            "endpoint": "POST /api/runtime/execute",
            "status": "ready",
            "code": _server_execution_example(),
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
        "purpose": "保护 LLM API 与 Agent 工具调用链：模型请求、工具定义、模型输出和真实执行统一进入智安哨安全边界。",
        "enforcement_mode": {
            "current": "双模式：服务端强制 / 接入方建议",
            "description": (
                "通用 HTTP 接入（POST /api/runtime/evaluate）属于建议式 API："
                "智安哨返回决策和审计编号，但是否遵守决策由接入方自行控制。"
                "需要由平台收回执行权时，使用 POST /api/runtime/execute。"
            ),
            "forced_mode": (
                "POST /api/runtime/execute 会强制开启监督和隔离执行器，"
                "工具由智安哨服务端处理；OpenClaw 插件和 MCP Gateway 仍提供各自协议的强制接入。"
            ),
            "decision_compliance_expectation": (
                "接入方必须实现：仅当 decision === '允许' 时才执行真实工具；"
                "'拒绝'和'隔离'不执行；'询问'暂停等待人工。"
                "智安哨通过执行回执（/api/runtime/executions/{audit_id}/complete）校验合规性。"
            ),
            "llm_api_gateway": (
                "OpenAI 兼容代理在 Provider 前检查不可信消息，在 Provider 后检查文本、reasoning 与 tool call；"
                "被控制的响应不会把原始 tool call 返回给 Agent。多轮请求应携带稳定的 X-Agent-Session-ID，"
                "严格回执模式还会绑定会话与 Provider tool_call_id。"
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
            "server_execution": "需要服务端托管执行时调用 POST /api/runtime/execute；该入口强制 guard_enabled=true 与 execute_in_sandbox=true。",
            "identity_binding": "生产接口要求 Bearer Token 在服务端绑定到同名 agent_id。",
            "execution_receipt": "完成决策处置后调用 /api/runtime/executions/{audit_id}/complete，回传实际执行状态。",
            "session_binding": "OpenAI/MCP 多轮请求使用 X-Agent-Session-ID（或 agent_supervisor.session_id）保持同一 Agent 会话；回执不得跨会话或跨 Provider tool_call_id 重放。",
            "custom_tool_mapping": "管理员可在运行治理中心把 browser.open 等原始工具映射到 api.call 等标准能力；审计同时保留两者。",
            "external_api_allowlist": "带身份 Agent 的绝对 HTTP(S) 目标必须命中 agent_api_allowlists；相对路由按本地能力处理，未登记主机进入 external-api-allowlist 复核；外部连接器跟随重定向前应逐跳调用 resolve_public_redirect_chain。",
            "capability_registration": "生产环境应登记 agent_tool_allowlists 与 agent_model_allowlists，并在策略设置中开启 require_agent_capability_registration 与 require_agent_model_registration；关闭时仅保留兼容模式，readiness 会标记缺口。",
        },
        "examples": examples,
        "acceptance": [
            "工具调用前必须调用 /api/runtime/evaluate。",
            "需要服务端托管执行时改用 /api/runtime/execute，工具副作用由服务端执行结果确认。",
            "每个生产 Agent 使用独立 Token，且请求 agent_id 必须与服务端 Token 映射一致。",
            "为每个生产 Agent 登记外部 API 主机白名单；未登记绝对目标不得自动外联。",
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


def _openai_gateway_example() -> str:
    return dedent(
        """
        import os
        from openai import OpenAI

        # 把 Agent 使用的 base_url 指向智安哨；messages/tools/tool_choice 保持原样。
        client = OpenAI(
            # Use the token bound to the same agent_id; the shared API token is read-only.
            api_key=os.environ["AGENT_SUPERVISOR_AGENT_TOKEN"],
            base_url="http://127.0.0.1:8012/v1",
            default_headers={"X-Agent-Session-ID": os.environ["AGENT_SESSION_ID"]},
        )
        response = client.chat.completions.create(
            model="target-model",
            messages=messages,
            tools=tools,
            tool_choice="auto",
            extra_body={"agent_supervisor": {"agent_id": "agent-1", "session_id": os.environ["AGENT_SESSION_ID"]}},
        )
        # 只有没有被网关控制的 tool call 才会返回给 Agent。
        decision = getattr(response, "agent_supervisor", {}).get("decision", "")
        if decision in {"拒绝", "询问", "隔离"}:
            raise RuntimeError("智安哨已控制本次模型响应")
        """
    )


def _server_execution_example() -> str:
    return dedent(
        """
        import os
        import requests

        def execute_under_sentinel(agent_id, tool_name, arguments, model_input=""):
            token = os.environ["AGENT_SUPERVISOR_AGENT_TOKEN"]
            response = requests.post(
                "http://127.0.0.1:8012/api/runtime/execute",
                headers={"Authorization": f"Bearer {token}"},
                json={
                    "agent_id": agent_id,
                    "agent_role": "executor",
                    "source_app": "generic-agent",
                    "model_input": model_input,
                    "tool_call": {"tool": tool_name, "arguments": arguments},
                    # 服务端会覆盖这两个字段，调用方提交值只作为证据。
                    "guard_enabled": False,
                    "execute_in_sandbox": False,
                },
                timeout=10,
            )
            response.raise_for_status()
            result = response.json()
            if result["enforcement"]["mode"] != "supervisor-owned-executor":
                raise RuntimeError("missing server enforcement contract")
            return result["decision"], result["audit_log"]["tool_output"], result["audit_log"]
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
