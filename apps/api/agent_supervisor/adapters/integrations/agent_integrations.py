from __future__ import annotations

from datetime import datetime, timezone
from textwrap import dedent
from typing import Any


def build_agent_integration_bundle() -> dict[str, Any]:
    """Return the small, production-facing integration contract."""

    return {
        "name": "智安哨 Agent 网关接入契约",
        "version": "1.0.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "purpose": "让模型请求、工具决策和执行回执沿着同一条可审计链路运行。",
        "decision_contract": {
            "允许": "调用方可以执行，并保留 audit_id 与回执。",
            "询问": "暂停执行，等待人工审批。",
            "拒绝": "禁止执行工具调用。",
            "隔离": "只允许由调用方在其受控低权限环境中执行。",
        },
        "event_contract": {
            "required_fields": ["agent_id", "tool_call.tool", "tool_call.arguments"],
            "recommended_fields": ["session_id", "source_app", "model_input", "model_output"],
            "safe_default": "调用方没有明确允许决策或回执时保持未执行。",
        },
        "examples": [
            {
                "id": "openai-compatible-gateway",
                "name": "OpenAI 兼容模型网关",
                "framework": "OpenAI SDK / 兼容客户端",
                "runtime_stage": "模型请求和模型返回之间",
                "endpoint": "POST /v1/chat/completions",
                "status": "ready",
                "code": _openai_example(),
            },
            {
                "id": "mcp-gateway",
                "name": "MCP 网关",
                "framework": "MCP stdio / Streamable HTTP 客户端",
                "runtime_stage": "tools/list 与 tools/call",
                "endpoint": "POST /api/mcp",
                "status": "ready",
                "code": _mcp_example(),
            },
            {
                "id": "external-receipt",
                "name": "外部工具回执",
                "framework": "任意 Agent 框架",
                "runtime_stage": "调用方完成工具后",
                "endpoint": "POST /api/runtime/executions/{audit_id}/complete",
                "status": "ready",
                "code": _receipt_example(),
            },
        ],
        "acceptance": [
            "每个 Agent 使用独立 Bearer Token，并让 agent_id 与服务端身份绑定。",
            "OpenAI 请求使用稳定的 X-Agent-Session-ID，MCP 请求保持同一会话。",
            "调用方只在 decision=允许 时执行，其余决策都不产生工具副作用。",
            "工具完成后提交一次性回执；回执绑定 audit_id、Agent、会话和参数摘要。",
            "不要把 Provider 或 MCP 密钥写入浏览器代码、日志或请求正文。",
        ],
    }


def build_agent_integration_markdown(data: dict[str, Any] | None = None) -> str:
    data = data or build_agent_integration_bundle()
    lines = [f"# {data['name']}", "", data["purpose"], "", "## 决策合约", ""]
    lines.extend(f"- {key}：{value}" for key, value in data["decision_contract"].items())
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
    lines.extend(["## 验收清单", ""])
    lines.extend(f"- {item}" for item in data["acceptance"])
    return "\n".join(lines)


def _openai_example() -> str:
    return dedent(
        """
        import os
        from openai import OpenAI

        client = OpenAI(
            api_key=os.environ["AGENT_TOKEN"],
            base_url="http://127.0.0.1:8012/v1",
            default_headers={"X-Agent-Session-ID": os.environ["AGENT_SESSION_ID"]},
        )
        response = client.chat.completions.create(
            model="target-model",
            messages=messages,
            tools=tools,
            tool_choice="auto",
        )
        # 受控的 tool call 不会作为可执行调用返回给 Agent。
        """
    )


def _mcp_example() -> str:
    return dedent(
        """
        # 将 MCP 客户端的 POST /mcp 地址替换为智安哨的 /api/mcp。
        # stdio 连接器由网关进程管理，Streamable HTTP 使用同一 Bearer Token。
        headers = {
            "Authorization": f"Bearer {os.environ['AGENT_TOKEN']}",
            "MCP-Session-Id": os.environ["MCP_SESSION_ID"],
        }
        """
    )


def _receipt_example() -> str:
    return dedent(
        """
        import hashlib
        import json
        import requests

        result_hash = hashlib.sha256(
            json.dumps(result, ensure_ascii=False, sort_keys=True).encode("utf-8")
        ).hexdigest()
        requests.post(
            f"http://127.0.0.1:8012/api/runtime/executions/{audit_id}/complete",
            headers={"Authorization": f"Bearer {os.environ['AGENT_TOKEN']}"},
            json={
                "receipt_id": receipt_id,
                "agent_id": agent_id,
                "tool_call": tool_call,
                "status": "completed",
                "execution_target": "real",
                "result_hash": result_hash,
            },
            timeout=5,
        ).raise_for_status()
        """
    )
