"""MCP Gateway 核心：JSON-RPC 方法路由 + 强制拦截 + 上游转发。"""

from __future__ import annotations

import threading
from typing import Any

from apps.api.agent_supervisor.mcp_gateway.interceptor import build_blocked_response, inspect_tools_call
from apps.api.agent_supervisor.mcp_gateway.upstream import StdioMcpUpstream

GATEWAY_VERSION = "0.1.0"


class McpGateway:
    """把 Agent 的 MCP 请求转发给真实上游，并强制监督 tools/call。"""

    def __init__(
        self,
        upstream: StdioMcpUpstream,
        *,
        guard_enabled: bool = True,
        server_name: str = "zhiAn-sentinel-mcp-gateway",
    ) -> None:
        self._upstream = upstream
        self._guard_enabled = guard_enabled
        self._server_name = server_name
        self._stats_lock = threading.Lock()
        self._stats = {"messages": 0, "tool_calls": 0, "blocked": 0, "forwarded_tool_calls": 0}

    # -- 对外接口 -----------------------------------------------------------

    @property
    def upstream(self) -> StdioMcpUpstream:
        return self._upstream

    @property
    def guard_enabled(self) -> bool:
        return self._guard_enabled

    def stats(self) -> dict[str, int]:
        with self._stats_lock:
            return dict(self._stats)

    def handle(self, message: dict[str, Any]) -> dict[str, Any] | None:
        """处理单条 JSON-RPC 消息；通知返回 None，请求返回响应。"""
        if not isinstance(message, dict) or not message.get("method"):
            raise ValueError("MCP 消息必须是包含 method 的 JSON-RPC 请求或通知。")
        method = str(message["method"])
        params = message.get("params")
        if not isinstance(params, dict):
            params = {}
        client_id = message.get("id")

        with self._stats_lock:
            self._stats["messages"] += 1

        is_notification = "id" not in message

        if method == "tools/call" and not is_notification:
            return self._handle_tools_call(message, params, client_id)

        if is_notification:
            self._upstream.notify(method, params)
            return None

        if method == "initialize":
            return self._handle_initialize(message, params, client_id)

        if method == "ping":
            return {"jsonrpc": "2.0", "id": client_id, "result": {}}

        return self._upstream.request(method, params, client_id=client_id)

    def close(self) -> None:
        self._upstream.close()

    # -- 内部 ---------------------------------------------------------------

    def _handle_tools_call(
        self,
        message: dict[str, Any],
        params: dict[str, Any],
        client_id: Any,
    ) -> dict[str, Any]:
        with self._stats_lock:
            self._stats["tool_calls"] += 1

        if self._guard_enabled:
            decision = inspect_tools_call(params, agent_id="mcp-gateway")
            if decision is not None:
                with self._stats_lock:
                    self._stats["blocked"] += 1
                return build_blocked_response(client_id, decision)

        if not str(params.get("name") or ""):
            return {
                "jsonrpc": "2.0",
                "id": client_id,
                "error": {"code": -32602, "message": "tools/call 缺少工具名称参数 name。"},
            }

        with self._stats_lock:
            self._stats["forwarded_tool_calls"] += 1
        return self._upstream.request("tools/call", params, client_id=client_id)

    def _handle_initialize(
        self,
        message: dict[str, Any],
        params: dict[str, Any],
        client_id: Any,
    ) -> dict[str, Any]:
        response = self._upstream.request("initialize", params, client_id=client_id)
        result = response.get("result")
        if isinstance(result, dict):
            upstream_info = result.get("serverInfo")
            result["serverInfo"] = {"name": self._server_name, "version": GATEWAY_VERSION}
            result["zhiAnSentinel"] = {
                "gateway": True,
                "guardEnabled": self._guard_enabled,
                "upstreamServerInfo": upstream_info,
            }
        return response


# -- 模块级单例（按环境变量懒加载） -----------------------------------------

_gateway_lock = threading.Lock()
_gateway: McpGateway | None = None


def get_gateway() -> McpGateway | None:
    """获取配置驱动的网关单例；未配置上游时返回 None。"""
    global _gateway
    with _gateway_lock:
        if _gateway is not None:
            return _gateway
        from apps.api.agent_supervisor.mcp_gateway.config import (
            gateway_guard_enabled,
            gateway_server_name,
        )
        from apps.api.agent_supervisor.mcp_gateway.upstream import new_upstream_from_config

        upstream = new_upstream_from_config()
        if upstream is None:
            return None
        _gateway = McpGateway(
            upstream,
            guard_enabled=gateway_guard_enabled(),
            server_name=gateway_server_name(),
        )
        return _gateway


def reset_gateway() -> None:
    """关闭并清空单例（测试与配置变更时使用）。"""
    global _gateway
    with _gateway_lock:
        if _gateway is not None:
            _gateway.close()
        _gateway = None
