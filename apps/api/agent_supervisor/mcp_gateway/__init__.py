"""MCP Gateway：Model Context Protocol 代理层强制监督。

Agent 连接智安哨 MCP Gateway（Streamable HTTP 入口），Gateway 转发到真实
MCP Server（stdio 上游），所有 tools/call 必须经过 supervisor.decide()，
拒绝 / 隔离 / 询问时直接返回阻断结果，不转发上游。
"""

from apps.api.agent_supervisor.mcp_gateway.config import (
    gateway_enabled,
    gateway_server_name,
    gateway_timeout_seconds,
    upstream_command,
)
from apps.api.agent_supervisor.mcp_gateway.gateway import McpGateway, get_gateway, reset_gateway
from apps.api.agent_supervisor.mcp_gateway.interceptor import (
    BLOCKED_DECISIONS,
    build_blocked_result,
    inspect_tools_call,
)
from apps.api.agent_supervisor.mcp_gateway.upstream import StdioMcpUpstream, StdioUpstreamError

__all__ = [
    "BLOCKED_DECISIONS",
    "McpGateway",
    "StdioMcpUpstream",
    "StdioUpstreamError",
    "build_blocked_result",
    "gateway_enabled",
    "gateway_server_name",
    "gateway_timeout_seconds",
    "get_gateway",
    "inspect_tools_call",
    "reset_gateway",
    "upstream_command",
]
