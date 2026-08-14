"""MCP Gateway：Model Context Protocol 代理层强制监督。

Agent 连接智安哨 MCP Gateway（Streamable HTTP 入口），Gateway 转发到真实
MCP Server（stdio 上游），所有 tools/call 必须经过 supervisor.decide()，
拒绝 / 隔离 / 询问时直接返回阻断结果，不转发上游。

多上游路由：MCP_GATEWAY_ROUTES_JSON 声明命名路由，按工具目录路由
tools/call；tools/list 聚合所有路由并标注来源。

审计落库：监督开启时每次 tools/call（放行与阻断）写入统一审计链
（source_app=mcp-gateway），可在 /api/audit_logs 与 /api/alerts 查询。
"""

from apps.api.agent_supervisor.mcp_gateway.audit import SOURCE_APP, record_gateway_tool_call
from apps.api.agent_supervisor.mcp_gateway.config import (
    gateway_enabled,
    gateway_routes,
    gateway_server_name,
    gateway_timeout_seconds,
    upstream_command,
)
from apps.api.agent_supervisor.mcp_gateway.gateway import GATEWAY_VERSION, McpGateway, get_gateway, reset_gateway
from apps.api.agent_supervisor.mcp_gateway.interceptor import (
    BLOCKED_DECISIONS,
    build_blocked_result,
    evaluate_tools_call,
    inspect_tools_call,
)
from apps.api.agent_supervisor.mcp_gateway.router import DEFAULT_ROUTE, UpstreamRouter, router_from_config
from apps.api.agent_supervisor.mcp_gateway.upstream import StdioMcpUpstream, StdioUpstreamError

__all__ = [
    "BLOCKED_DECISIONS",
    "DEFAULT_ROUTE",
    "GATEWAY_VERSION",
    "McpGateway",
    "SOURCE_APP",
    "StdioMcpUpstream",
    "StdioUpstreamError",
    "UpstreamRouter",
    "build_blocked_result",
    "evaluate_tools_call",
    "gateway_enabled",
    "gateway_routes",
    "gateway_server_name",
    "gateway_timeout_seconds",
    "get_gateway",
    "inspect_tools_call",
    "record_gateway_tool_call",
    "reset_gateway",
    "router_from_config",
    "upstream_command",
]
