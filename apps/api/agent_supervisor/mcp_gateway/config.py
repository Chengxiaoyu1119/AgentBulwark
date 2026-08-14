"""MCP Gateway 配置：环境变量驱动，未配置上游命令时网关关闭。"""

from __future__ import annotations

import os
import shlex
from pathlib import Path

DEFAULT_TIMEOUT_SECONDS = 10.0
DEFAULT_SERVER_NAME = "zhiAn-sentinel-mcp-gateway"


def upstream_command() -> list[str]:
    """上游 MCP Server 启动命令（空格分隔），未配置时返回空列表。"""
    raw = os.environ.get("MCP_GATEWAY_UPSTREAM_COMMAND", "").strip()
    if not raw:
        return []
    return shlex.split(raw)


def upstream_cwd() -> str:
    return os.environ.get("MCP_GATEWAY_UPSTREAM_CWD", "").strip() or str(Path.cwd())


def gateway_enabled() -> bool:
    """仅当配置了上游命令且未显式关闭时启用。"""
    if os.environ.get("MCP_GATEWAY_ENABLED", "").strip().lower() == "false":
        return False
    return bool(upstream_command())


def gateway_guard_enabled() -> bool:
    """监督开关：默认开启；显式关闭时 Gateway 退化为纯代理（不建议）。"""
    return os.environ.get("MCP_GATEWAY_GUARD_ENABLED", "true").strip().lower() != "false"


def gateway_timeout_seconds() -> float:
    try:
        return float(os.environ.get("MCP_GATEWAY_TIMEOUT_SECONDS", DEFAULT_TIMEOUT_SECONDS))
    except ValueError:
        return DEFAULT_TIMEOUT_SECONDS


def gateway_server_name() -> str:
    return os.environ.get("MCP_GATEWAY_SERVER_NAME", DEFAULT_SERVER_NAME).strip() or DEFAULT_SERVER_NAME
