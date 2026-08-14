"""MCP Gateway 配置：环境变量驱动，未配置上游命令时网关关闭。"""

from __future__ import annotations

import json
import os
import shlex
from pathlib import Path

DEFAULT_TIMEOUT_SECONDS = 10.0
DEFAULT_SERVER_NAME = "zhiAn-sentinel-mcp-gateway"


def gateway_routes() -> dict[str, list[str]]:
    """解析附加上游路由 MCP_GATEWAY_ROUTES_JSON。

    格式：[{"name":"fs","command":"npx -y @mcp/server-fs","cwd":"D:/data"}]
    返回 路由名 → 启动命令列表；解析失败时忽略并返回空（default 始终由
    MCP_GATEWAY_UPSTREAM_COMMAND 提供）。
    """
    raw = os.environ.get("MCP_GATEWAY_ROUTES_JSON", "").strip()
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    if not isinstance(parsed, list):
        return {}
    routes: dict[str, list[str]] = {}
    for entry in parsed:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("name", "")).strip()
        command = entry.get("command", "")
        argv = shlex.split(str(command)) if isinstance(command, str) else [str(item) for item in command]
        if name and argv and name != "default":
            routes[name] = argv
    return routes


def route_cwds() -> dict[str, str]:
    """路由名 → cwd（未配置的路由返回空串，由上游用 Path.cwd()）。"""
    raw = os.environ.get("MCP_GATEWAY_ROUTES_JSON", "").strip()
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    cwds: dict[str, str] = {}
    if isinstance(parsed, list):
        for entry in parsed:
            if isinstance(entry, dict) and entry.get("name"):
                cwds[str(entry["name"])] = str(entry.get("cwd", "") or "")
    return cwds


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
