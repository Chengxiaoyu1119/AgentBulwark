"""MCP Gateway 配置：环境变量驱动，未配置上游命令时网关关闭。"""

from __future__ import annotations

import hashlib
import json
import math
import os
import secrets
import shlex
from pathlib import Path

from apps.api.agent_supervisor.domains.runtime.security_profile import production_security_profile

DEFAULT_TIMEOUT_SECONDS = 10.0
MIN_TIMEOUT_SECONDS = 0.1
MAX_TIMEOUT_SECONDS = 300.0
DEFAULT_SERVER_NAME = "zhiAn-sentinel-mcp-gateway"
DEFAULT_MAX_MESSAGE_BYTES = 1 * 1024 * 1024
DEFAULT_MAX_PENDING_RESPONSES = 256
DEFAULT_RESOURCE_LIMITS_ENABLED = True
DEFAULT_ALLOW_SIDE_EFFECT_NOTIFICATIONS = False
DEFAULT_NETWORK_MODE = "reject-unpinned"
DEFAULT_SESSION_ISOLATION = True
DEFAULT_MAX_SESSIONS = 128
DEFAULT_MAX_SUBSCRIPTIONS = 128
DEFAULT_REQUEST_STATE_TTL_SECONDS = 300
_EPHEMERAL_REQUEST_STATE_SECRET = secrets.token_bytes(48)


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
        argv = _split_command(command) if isinstance(command, str) else [str(item) for item in command]
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
    return _split_command(raw)


def _split_command(raw: str) -> list[str]:
    """Split a configured child command without corrupting Windows paths.

    ``shlex.split`` defaults to POSIX escaping, where every backslash is an
    escape character.  That silently turns a normal Windows command such as
    ``D:\\Software\\Python\\python.exe`` into ``D:SoftwarePythonpython.exe``
    and makes the MCP gateway fail before it can send its first JSON-RPC frame.
    Preserve backslashes on Windows, while still accepting quoted executable
    paths (including paths containing spaces).  POSIX deployments retain the
    existing shell-like parsing rules.
    """
    if os.name != "nt":
        return shlex.split(raw)
    try:
        tokens = shlex.split(raw, posix=False)
    except ValueError:
        return []
    normalized: list[str] = []
    for token in tokens:
        if len(token) >= 2 and token[0] == token[-1] and token[0] in {"'", '"'}:
            token = token[1:-1]
        normalized.append(token)
    return normalized


def upstream_cwd() -> str:
    return os.environ.get("MCP_GATEWAY_UPSTREAM_CWD", "").strip() or str(Path.cwd())


def gateway_enabled() -> bool:
    """仅当配置了上游命令且未显式关闭时启用。"""
    if os.environ.get("MCP_GATEWAY_ENABLED", "").strip().lower() == "false":
        return False
    return bool(upstream_command())


def gateway_guard_enabled() -> bool:
    """监督开关：默认开启；显式关闭时 Gateway 退化为纯代理（不建议）。"""
    if production_security_profile():
        return True
    return os.environ.get("MCP_GATEWAY_GUARD_ENABLED", "true").strip().lower() != "false"


def gateway_allow_side_effect_notifications() -> bool:
    """Whether to opt into forwarding ``tools/call`` notifications.

    JSON-RPC notifications have no response channel.  A forwarded notification
    can therefore create a side effect without giving the caller an audit
    reference or a way to observe a post-execution audit failure.  The secure
    default rejects them; compatibility deployments must opt in explicitly.
    """
    if production_security_profile():
        return False
    raw = os.environ.get("MCP_GATEWAY_ALLOW_SIDE_EFFECT_NOTIFICATIONS")
    if raw is None:
        return DEFAULT_ALLOW_SIDE_EFFECT_NOTIFICATIONS
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def gateway_network_mode() -> str:
    """Return how MCP tools that carry absolute HTTP targets are handled.

    An opaque stdio MCP child owns its own socket connection.  The Gateway can
    resolve and audit the URL, but cannot force that child to connect to the
    address it resolved.  Until a Gateway-owned HTTP executor exists, the
    default is therefore fail-closed.  ``allow-unpinned`` is an explicit
    compatibility downgrade for legacy deployments and is surfaced in status.
    """
    if production_security_profile():
        return DEFAULT_NETWORK_MODE
    raw = os.environ.get("MCP_GATEWAY_NETWORK_MODE", DEFAULT_NETWORK_MODE).strip().lower()
    if raw in {"allow-unpinned", "reject-unpinned"}:
        return raw
    return DEFAULT_NETWORK_MODE


def gateway_session_isolation() -> bool:
    """Whether the configured Gateway allocates one MCP child per Agent session."""

    # A shared MCP child leaks initialize state, catalogs and response buffers
    # across Agents. Production deployments keep this boundary even when a
    # stale compatibility flag says ``false``.
    if production_security_profile():
        return True
    raw = os.environ.get("MCP_GATEWAY_SESSION_ISOLATION")
    if raw is None:
        return DEFAULT_SESSION_ISOLATION
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def gateway_max_sessions() -> int:
    """Bound the number of live Agent/session MCP child processes."""

    try:
        value = int(os.environ.get("MCP_GATEWAY_MAX_SESSIONS", DEFAULT_MAX_SESSIONS))
    except (TypeError, ValueError):
        value = DEFAULT_MAX_SESSIONS
    return max(1, min(value, 1024))


def gateway_max_subscriptions() -> int:
    """Bound concurrent modern ``subscriptions/listen`` response streams."""

    try:
        value = int(os.environ.get("MCP_GATEWAY_MAX_SUBSCRIPTIONS", DEFAULT_MAX_SUBSCRIPTIONS))
    except (TypeError, ValueError):
        value = DEFAULT_MAX_SUBSCRIPTIONS
    return max(1, min(value, 1024))


def gateway_request_state_secret() -> bytes:
    """Return the HMAC key used to bind modern MRTR ``requestState``.

    Deployments should set ``MCP_GATEWAY_REQUEST_STATE_SECRET`` to the same
    high-entropy value on every worker.  A configured audit HMAC key is a
    useful local fallback; when neither exists, the process uses an ephemeral
    key, which intentionally invalidates outstanding states on restart.
    """
    validate_gateway_request_state_configuration()
    raw = os.environ.get("MCP_GATEWAY_REQUEST_STATE_SECRET", "").strip()
    if raw:
        return raw.encode("utf-8")
    audit_key = os.environ.get("AGENT_SUPERVISOR_AUDIT_HMAC_KEY", "").strip()
    if audit_key:
        return hashlib.sha256(("mcp-request-state:" + audit_key).encode("utf-8")).digest()
    return _EPHEMERAL_REQUEST_STATE_SECRET


def validate_gateway_request_state_configuration() -> None:
    """Fail startup on an explicitly configured MRTR key below the HMAC floor."""

    raw = os.environ.get("MCP_GATEWAY_REQUEST_STATE_SECRET", "").strip()
    if raw and len(raw.encode("utf-8")) < 32:
        raise RuntimeError("MCP_GATEWAY_REQUEST_STATE_SECRET 至少需要 32 字节。")


def gateway_mrtr_timeout_seconds() -> int:
    """Bound how long a legacy child may wait for modern input responses."""
    try:
        value = int(os.environ.get("MCP_GATEWAY_MRTR_TIMEOUT_SECONDS", DEFAULT_REQUEST_STATE_TTL_SECONDS))
    except (TypeError, ValueError):
        value = DEFAULT_REQUEST_STATE_TTL_SECONDS
    return max(30, min(value, 900))


def gateway_timeout_seconds() -> float:
    try:
        value = float(os.environ.get("MCP_GATEWAY_TIMEOUT_SECONDS", DEFAULT_TIMEOUT_SECONDS))
    except (TypeError, ValueError):
        return DEFAULT_TIMEOUT_SECONDS
    if not math.isfinite(value):
        return DEFAULT_TIMEOUT_SECONDS
    return max(MIN_TIMEOUT_SECONDS, min(value, MAX_TIMEOUT_SECONDS))


def gateway_max_message_bytes() -> int:
    try:
        value = int(os.environ.get("MCP_GATEWAY_MAX_MESSAGE_BYTES", DEFAULT_MAX_MESSAGE_BYTES))
    except (TypeError, ValueError):
        value = DEFAULT_MAX_MESSAGE_BYTES
    return max(16 * 1024, min(value, 16 * 1024 * 1024))


def gateway_max_pending_responses() -> int:
    try:
        value = int(os.environ.get("MCP_GATEWAY_MAX_PENDING_RESPONSES", DEFAULT_MAX_PENDING_RESPONSES))
    except (TypeError, ValueError):
        value = DEFAULT_MAX_PENDING_RESPONSES
    return max(16, min(value, 4096))


def gateway_resource_limits_enabled() -> bool:
    if production_security_profile():
        return True
    raw = os.environ.get("MCP_GATEWAY_RESOURCE_LIMITS_ENABLED")
    if raw is None:
        return DEFAULT_RESOURCE_LIMITS_ENABLED
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def gateway_resource_limits() -> dict[str, int | bool | str]:
    """Expose the effective child-process budget without exposing secrets."""
    def bounded(name: str, default: int, minimum: int, maximum: int) -> int:
        try:
            value = int(os.environ.get(name, default))
        except (TypeError, ValueError):
            value = default
        return max(minimum, min(value, maximum))

    os_enforced = os.name != "nt"
    isolation_mode = "posix-rlimit" if os_enforced else "none"
    if os.name == "nt":
        # Import lazily to keep the configuration module independent from the
        # stdio client during normal startup and to make the capability check
        # visible in runtime status before an upstream is launched.
        try:
            from apps.api.agent_supervisor.mcp_gateway.upstream import windows_job_objects_available

            os_enforced = windows_job_objects_available()
        except (ImportError, OSError):
            os_enforced = False
        isolation_mode = "windows-job-object" if os_enforced else "none"
    return {
        "enabled": gateway_resource_limits_enabled(),
        "os_enforced": os_enforced,
        "isolation_mode": isolation_mode,
        "max_message_bytes": gateway_max_message_bytes(),
        "max_pending_responses": gateway_max_pending_responses(),
        "max_cpu_seconds": bounded("MCP_GATEWAY_MAX_CPU_SECONDS", 30, 1, 300),
        "max_memory_bytes": bounded("MCP_GATEWAY_MAX_MEMORY_BYTES", 512 * 1024 * 1024, 64 * 1024 * 1024, 4 * 1024 * 1024 * 1024),
        "max_pids": bounded("MCP_GATEWAY_MAX_PIDS", 128, 16, 4096),
        "max_open_files": bounded("MCP_GATEWAY_MAX_OPEN_FILES", 256, 32, 4096),
        "max_file_bytes": bounded("MCP_GATEWAY_MAX_FILE_BYTES", 16 * 1024 * 1024, 1 * 1024 * 1024, 256 * 1024 * 1024),
    }


def gateway_server_name() -> str:
    return os.environ.get("MCP_GATEWAY_SERVER_NAME", DEFAULT_SERVER_NAME).strip() or DEFAULT_SERVER_NAME
