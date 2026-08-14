from __future__ import annotations

import os
from ipaddress import ip_address

from fastapi import HTTPException

from apps.api.agent_supervisor.domains.runtime.agent_credentials import (
    ALLOW_SHARED_EXECUTOR_TOKEN_ENV,
    get_agent_token_bindings,
)


def configure_server_security(host: str) -> None:
    """Apply local-demo defaults and fail closed for public bind addresses."""
    loopback = _is_loopback_host(host)
    os.environ.setdefault("AGENT_SUPERVISOR_AUTH_DISABLED", "true" if loopback else "false")
    if loopback:
        return
    if _env_bool("AGENT_SUPERVISOR_AUTH_DISABLED"):
        raise RuntimeError("公网监听地址要求 AGENT_SUPERVISOR_AUTH_DISABLED=false")
    try:
        agent_tokens = get_agent_token_bindings()
    except HTTPException as exc:
        raise RuntimeError(str(exc.detail)) from exc
    token_keys = (
        "AGENT_SUPERVISOR_API_TOKEN",
        "AGENT_SUPERVISOR_API_TOKEN_ADMIN",
        "AGENT_SUPERVISOR_API_TOKEN_EXECUTOR",
        "AGENT_SUPERVISOR_API_TOKEN_ANALYST",
        "AGENT_SUPERVISOR_API_TOKEN_OBSERVER",
    )
    if not any((os.getenv(key) or "").strip() for key in token_keys) and not agent_tokens:
        raise RuntimeError("公网监听地址要求配置 API Token")
    shared_executor_token = (os.getenv("AGENT_SUPERVISOR_API_TOKEN_EXECUTOR") or "").strip()
    if shared_executor_token and not agent_tokens and not _env_bool(ALLOW_SHARED_EXECUTOR_TOKEN_ENV):
        raise RuntimeError("公网运行时的 executor Token 必须绑定到具体 agent_id，或显式开启共享兼容模式")
    if not (os.getenv("AGENT_SUPERVISOR_AUDIT_HMAC_KEY") or "").strip():
        raise RuntimeError("公网监听地址要求配置审计 HMAC 密钥")


def _is_loopback_host(host: str) -> bool:
    normalized = (host or "").strip().lower()
    if normalized == "localhost":
        return True
    try:
        return ip_address(normalized).is_loopback
    except ValueError:
        return False


def _env_bool(name: str) -> bool:
    return (os.getenv(name) or "").strip().lower() in {"1", "true", "yes", "on"}
