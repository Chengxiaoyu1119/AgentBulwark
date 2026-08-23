from __future__ import annotations

import hashlib
import ipaddress
import os
import time

from fastapi import Header, HTTPException, Request

from apps.api.agent_supervisor.adapters.proxy.resource_governance import resource_limits
from apps.api.agent_supervisor.auth import current_security_role, require_api_token
from apps.api.agent_supervisor.domains.runtime.agent_credentials import (
    agent_id_for_token,
    shared_executor_compatibility_enabled,
)
from apps.api.agent_supervisor.domains.runtime.security_profile import production_security_profile
from apps.api.agent_supervisor.storage.database import _ensure_governance_tables, get_connection

PROXY_REQUIRE_SERVER_OBSERVED_RECEIPTS_ENV = "AGENT_SUPERVISOR_PROXY_REQUIRE_SERVER_OBSERVED_RECEIPTS"

def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int, *, minimum: int = 0, maximum: int = 10_000) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return max(minimum, min(maximum, value))


def _client_host(request: Request) -> str:
    if _env_bool("AGENT_SUPERVISOR_TRUST_PROXY_HEADERS", False):
        forwarded_for = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
        if forwarded_for:
            return forwarded_for
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


def _is_local_or_private(host: str) -> bool:
    lowered = host.strip().lower()
    if lowered in {"localhost", "127.0.0.1", "::1"}:
        return True
    try:
        ip = ipaddress.ip_address(lowered)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_private or ip.is_link_local


def _rate_limit_key(host: str, token: str) -> str:
    if token:
        # Hash the complete token. Truncating to a short prefix lets two
        # distinct credentials share a bucket and lets one caller throttle
        # another by deliberately choosing the same prefix.
        return f"token:{token}"
    return f"ip:{host}"


def _enforce_rate_limit(key: str) -> None:
    limit = _env_int("AGENT_SUPERVISOR_PROXY_RATE_LIMIT_PER_MINUTE", 30, minimum=0, maximum=5000)
    if limit <= 0:
        return
    now = time.time()
    max_keys = _env_int("AGENT_SUPERVISOR_PROXY_RATE_LIMIT_MAX_KEYS", 10_000, minimum=100, maximum=100_000)
    key_hash = hashlib.sha256(key.encode("utf-8")).hexdigest()
    with get_connection() as conn:
        _ensure_governance_tables(conn)
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            """
            SELECT key_hash, window_started, request_count
            FROM gateway_rate_limit_buckets
            WHERE key_hash = ?
            """,
            (key_hash,),
        ).fetchone()
        if row is None:
            count_row = conn.execute("SELECT COUNT(*) AS count FROM gateway_rate_limit_buckets").fetchone()
            tracked = int(count_row["count"] if count_row is not None else 0)
            if tracked >= max_keys:
                conn.execute(
                    """
                    DELETE FROM gateway_rate_limit_buckets
                    WHERE key_hash IN (
                        SELECT key_hash FROM gateway_rate_limit_buckets
                        ORDER BY last_seen ASC LIMIT ?
                    )
                    """,
                    (tracked - max_keys + 1,),
                )
            conn.execute(
                """
                INSERT INTO gateway_rate_limit_buckets
                    (key_hash, window_started, request_count, last_seen, updated_at)
                VALUES (?, ?, 1, ?, ?)
                """,
                (key_hash, now, now, now),
            )
            return
        if now - float(row["window_started"]) >= 60:
            conn.execute(
                """
                UPDATE gateway_rate_limit_buckets
                SET window_started = ?, request_count = 1, last_seen = ?, updated_at = ?
                WHERE key_hash = ?
                """,
                (now, now, now, key_hash),
            )
            return
        if int(row["request_count"]) >= limit:
            raise HTTPException(status_code=429, detail="OpenAI 兼容代理请求过于频繁，请稍后再试。")
        conn.execute(
            """
            UPDATE gateway_rate_limit_buckets
            SET request_count = request_count + 1, last_seen = ?, updated_at = ?
            WHERE key_hash = ?
            """,
            (now, now, key_hash),
        )


def proxy_security_snapshot() -> dict:
    auth_disabled = _env_bool("AGENT_SUPERVISOR_AUTH_DISABLED")
    server_observed_receipts_required = proxy_server_observed_receipts_required()
    return {
        "enabled": _env_bool("AGENT_SUPERVISOR_PROXY_ENABLED", True),
        "endpoint": "/v1/chat/completions",
        "endpoints": ["/v1/chat/completions", "/v1/responses"],
        "responses_compatibility": "text-and-function-subset",
        "generation_roles": ["executor", "analyst", "admin"],
        "read_only_roles": ["observer"],
        "auth_required": not auth_disabled,
        "local_unauthenticated_allowed": _env_bool("AGENT_SUPERVISOR_PROXY_ALLOW_LOCAL_UNAUTHENTICATED", True),
        "public_unauthenticated_allowed": _env_bool("AGENT_SUPERVISOR_PROXY_ALLOW_UNAUTHENTICATED_PUBLIC", False),
        "trust_proxy_headers": _env_bool("AGENT_SUPERVISOR_TRUST_PROXY_HEADERS", False),
        "provider_failover_enabled": _env_bool("AGENT_SUPERVISOR_PROXY_ALLOW_PROVIDER_FAILOVER", False),
        "model_override_enabled": _env_bool("AGENT_SUPERVISOR_PROXY_ALLOW_MODEL_OVERRIDE", False),
        # A server-observed result is a stronger invariant than merely having
        # a receipt object.  Keep the effective receipt requirement true when
        # production requires observed evidence, even if a legacy switch was
        # accidentally disabled.
        "tool_receipts_required": _env_bool("AGENT_SUPERVISOR_PROXY_REQUIRE_TOOL_RECEIPTS", True)
        or server_observed_receipts_required,
        "server_observed_receipts_required": server_observed_receipts_required,
        "reasoning_exposed": _env_bool("AGENT_SUPERVISOR_PROXY_EXPOSE_REASONING", False),
        "executor_identity_required": not shared_executor_compatibility_enabled(),
        "shared_executor_compatibility": shared_executor_compatibility_enabled(),
        "session_header": "X-Agent-Session-ID",
        "rate_limit_per_minute": _env_int("AGENT_SUPERVISOR_PROXY_RATE_LIMIT_PER_MINUTE", 30, minimum=0, maximum=5000),
        "rate_limit_max_keys": _env_int("AGENT_SUPERVISOR_PROXY_RATE_LIMIT_MAX_KEYS", 10_000, minimum=100, maximum=100_000),
        "rate_limit_scope": "sqlite-shared",
        "tracked_client_count": _tracked_rate_limit_count(),
        "resource_governance": resource_limits(),
    }


def proxy_server_observed_receipts_required() -> bool:
    """Return the effective trust requirement for model-visible tool results.

    A caller-authored receipt proves only that the caller submitted a matching
    hash.  Production therefore requires results observed by the gateway
    executor; an environment override cannot weaken that profile.  Local
    profiles retain an explicit switch for SDK integration work.
    """

    return production_security_profile() or _env_bool(
        PROXY_REQUIRE_SERVER_OBSERVED_RECEIPTS_ENV,
        False,
    )


def reset_proxy_rate_limits() -> None:
    with get_connection() as conn:
        _ensure_governance_tables(conn)
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("DELETE FROM gateway_rate_limit_buckets")


def _tracked_rate_limit_count() -> int:
    with get_connection() as conn:
        _ensure_governance_tables(conn)
        row = conn.execute("SELECT COUNT(*) AS count FROM gateway_rate_limit_buckets").fetchone()
    return int(row["count"] if row is not None else 0)


def require_openai_proxy_access(
    request: Request,
    authorization: str | None = Header(default=None),
    x_agent_supervisor_api_token: str | None = Header(default=None, alias="X-Agent-Supervisor-Api-Token"),
    x_agent_session_id: str | None = Header(default=None, alias="X-Agent-Session-ID"),
) -> dict:
    if not _env_bool("AGENT_SUPERVISOR_PROXY_ENABLED", True):
        raise HTTPException(status_code=404, detail="OpenAI 兼容代理未启用。")

    host = _client_host(request)
    token = ""
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
    token = token or (x_agent_supervisor_api_token or "").strip()

    if _env_bool("AGENT_SUPERVISOR_AUTH_DISABLED"):
        local_or_private = _is_local_or_private(host)
        if local_or_private and not _env_bool("AGENT_SUPERVISOR_PROXY_ALLOW_LOCAL_UNAUTHENTICATED", True):
            raise HTTPException(status_code=401, detail="OpenAI 兼容代理未允许本地免鉴权访问。")
        if not local_or_private and not _env_bool("AGENT_SUPERVISOR_PROXY_ALLOW_UNAUTHENTICATED_PUBLIC", False):
            raise HTTPException(status_code=401, detail="公网访问 OpenAI 兼容代理必须开启 API Token 鉴权。")
    else:
        require_api_token(authorization=authorization, x_agent_supervisor_api_token=x_agent_supervisor_api_token)

    _enforce_rate_limit(_rate_limit_key(host, token))
    return {
        "client": host,
        "authenticated": bool(token) and not _env_bool("AGENT_SUPERVISOR_AUTH_DISABLED"),
        "agent_id": agent_id_for_token(token) or "",
        "session_id": x_agent_session_id.strip() if isinstance(x_agent_session_id, str) else "",
        "role": current_security_role(
            authorization=authorization,
            x_agent_supervisor_api_token=x_agent_supervisor_api_token,
        ),
    }


def require_openai_proxy_generation(
    request: Request,
    authorization: str | None = Header(default=None),
    x_agent_supervisor_api_token: str | None = Header(default=None, alias="X-Agent-Supervisor-Api-Token"),
    x_agent_session_id: str | None = Header(default=None, alias="X-Agent-Session-ID"),
) -> dict:
    """Require a role that may create model traffic through the proxy.

    ``/v1/models`` is a read-only discovery endpoint.  A chat completion can
    incur provider cost and can return executable tool calls, so an observer
    credential must not be able to use it.  Agent-bound executor tokens,
    analyst credentials and administrators are the explicit write-capable
    roles for this boundary.
    """
    context = require_openai_proxy_access(
        request,
        authorization=authorization,
        x_agent_supervisor_api_token=x_agent_supervisor_api_token,
        x_agent_session_id=x_agent_session_id,
    )
    role = str(context.get("role") or "observer")
    if role not in {"executor", "analyst", "admin"}:
        raise HTTPException(status_code=403, detail="observer 角色仅允许读取模型目录，不能发起模型请求")
    if role == "executor" and not context.get("agent_id") and not shared_executor_compatibility_enabled():
        raise HTTPException(status_code=403, detail="LLM 代理的 executor 凭证必须绑定到具体 agent_id")
    return context
