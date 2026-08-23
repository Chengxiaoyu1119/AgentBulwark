from __future__ import annotations

import os
import sys
from ipaddress import ip_address
from pathlib import Path

from fastapi import HTTPException

from apps.api.agent_supervisor.domains.runtime.agent_credentials import (
    ALLOW_SHARED_EXECUTOR_TOKEN_ENV,
    get_agent_token_bindings,
)
from apps.api.agent_supervisor.domains.runtime.security_profile import (
    SECURITY_PROFILE_ENV,
    production_security_profile,
)

_REPO_ROOT = Path(__file__).resolve().parents[5]


def load_environment_file(path: Path | None = None) -> None:
    """Load the repository ``.env`` before startup defaults are applied.

    The launchers intentionally keep process-level environment variables
    authoritative (for example a one-click local launcher may explicitly
    disable authentication).  Values from ``.env`` only fill variables that
    are not already present.  Keeping this small loader in the runtime
    security module makes the ordering explicit: a loopback default must not
    overwrite an operator's ``AGENT_SUPERVISOR_AUTH_DISABLED=false`` setting.
    """

    env_path = path or (_REPO_ROOT / ".env")
    if not env_path.exists():
        return
    try:
        lines = env_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if value and value[0:1] == value[-1:] and value[0:1] in {"'", '"'}:
            value = value[1:-1]
        if key and key not in os.environ:
            os.environ[key] = value


def configured_bind_host() -> str:
    """Resolve the bind host for both managed launchers and direct Uvicorn.

    The repository launchers pass ``AGENT_SUPERVISOR_API_HOST`` explicitly, but
    operators can also start the ASGI app with ``uvicorn ... --host``.  The
    lifespan hook cannot inspect Uvicorn's socket after startup, so parse that
    one command-line option before applying the same fail-closed policy.  A
    missing option matches Uvicorn's loopback default.
    """

    configured = os.getenv("AGENT_SUPERVISOR_API_HOST", "").strip()
    if configured:
        return configured
    argv = list(sys.argv)
    for index, argument in enumerate(argv):
        if argument == "--host" and index + 1 < len(argv):
            candidate = str(argv[index + 1]).strip()
            if candidate:
                return candidate
        if argument.startswith("--host="):
            candidate = argument.split("=", 1)[1].strip()
            if candidate:
                return candidate
    return "127.0.0.1"


def configure_server_security(host: str) -> None:
    """Apply local-demo defaults and fail closed for public bind addresses."""
    # ``dev_server`` and ``portable_server`` call this before importing the
    # FastAPI app.  Keep the load here as a second, direct-entrypoint guard for
    # ``uvicorn ...:app`` and for tests that invoke this function directly.
    load_environment_file()
    loopback = _is_loopback_host(host)
    os.environ.setdefault("AGENT_SUPERVISOR_AUTH_DISABLED", "true" if loopback else "false")
    # Local loopback launches keep fixture compatibility; public/managed
    # launches force the stricter registration defaults unless the operator
    # explicitly selected a profile.
    os.environ.setdefault(SECURITY_PROFILE_ENV, "local" if loopback else "production")
    # An explicit production profile is a deployment contract, even when the
    # socket is bound to loopback for a smoke test or reverse-proxy sidecar.
    # Do not let the bind address silently downgrade authentication and audit
    # integrity requirements.
    if loopback and not production_security_profile():
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
    if production_security_profile() and (
        shared_executor_token or _env_bool(ALLOW_SHARED_EXECUTOR_TOKEN_ENV)
    ):
        raise RuntimeError("production 安全档不允许共享 executor Token 兼容路径；请配置独立 Agent Token")
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
