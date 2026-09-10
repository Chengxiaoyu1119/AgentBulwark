import os
from hmac import compare_digest

from fastapi import Header, HTTPException

from apps.api.agent_supervisor.domains.runtime import agent_credentials
from apps.api.agent_supervisor.domains.runtime.agent_credentials import (
    ROLE_LOOKUP_ORDER,
    ROLE_ORDER,
    agent_id_for_token,
    env_bool,
    get_agent_token_bindings,
    role_token,
    supplied_token,
)
from apps.api.agent_supervisor.domains.runtime.security_profile import production_security_profile

# Roles are capability peers; keep grants explicit so observers never inherit execution rights.
ROLE_GRANTS = {
    "observer": frozenset({"observer", "executor", "analyst", "admin"}),
    "executor": frozenset({"executor", "admin"}),
    "analyst": frozenset({"analyst", "admin"}),
    "admin": frozenset({"admin"}),
}


def require_api_token(
    authorization: str | None = Header(default=None),
    x_agent_supervisor_api_token: str | None = Header(default=None, alias="X-Agent-Supervisor-Api-Token"),
) -> None:
    if env_bool("AGENT_SUPERVISOR_AUTH_DISABLED"):
        return

    expected_token = (os.getenv("AGENT_SUPERVISOR_API_TOKEN") or "").strip()
    role_tokens = [role_token(role) for role in ROLE_ORDER]
    agent_tokens = list(get_agent_token_bindings().values())
    supplied = supplied_token(authorization, x_agent_supervisor_api_token)
    registered_agent_id = agent_id_for_token(supplied)
    if not expected_token and not any(role_tokens) and not agent_tokens and not registered_agent_id:
        raise HTTPException(
            status_code=503,
            detail=(
                "API token is not configured. Set AGENT_SUPERVISOR_AGENT_TOKENS_JSON or AGENT_SUPERVISOR_API_TOKEN, "
                "or set AGENT_SUPERVISOR_AUTH_DISABLED=true for local development only."
            ),
        )

    if not supplied or not (expected_token and compare_digest(supplied, expected_token)):
        if not registered_agent_id and not any(token and compare_digest(supplied, token) for token in [*role_tokens, *agent_tokens]):
            raise HTTPException(status_code=401, detail="Invalid or missing API token")


def current_security_role(
    authorization: str | None = Header(default=None),
    x_agent_supervisor_api_token: str | None = Header(default=None, alias="X-Agent-Supervisor-Api-Token"),
) -> str:
    if env_bool("AGENT_SUPERVISOR_AUTH_DISABLED"):
        return "admin"

    supplied = supplied_token(authorization, x_agent_supervisor_api_token)
    observer_token = role_token("observer")
    if observer_token and supplied and compare_digest(supplied, observer_token):
        return "observer"
    if agent_id_for_token(supplied):
        return "executor"
    for role in ("executor", "analyst", "admin"):
        token = role_token(role)
        if token and supplied and compare_digest(supplied, token):
            return role

    shared_token = (os.getenv("AGENT_SUPERVISOR_API_TOKEN") or "").strip()
    if shared_token and supplied and compare_digest(supplied, shared_token) and production_security_profile():
        # Shared production credentials bootstrap an observer session, never a
        # capability grant; keep this ahead of DEFAULT_ROLE.
        return "observer"

    configured_default = (os.getenv("AGENT_SUPERVISOR_DEFAULT_ROLE") or "").strip().lower()
    if configured_default:
        return configured_default if configured_default in ROLE_ORDER else "observer"

    # In local loopback mode the shared token represents the human operator;
    # production keeps that credential read-only.
    if shared_token and supplied and compare_digest(supplied, shared_token):
        local_role = (os.getenv("AGENT_SUPERVISOR_LOCAL_OPERATOR_ROLE") or "admin").strip().lower()
        return local_role if local_role in {"observer", "analyst", "admin"} else "admin"

    return "observer"


def current_agent_identity(
    authorization: str | None = Header(default=None),
    x_agent_supervisor_api_token: str | None = Header(default=None, alias="X-Agent-Supervisor-Api-Token"),
) -> str | None:
    if env_bool("AGENT_SUPERVISOR_AUTH_DISABLED"):
        return None
    return agent_id_for_token(supplied_token(authorization, x_agent_supervisor_api_token))


def require_role(role: str, current_role: str) -> None:
    allowed_roles = ROLE_GRANTS.get(role, frozenset())
    if current_role not in allowed_roles:
        raise HTTPException(status_code=403, detail=f"当前角色 {current_role} 无权执行该操作，需要 {role}")


def require_any_role(roles: set[str], current_role: str) -> None:
    if current_role not in roles:
        allowed = "、".join(role for role in ROLE_LOOKUP_ORDER if role in roles)
        raise HTTPException(status_code=403, detail=f"当前角色 {current_role} 无权执行该操作，需要以下角色之一：{allowed}")


def authenticated_operator(role: str) -> str:
    return f"security-{role}"


def require_agent_identity(agent_id: str, current_role: str, authenticated_agent_id: str | None) -> None:
    agent_credentials.require_agent_identity(agent_id, current_role, authenticated_agent_id)


# Compatibility export; the implementation lives under the runtime domain.
from apps.api.agent_supervisor.domains.runtime.route_scope import restrict_executor_scope  # noqa: E402, F401
