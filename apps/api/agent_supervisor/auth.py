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

# Roles are capability peers, not a single numeric hierarchy: an analyst may
# inspect and write research artifacts but must not inherit executor side
# effects, while an executor must not inherit analyst-only operations.  Keep
# the grant relation explicit so a read-only observer can never satisfy an
# execution requirement merely because both roles share a legacy numeric rank.
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
    if not expected_token and not any(role_tokens) and not agent_tokens:
        raise HTTPException(
            status_code=503,
            detail=(
                "API token is not configured. Set AGENT_SUPERVISOR_AGENT_TOKENS_JSON or AGENT_SUPERVISOR_API_TOKEN, "
                "or set AGENT_SUPERVISOR_AUTH_DISABLED=true for local demos only."
            ),
        )

    supplied = supplied_token(authorization, x_agent_supervisor_api_token)
    if not supplied or not (expected_token and compare_digest(supplied, expected_token)):
        if not any(token and compare_digest(supplied, token) for token in [*role_tokens, *agent_tokens]):
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

    configured_default = (os.getenv("AGENT_SUPERVISOR_DEFAULT_ROLE") or "").strip().lower()
    if configured_default:
        return configured_default if configured_default in ROLE_ORDER else "observer"

    # A protected loopback checkout is operated by the human who started it.
    # Make its explicitly configured shared token useful without weakening a
    # public deployment. Production keeps the same shared credential read-only;
    # machine execution still requires a role-specific or Agent-bound token.
    shared_token = (os.getenv("AGENT_SUPERVISOR_API_TOKEN") or "").strip()
    if shared_token and supplied and compare_digest(supplied, shared_token) and not production_security_profile():
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


def require_agent_identity(agent_id: str, current_role: str, authenticated_agent_id: str | None) -> None:
    agent_credentials.require_agent_identity(agent_id, current_role, authenticated_agent_id)


# Kept as a compatibility export for routers and integrations.  The route-scope
# implementation lives under the runtime domain so the auth entrypoint remains
# limited to identity and role resolution.
from apps.api.agent_supervisor.domains.runtime.route_scope import restrict_executor_scope  # noqa: E402, F401
