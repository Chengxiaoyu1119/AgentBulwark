import os
from hmac import compare_digest

from fastapi import Depends, Header, HTTPException, Request

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

EXECUTOR_ALLOWED_ROUTES = {
    ("GET", "/api/auth/context"),
    ("GET", "/api/health"),
    ("POST", "/api/integrations/openclaw/events"),
    ("POST", "/api/runtime/batch_evaluate"),
    ("POST", "/api/runtime/evaluate"),
    ("POST", "/api/supervisor/batch_evaluate"),
    ("POST", "/api/supervisor/evaluate"),
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

    role = (os.getenv("AGENT_SUPERVISOR_DEFAULT_ROLE", "observer") or "observer").strip().lower()
    return role if role in ROLE_ORDER else "observer"


def current_agent_identity(
    authorization: str | None = Header(default=None),
    x_agent_supervisor_api_token: str | None = Header(default=None, alias="X-Agent-Supervisor-Api-Token"),
) -> str | None:
    if env_bool("AGENT_SUPERVISOR_AUTH_DISABLED"):
        return None
    return agent_id_for_token(supplied_token(authorization, x_agent_supervisor_api_token))


def require_role(role: str, current_role: str) -> None:
    required = ROLE_ORDER.get(role, ROLE_ORDER["admin"])
    actual = ROLE_ORDER.get(current_role, ROLE_ORDER["observer"])
    if actual < required:
        raise HTTPException(status_code=403, detail=f"当前角色 {current_role} 无权执行该操作，需要 {role}")


def require_any_role(roles: set[str], current_role: str) -> None:
    if current_role not in roles:
        allowed = "、".join(role for role in ROLE_LOOKUP_ORDER if role in roles)
        raise HTTPException(status_code=403, detail=f"当前角色 {current_role} 无权执行该操作，需要以下角色之一：{allowed}")


def require_agent_identity(agent_id: str, current_role: str, authenticated_agent_id: str | None) -> None:
    agent_credentials.require_agent_identity(agent_id, current_role, authenticated_agent_id)


def restrict_executor_scope(
    request: Request,
    role: str = Depends(current_security_role),
) -> None:
    if role != "executor":
        return
    route = (request.method.upper(), request.url.path)
    approval_action = request.method.upper() == "POST" and request.url.path.startswith("/api/approvals/") and request.url.path.endswith(
        ("/claim", "/complete")
    )
    execution_receipt = (
        request.method.upper() == "POST"
        and request.url.path.startswith("/api/runtime/executions/")
        and request.url.path.endswith("/complete")
    )
    if route not in EXECUTOR_ALLOWED_ROUTES and not approval_action and not execution_receipt:
        raise HTTPException(status_code=403, detail="executor 角色仅允许调用生产监督和审批恢复接口")
