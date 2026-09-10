from __future__ import annotations

import secrets
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from apps.api.agent_supervisor.auth import current_security_role, require_api_token, require_role, restrict_executor_scope
from apps.api.agent_supervisor.schemas.main_models import AgentRegistrationCreate
from apps.api.agent_supervisor.storage.data import get_policy_settings
from apps.api.agent_supervisor.storage.database import (
    create_agent_registration,
    list_agent_registrations,
    revoke_agent_registration,
    rotate_agent_registration_token,
)

router = APIRouter(dependencies=[Depends(require_api_token), Depends(restrict_executor_scope)])


def _agent_view(item: dict[str, Any]) -> dict[str, Any]:
    settings = get_policy_settings()
    agent_id = str(item.get("agent_id") or "")
    tool_bound = agent_id in (settings.get("agent_tool_allowlists") or {})
    model_bound = agent_id in (settings.get("agent_model_allowlists") or {})
    context_bound = agent_id in (settings.get("agent_context_allowlists") or {})
    api_bound = agent_id in (settings.get("agent_api_allowlists") or {})
    return {
        **item,
        "policy_binding": {
            "tools": tool_bound,
            "models": model_bound,
            "context": context_bound,
            "api": api_bound,
            # A registered Agent is ready only after every authority boundary
            # has an explicit scope; partial configuration must remain visible.
            "ready": tool_bound and model_bound and context_bound and api_bound,
        },
    }


def _new_token() -> str:
    return secrets.token_urlsafe(32)


@router.get("/api/agents")
def agents(role: str = Depends(current_security_role)) -> list[dict[str, Any]]:
    require_role("analyst", role)
    return [_agent_view(item) for item in list_agent_registrations()]


@router.post("/api/agents")
def create_agent(request: AgentRegistrationCreate, role: str = Depends(current_security_role)) -> dict[str, Any]:
    require_role("admin", role)
    try:
        return _agent_view(
            create_agent_registration(
                agent_id=request.agent_id,
                display_name=request.display_name.strip() or request.agent_id,
                token=_new_token(),
                created_by=f"security-{role}",
            )
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/api/agents/{agent_id}/rotate-token")
def rotate_token(agent_id: str, role: str = Depends(current_security_role)) -> dict[str, Any]:
    require_role("admin", role)
    try:
        return _agent_view(rotate_agent_registration_token(agent_id=agent_id, token=_new_token()))
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"未知 Agent：{agent_id}") from exc


@router.post("/api/agents/{agent_id}/revoke")
def revoke_token(agent_id: str, role: str = Depends(current_security_role)) -> dict[str, Any]:
    require_role("admin", role)
    try:
        return _agent_view(revoke_agent_registration(agent_id=agent_id))
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"未知 Agent：{agent_id}") from exc
