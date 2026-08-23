"""Unauthenticated liveness and console bootstrap metadata.

This router intentionally exposes no model, policy, Agent, route, or evidence
details. The console needs one stable endpoint to distinguish an offline
backend from an online backend that is waiting for operator authentication.
"""

from fastapi import APIRouter

from apps.api.agent_supervisor.domains.runtime.agent_credentials import env_bool
from apps.api.agent_supervisor.domains.runtime.security_profile import security_profile

router = APIRouter()


@router.get("/api/public/status")
def public_status() -> dict:
    return {
        "ok": True,
        "service": "agent-security-supervisor",
        "console_auth": {
            "required": not env_bool("AGENT_SUPERVISOR_AUTH_DISABLED"),
            "transport": "bearer",
            "profile": security_profile(),
        },
    }
