"""Hard boundary between the operational gateway and experiment routes."""

from fastapi import HTTPException

from apps.api.agent_supervisor.domains.runtime.agent_credentials import env_bool


def labs_enabled() -> bool:
    return env_bool("AGENT_SUPERVISOR_LABS_ENABLED")


def require_labs_enabled() -> None:
    if not labs_enabled():
        raise HTTPException(status_code=404, detail="实验环境未在当前运行实例中启用")
