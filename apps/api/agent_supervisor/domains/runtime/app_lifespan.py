from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from apps.api.agent_supervisor.domains.evidence.gateway_evidence import initialize_gateway_runtime_evidence
from apps.api.agent_supervisor.domains.runtime.runtime_backup import clear_runtime_active, mark_runtime_active
from apps.api.agent_supervisor.domains.runtime.server_security import (
    configure_server_security,
    configured_bind_host,
    load_environment_file,
)
from apps.api.agent_supervisor.domains.runtime.tools import init_runtime
from apps.api.agent_supervisor.storage.database import init_db


@asynccontextmanager
async def app_lifespan(_: FastAPI) -> AsyncIterator[None]:
    load_environment_file()
    # Managed launchers expose the intended bind host through the
    # environment.  ``configured_bind_host`` also handles direct
    # ``uvicorn ... --host`` starts, so a public socket cannot bypass the
    # token/HMAC checks simply by skipping the repository launcher.
    configure_server_security(configured_bind_host())
    runtime_marker = mark_runtime_active()
    try:
        initialize_gateway_runtime_evidence()
        init_db()
        init_runtime()
        yield
    finally:
        # The MCP stdio gateway and optional semantic detector own subprocesses
        # / worker threads.  Closing them at application shutdown prevents a
        # reload or TestClient lifecycle from leaking processes and handles.
        from apps.api.agent_supervisor.domains.governance.semantic_detector import reset_semantic_detector
        from apps.api.agent_supervisor.mcp_gateway.gateway import reset_gateway

        reset_gateway()
        reset_semantic_detector()
        clear_runtime_active(runtime_marker)
