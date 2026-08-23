import os
import sys
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from apps.api.agent_supervisor.domains.runtime.app_lifespan import app_lifespan
from apps.api.agent_supervisor.domains.runtime.request_limits import (
    MAX_REQUEST_BODY_BYTES,
    RequestBodyLimitMiddleware,
)

from .paths import REPO_ROOT
from .routers import core, evaluations, integrations, mcp, proxy, public, scenarios

app = FastAPI(title="智安哨 API", version="0.1.0", lifespan=app_lifespan)


def _cors_origins() -> list[str]:
    configured = os.getenv("AGENT_SUPERVISOR_CORS_ORIGINS", "")
    if configured.strip():
        return [origin.strip() for origin in configured.split(",") if origin.strip()]
    return ["http://127.0.0.1:5178", "http://localhost:5178"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(RequestBodyLimitMiddleware, max_body_bytes=MAX_REQUEST_BODY_BYTES)

app.include_router(public.router)
app.include_router(core.router)
app.include_router(scenarios.router)
app.include_router(evaluations.router)
app.include_router(integrations.router)
app.include_router(proxy.router)
app.include_router(mcp.router)

def _console_dist_dir() -> Path:
    bundled_root = Path(getattr(sys, "_MEIPASS", ""))
    bundled_dist = bundled_root / "apps" / "console" / "dist" if bundled_root else Path()
    if bundled_dist.exists():
        return bundled_dist
    return REPO_ROOT / "apps" / "console" / "dist"


_CONSOLE_DIST = _console_dist_dir()
if _CONSOLE_DIST.exists():
    app.mount("/", StaticFiles(directory=_CONSOLE_DIST, html=True), name="console")
