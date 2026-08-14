import os
import sys
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from apps.api.agent_supervisor.domains.runtime.app_lifespan import app_lifespan

from .paths import REPO_ROOT
from .routers import core, evaluations, integrations, proxy, scenarios

MAX_REQUEST_BODY_BYTES = 1024 * 1024


class _RequestBodyTooLarge(Exception):
    pass


class RequestBodyLimitMiddleware:
    def __init__(self, app: Any, max_body_bytes: int) -> None:
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        content_length = headers.get(b"content-length", b"")
        try:
            declared_size = int(content_length) if content_length else 0
        except ValueError:
            declared_size = 0
        if declared_size > self.max_body_bytes:
            await self._reject(scope, receive, send)
            return

        received_size = 0
        response_started = False

        async def limited_receive() -> dict[str, Any]:
            nonlocal received_size
            message = await receive()
            if message.get("type") == "http.request":
                received_size += len(message.get("body", b""))
                if received_size > self.max_body_bytes:
                    raise _RequestBodyTooLarge
            return message

        async def tracked_send(message: dict[str, Any]) -> None:
            nonlocal response_started
            if message.get("type") == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracked_send)
        except _RequestBodyTooLarge:
            if response_started:
                raise
            await self._reject(scope, receive, send)

    async def _reject(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        response = JSONResponse(
            status_code=413,
            content={"detail": f"请求体不能超过 {self.max_body_bytes} 字节"},
        )
        await response(scope, receive, send)


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

app.include_router(core.router)
app.include_router(scenarios.router)
app.include_router(evaluations.router)
app.include_router(integrations.router)
app.include_router(proxy.router)

def _console_dist_dir() -> Path:
    bundled_root = Path(getattr(sys, "_MEIPASS", ""))
    bundled_dist = bundled_root / "apps" / "console" / "dist" if bundled_root else Path()
    if bundled_dist.exists():
        return bundled_dist
    return REPO_ROOT / "apps" / "console" / "dist"


_CONSOLE_DIST = _console_dist_dir()
if _CONSOLE_DIST.exists():
    app.mount("/", StaticFiles(directory=_CONSOLE_DIST, html=True), name="console")
