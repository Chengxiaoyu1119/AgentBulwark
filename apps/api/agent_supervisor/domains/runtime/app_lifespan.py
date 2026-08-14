from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from apps.api.agent_supervisor.domains.runtime.tools import init_sandbox
from apps.api.agent_supervisor.storage.database import init_db


@asynccontextmanager
async def app_lifespan(_: FastAPI) -> AsyncIterator[None]:
    init_db()
    init_sandbox()
    yield
