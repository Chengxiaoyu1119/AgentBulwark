from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from fastapi.responses import StreamingResponse

from apps.api.agent_supervisor.adapters.integrations.agent_integrations import (
    build_agent_integration_bundle,
    build_agent_integration_markdown,
)
from apps.api.agent_supervisor.auth import (
    current_agent_identity,
    current_security_role,
    require_agent_identity,
    require_any_role,
    require_api_token,
    restrict_executor_scope,
)
from apps.api.agent_supervisor.domains.runtime.event_stream import stream_runtime_events
from apps.api.agent_supervisor.domains.runtime.execution_receipts import (
    ExecutionReceiptConflictError,
    complete_execution,
    get_execution_receipt,
    list_execution_receipts,
)
from apps.api.agent_supervisor.schemas.main_models import ExecutionReceiptRequest

router = APIRouter(dependencies=[Depends(require_api_token), Depends(restrict_executor_scope)])


def _require_executor_access(role: str = Depends(current_security_role)) -> None:
    require_any_role({"executor", "admin"}, role)


def _require_analyst_access(role: str = Depends(current_security_role)) -> None:
    require_any_role({"analyst", "admin"}, role)


@router.get("/api/events/stream")
def runtime_event_stream(role: str = Depends(current_security_role)) -> StreamingResponse:
    return StreamingResponse(
        stream_runtime_events(role=role),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/api/integrations/agents/bundle")
def agent_integration_bundle() -> dict[str, Any]:
    return build_agent_integration_bundle()


@router.get("/api/integrations/agents/bundle.md")
def agent_integration_bundle_markdown() -> Response:
    return Response(build_agent_integration_markdown(), media_type="text/markdown; charset=utf-8")


@router.post("/api/runtime/executions/{audit_id}/complete")
def runtime_execution_complete(
    audit_id: str,
    request: ExecutionReceiptRequest,
    role: str = Depends(current_security_role),
    authenticated_agent_id: str | None = Depends(current_agent_identity),
) -> dict[str, Any]:
    _require_executor_access(role)
    require_agent_identity(request.agent_id, role, authenticated_agent_id)
    try:
        return complete_execution(audit_id, request.model_dump())
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"未知审计记录：{audit_id}") from exc
    except ExecutionReceiptConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/api/runtime/executions")
def runtime_executions(limit: int = Query(200, ge=1, le=1000), role: str = Depends(current_security_role)) -> dict[str, Any]:
    _require_analyst_access(role)
    return list_execution_receipts(limit=limit)


@router.get("/api/runtime/executions/{audit_id}")
def runtime_execution(audit_id: str, role: str = Depends(current_security_role)) -> dict[str, Any]:
    _require_analyst_access(role)
    try:
        return get_execution_receipt(audit_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"未知审计记录：{audit_id}") from exc
