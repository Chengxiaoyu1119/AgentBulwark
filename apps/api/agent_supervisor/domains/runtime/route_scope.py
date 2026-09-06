"""Route-level scope for the bound executor role."""

from __future__ import annotations

from fastapi import Depends, HTTPException, Request

from apps.api.agent_supervisor.auth import current_security_role

EXECUTOR_ALLOWED_ROUTES = {
    ("GET", "/api/auth/context"),
    ("GET", "/api/health"),
    # Read-only runtime status is safe for a bound Agent and is needed to
    # diagnose an otherwise opaque 403/Provider-boundary state.  The handler
    # still redacts Provider endpoints for executor credentials.
    ("GET", "/api/runtime_status"),
}


def restrict_executor_scope(
    request: Request,
    role: str = Depends(current_security_role),
) -> None:
    if role != "executor":
        return
    route = (request.method.upper(), request.url.path)
    approval_action = (
        request.method.upper() == "POST"
        and request.url.path.startswith("/api/approvals/")
        and request.url.path.endswith(("/claim", "/complete"))
    )
    execution_receipt = (
        request.method.upper() == "POST"
        and request.url.path.startswith("/api/runtime/executions/")
        and request.url.path.endswith("/complete")
    )
    if route not in EXECUTOR_ALLOWED_ROUTES and not approval_action and not execution_receipt:
        raise HTTPException(status_code=403, detail="executor 角色仅允许调用生产监督和审批恢复接口")
