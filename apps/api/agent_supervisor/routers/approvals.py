from fastapi import APIRouter, Depends, HTTPException, Query, Response

from apps.api.agent_supervisor.auth import (
    authenticated_operator,
    current_agent_identity,
    current_security_role,
    require_agent_identity,
    require_any_role,
    require_api_token,
    require_role,
    restrict_executor_scope,
)
from apps.api.agent_supervisor.domains.governance.approvals import (
    build_approval_review_markdown,
    claim_approval_execution,
    complete_approval_execution,
    decide_approval_review,
    get_approval_review,
    list_approval_reviews,
    redact_approval_inventory_for_observer,
    redact_approval_review_for_observer,
    write_approval_review_report,
)
from apps.api.agent_supervisor.schemas.main_models import (
    ApprovalDecisionRequest,
    ApprovalExecutionClaimRequest,
    ApprovalExecutionCompleteRequest,
)

router = APIRouter(dependencies=[Depends(require_api_token), Depends(restrict_executor_scope)])


def _require_analyst_access(role: str = Depends(current_security_role)) -> None:
    require_any_role({"analyst", "admin"}, role)


@router.get("/api/approvals")
def approval_reviews(
    status: str = "全部",
    limit: int = Query(100, ge=1, le=500),
    role: str = Depends(current_security_role),
) -> dict:
    try:
        data = list_approval_reviews(status=status, limit=limit)
        return redact_approval_inventory_for_observer(data) if role == "observer" else data
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/api/approvals.md")
def approval_reviews_markdown(
    status: str = "全部",
    limit: int = Query(100, ge=1, le=500),
    role: str = Depends(current_security_role),
) -> Response:
    try:
        data = list_approval_reviews(status=status, limit=limit)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if role == "observer":
        data = redact_approval_inventory_for_observer(data)
    return Response(build_approval_review_markdown(data), media_type="text/markdown; charset=utf-8")


@router.post("/api/approvals/write", dependencies=[Depends(_require_analyst_access)])
def write_approval_reviews() -> dict:
    return write_approval_review_report()


@router.get("/api/approvals/{review_id}")
def approval_review_detail(review_id: str, role: str = Depends(current_security_role)) -> dict:
    try:
        review = get_approval_review(review_id)
        return redact_approval_review_for_observer(review) if role == "observer" else review
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"未知复核单：{review_id}") from exc


@router.post("/api/approvals/{review_id}/claim")
def approval_execution_claim(
    review_id: str,
    request: ApprovalExecutionClaimRequest,
    role: str = Depends(current_security_role),
    authenticated_agent_id: str | None = Depends(current_agent_identity),
) -> dict:
    require_any_role({"executor", "admin"}, role)
    require_agent_identity(request.agent_id, role, authenticated_agent_id)
    try:
        return claim_approval_execution(review_id, request.agent_id, request.tool_call)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"未知复核单：{review_id}") from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/api/approvals/{review_id}/complete")
def approval_execution_complete(
    review_id: str,
    request: ApprovalExecutionCompleteRequest,
    role: str = Depends(current_security_role),
    authenticated_agent_id: str | None = Depends(current_agent_identity),
) -> dict:
    require_any_role({"executor", "admin"}, role)
    require_agent_identity(request.agent_id, role, authenticated_agent_id)
    try:
        return complete_approval_execution(
            review_id,
            request.claim_id,
            request.agent_id,
            succeeded=request.succeeded,
            result_hash=request.result_hash,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"未知复核单：{review_id}") from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/api/approvals/{review_id}/decision")
def approval_review_decision(
    review_id: str,
    request: ApprovalDecisionRequest,
    role: str = Depends(current_security_role),
) -> dict:
    require_role("analyst", role)
    try:
        return decide_approval_review(
            review_id,
            action=request.action,
            operator=authenticated_operator(role),
            comment=request.comment,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"未知复核单：{review_id}") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/api/approvals/{review_id}/approve")
def approve_review(review_id: str, role: str = Depends(current_security_role)) -> dict:
    require_role("analyst", role)
    try:
        return decide_approval_review(
            review_id,
            action="approve",
            operator=authenticated_operator(role),
            comment="通过快捷审批接口完成批准。",
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"未知复核单：{review_id}") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/api/approvals/{review_id}/deny")
def deny_review(review_id: str, role: str = Depends(current_security_role)) -> dict:
    require_role("analyst", role)
    try:
        return decide_approval_review(
            review_id,
            action="reject",
            operator=authenticated_operator(role),
            comment="通过快捷审批接口完成拒绝。",
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"未知复核单：{review_id}") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
