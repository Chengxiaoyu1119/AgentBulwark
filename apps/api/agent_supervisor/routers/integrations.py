from __future__ import annotations

from datetime import datetime, timezone
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
from apps.api.agent_supervisor.domains.governance.integrity import (
    audit_hash,
    audit_signature_required,
    verify_audit_signature,
)
from apps.api.agent_supervisor.domains.runtime.event_stream import stream_runtime_events
from apps.api.agent_supervisor.domains.runtime.execution_receipts import (
    ExecutionReceiptConflictError,
    complete_execution,
    get_execution_receipt,
    list_execution_receipts,
    verify_execution_receipt,
)
from apps.api.agent_supervisor.domains.runtime.gateway_trace import build_gateway_trace
from apps.api.agent_supervisor.schemas.main_models import ExecutionReceiptRequest
from apps.api.agent_supervisor.storage.database import (
    OPERATIONAL_SOURCE_APPS,
    load_audit_log,
    load_execution_receipt,
    load_gateway_execution_claim,
    load_gateway_request_audit_events,
)

router = APIRouter(dependencies=[Depends(require_api_token), Depends(restrict_executor_scope)])


def _require_executor_access(role: str = Depends(current_security_role)) -> None:
    require_any_role({"executor", "admin"}, role)


def _require_analyst_access(role: str = Depends(current_security_role)) -> None:
    require_any_role({"analyst", "admin"}, role)


def _safe_hash(value: Any) -> str:
    candidate = str(value or "").strip().lower()
    if len(candidate) != 64 or any(char not in "0123456789abcdef" for char in candidate):
        return ""
    return candidate


def _safe_evidence_audit(audit: dict[str, Any], audit_id: str) -> dict[str, Any]:
    raw_context = audit.get("stage_context")
    context: dict[str, Any] = raw_context if isinstance(raw_context, dict) else {}
    raw_risk_score = audit.get("risk_score")
    risk_score = max(0, min(100, raw_risk_score)) if isinstance(raw_risk_score, int) and not isinstance(raw_risk_score, bool) else 0
    safe = {
        "audit_id": str(audit.get("id") or audit_id)[:256],
        "source_app": str(audit.get("source_app") or "")[:80],
        "agent_id": str(audit.get("agent_id") or "")[:160],
        "session_id": str(context.get("session_id") or audit.get("conversation_id") or "")[:160],
        "request_id": str(context.get("request_id") or "")[:256],
        "tool": str(audit.get("tool") or "")[:160],
        "standard_capability": str(audit.get("standard_capability") or "")[:160],
        "decision": str(audit.get("decision") or "未知")[:16],
        "risk_level": str(audit.get("risk_level") or "")[:32],
        "risk_score": risk_score,
        "policy_id": str(audit.get("policy_id") or "")[:160],
        "execution_status": str(audit.get("execution_status") or "")[:40],
        "execution_target": str(audit.get("execution_target") or "")[:40],
        "execution_phase": str(audit.get("execution_phase") or context.get("execution_phase") or "")[:40],
        "execution_evidence": str(audit.get("execution_evidence") or "")[:40],
        "execution_observed_by_server": audit.get("execution_observed_by_server") is True,
        "timestamp": str(audit.get("timestamp") or "")[:80],
        "created_at": str(audit.get("created_at") or "")[:80],
        "previous_hash": _safe_hash(audit.get("previous_hash")),
        "audit_hash": _safe_hash(audit.get("audit_hash")),
        "audit_signature": str(audit.get("audit_signature") or "")[:128],
        "audit_signature_key_id": str(audit.get("audit_signature_key_id") or "")[:80],
        "tool_call_hash": _safe_hash(audit.get("tool_call_hash")),
        "request_hash": _safe_hash(context.get("request_hash")),
        "provider_request_hash": _safe_hash(context.get("provider_request_hash")),
        "provider_response_hash": _safe_hash(context.get("provider_response_hash")),
        "provider_response_id": str(context.get("provider_response_id") or "")[:160],
        "provider": str(context.get("provider") or "")[:120],
        "provider_profile": str(context.get("provider_profile") or "")[:80],
        "provider_model": str(context.get("provider_model") or "")[:160],
    }
    return safe


def _safe_evidence_receipt(receipt: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(receipt, dict):
        return None
    fields = (
        "audit_id",
        "receipt_id",
        "agent_id",
        "tool_call_hash",
        "status",
        "execution_target",
        "result_hash",
        "duration_ms",
        "run_id",
        "decision",
        "policy_id",
        "audit_hash",
        "created_at",
        "request_hash",
        "agent_followed_decision",
        "execution_evidence",
        "execution_observed_by_server",
        "execution_confirmed",
        "control_verified",
        "receipt_hash",
        "receipt_signature",
        "receipt_signature_key_id",
    )
    return {key: receipt[key] for key in fields if key in receipt}


def _safe_evidence_claim(claim: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(claim, dict):
        return None
    fields = (
        "audit_id",
        "claim_id",
        "agent_id",
        "session_id",
        "tool_call_hash",
        "status",
        "created_at",
        "completed_at",
        "receipt_id",
    )
    return {key: claim[key] for key in fields if key in claim}


def _evidence_bundle(evidence_id: str) -> dict[str, Any]:
    audit_id = evidence_id.strip()
    if not audit_id or len(audit_id) > 256:
        raise HTTPException(status_code=404, detail="未找到证据记录")
    audit = load_audit_log(audit_id)
    if not isinstance(audit, dict) or str(audit.get("source_app") or "") not in OPERATIONAL_SOURCE_APPS:
        raise HTTPException(status_code=404, detail="未找到证据记录")

    stored_audit_hash = str(audit.get("audit_hash") or "")
    try:
        audit_hash_valid = bool(stored_audit_hash) and audit_hash(audit) == stored_audit_hash
    except (TypeError, ValueError, OverflowError):
        audit_hash_valid = False
    try:
        audit_signature_valid = audit_hash_valid and verify_audit_signature(
            stored_audit_hash,
            str(audit.get("audit_signature") or ""),
        )
    except (TypeError, ValueError):
        audit_signature_valid = False

    receipt = load_execution_receipt(audit_id)
    receipt_present = isinstance(receipt, dict)
    try:
        receipt_integrity_valid = not receipt_present or verify_execution_receipt(receipt)
    except (TypeError, ValueError, OverflowError):
        receipt_integrity_valid = False
    receipt_binding_valid = not receipt_present or (
        isinstance(receipt, dict)
        and str(receipt.get("audit_id") or "") == audit_id
        and str(receipt.get("audit_hash") or "") == stored_audit_hash
    )
    receipt_valid = receipt_integrity_valid and receipt_binding_valid

    raw_context = audit.get("stage_context")
    context: dict[str, Any] = raw_context if isinstance(raw_context, dict) else {}
    request_id = str(context.get("request_id") or "").strip()
    agent_id = str(audit.get("agent_id") or "").strip()
    session_id = str(context.get("session_id") or audit.get("conversation_id") or "").strip()
    trace = None
    trace_rows: list[dict[str, Any]] = []
    if str(audit.get("source_app") or "") == "openai-compatible-proxy" and request_id:
        try:
            loaded_trace_rows = load_gateway_request_audit_events(request_id, agent_id=agent_id, session_id=session_id)
            trace_rows = loaded_trace_rows if isinstance(loaded_trace_rows, list) else []
            trace = build_gateway_trace(
                request_id,
                trace_rows,
            )
        except (TypeError, ValueError):
            trace = None
    trace_required = str(audit.get("source_app") or "") == "openai-compatible-proxy" and bool(request_id)
    trace_valid = not trace_required or (
        trace is not None and any(str(row.get("id") or "") == audit_id for row in trace_rows)
    )

    verification = {
        "valid": bool(audit_hash_valid and audit_signature_valid and receipt_valid and trace_valid),
        "audit_hash_valid": audit_hash_valid,
        "audit_signature_valid": audit_signature_valid,
        "audit_signature_required": audit_signature_required(),
        "receipt_present": receipt_present,
        "receipt_valid": receipt_valid,
        "receipt_integrity_valid": receipt_integrity_valid,
        "receipt_binding_valid": receipt_binding_valid,
        "trace_required": trace_required,
        "trace_available": trace is not None,
        "trace_valid": trace_valid,
    }
    return {
        "schema_version": "agent-supervisor.evidence.v1",
        "evidence_id": audit_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "evidence_status": "verified" if verification["valid"] else "invalid",
        "audit": _safe_evidence_audit(audit, audit_id),
        "trace": trace,
        "receipt": _safe_evidence_receipt(receipt),
        "gateway_execution_claim": _safe_evidence_claim(load_gateway_execution_claim(audit_id)),
        "verification": verification,
    }


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


@router.get("/api/evidence/{evidence_id}")
def evidence_detail(evidence_id: str, role: str = Depends(current_security_role)) -> dict[str, Any]:
    """Return a redacted, verifiable evidence bundle for one live audit."""

    _require_analyst_access(role)
    return _evidence_bundle(evidence_id)


@router.post("/api/evidence/{evidence_id}/verify")
def evidence_verify(evidence_id: str, role: str = Depends(current_security_role)) -> dict[str, Any]:
    """Verify hashes and optional HMAC without returning raw action content."""

    _require_analyst_access(role)
    bundle = _evidence_bundle(evidence_id)
    return {
        "schema_version": bundle["schema_version"],
        "evidence_id": bundle["evidence_id"],
        "verified_at": datetime.now(timezone.utc).isoformat(),
        "evidence_status": bundle["evidence_status"],
        "verification": bundle["verification"],
    }
