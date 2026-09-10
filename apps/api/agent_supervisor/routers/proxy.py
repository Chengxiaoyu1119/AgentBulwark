from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse

from apps.api.agent_supervisor.adapters.models.model_adapter import ModelProviderUnavailableError, provider_status
from apps.api.agent_supervisor.adapters.proxy.openai_proxy import (
    ProxyPolicyRejectionError,
    run_openai_proxy_completion,
    stream_openai_proxy_completion,
)
from apps.api.agent_supervisor.adapters.proxy.proxy_security import (
    require_openai_proxy_access,
    require_openai_proxy_generation,
)
from apps.api.agent_supervisor.adapters.proxy.resource_governance import ProxyResourceLimitError
from apps.api.agent_supervisor.adapters.proxy.responses_compat import (
    ResponsesCompatibilityError,
    chat_response_to_responses,
    responses_request_to_chat,
)
from apps.api.agent_supervisor.auth import (
    current_agent_identity,
    current_security_role,
    require_agent_identity,
    require_any_role,
    require_api_token,
    restrict_executor_scope,
)
from apps.api.agent_supervisor.domains.governance.tool_contract import get_agent_model_allowlist
from apps.api.agent_supervisor.domains.runtime.gateway_execution import (
    GatewayExecutionUncertainError,
    execute_gateway_tool_call,
)
from apps.api.agent_supervisor.domains.runtime.gateway_trace import build_gateway_trace, build_gateway_trace_index
from apps.api.agent_supervisor.schemas.main_models import GatewayToolExecutionRequest
from apps.api.agent_supervisor.storage.data import get_policy_settings
from apps.api.agent_supervisor.storage.database import (
    latest_gateway_audit_logs,
    load_gateway_request_audit_events,
)

router = APIRouter()


def _gateway_trace_agent_scope(role: str, authenticated_agent_id: str | None) -> str:
    """Return the server-enforced trace scope for the authenticated caller."""

    if role == "executor":
        if not authenticated_agent_id:
            raise HTTPException(status_code=403, detail="Agent Trace 查询需要绑定到 agent_id 的 executor 凭证")
        return authenticated_agent_id
    require_any_role({"analyst", "admin"}, role)
    return ""


@router.get("/api/gateway/traces", dependencies=[Depends(require_api_token)])
def gateway_traces(
    limit: int = Query(50, ge=1, le=100),
    session_id: str = Query("", max_length=160),
    role: str = Depends(current_security_role),
    authenticated_agent_id: str | None = Depends(current_agent_identity),
) -> dict[str, Any]:
    """List recent redacted LLM gateway request traces.

    This is an operational view, not a report generator.  It groups all
    request stages by the immutable gateway request id and never returns raw
    messages, tool arguments or Provider bodies.
    """

    agent_scope = _gateway_trace_agent_scope(role, authenticated_agent_id)
    rows = latest_gateway_audit_logs(
        max(200, min(limit * 64, 2000)),
        agent_id=agent_scope,
        session_id=session_id.strip(),
    )
    return build_gateway_trace_index(rows, limit=limit)


@router.get("/api/gateway/traces/{request_id}", dependencies=[Depends(require_api_token)])
def gateway_trace_detail(
    request_id: str,
    role: str = Depends(current_security_role),
    authenticated_agent_id: str | None = Depends(current_agent_identity),
) -> dict[str, Any]:
    """Return one redacted gateway trace for exact operator deep-linking."""

    agent_scope = _gateway_trace_agent_scope(role, authenticated_agent_id)
    if not request_id.strip() or len(request_id) > 256:
        raise HTTPException(status_code=404, detail="未找到网关 Trace")
    rows = load_gateway_request_audit_events(request_id, agent_id=agent_scope)
    trace = build_gateway_trace(request_id, rows)
    if trace is None:
        raise HTTPException(status_code=404, detail="未找到网关 Trace")
    return trace


@router.post(
    "/api/gateway/tool_calls/{audit_id}/execute",
    dependencies=[Depends(require_api_token), Depends(restrict_executor_scope)],
)
def gateway_tool_call_execution(
    audit_id: str,
    request: GatewayToolExecutionRequest,
    role: str = Depends(current_security_role),
    authenticated_agent_id: str | None = Depends(current_agent_identity),
) -> dict[str, Any]:
    """Execute an audited Provider tool call without accepting client arguments."""

    if not audit_id.strip() or len(audit_id) > 256:
        raise HTTPException(status_code=404, detail="未找到网关审计记录")
    require_any_role({"executor", "admin"}, role)
    require_agent_identity(request.agent_id, role, authenticated_agent_id)
    try:
        return execute_gateway_tool_call(
            audit_id,
            agent_id=request.agent_id,
            session_id=request.session_id,
            provider_call_id=request.provider_call_id,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"未知网关审计记录：{audit_id}") from exc
    except GatewayExecutionUncertainError as exc:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "gateway_execution_uncertain",
                "message": str(exc),
                "audit_id": audit_id,
                "execution_status": "unknown",
                "retry": "reconciliation-required",
            },
        ) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "gateway_execution_conflict",
                "message": str(exc),
                "audit_id": audit_id,
            },
        ) from exc


def _gateway_audit_request_hash(audit: dict[str, Any]) -> str:
    audit_log = audit.get("audit_log") if isinstance(audit, dict) else None
    if not isinstance(audit_log, dict):
        return ""
    direct = str(audit_log.get("request_hash") or "")
    if direct:
        return direct
    stage_context = audit_log.get("stage_context")
    return str(stage_context.get("request_hash") or "") if isinstance(stage_context, dict) else ""


@router.get("/v1/models")
def openai_compatible_models(
    security_context: dict = Depends(require_openai_proxy_access),
) -> dict[str, Any]:
    """Expose only configured real target models for OpenAI SDK discovery."""
    data: list[dict[str, Any]] = []
    seen: set[str] = set()
    allowed_models = get_agent_model_allowlist(
        get_policy_settings(),
        str(security_context.get("agent_id") or ""),
    )
    caller_role = str(security_context.get("role") or "observer")
    for item in provider_status("target"):
        model = str(item.get("model") or "").strip()
        if not model or not item.get("configured") or item.get("mode") != "real-api" or model in seen:
            continue
        if allowed_models is not None and caller_role != "admin" and model.lower() not in set(allowed_models):
            continue
        seen.add(model)
        data.append({"id": model, "object": "model", "created": 0, "owned_by": item.get("provider", "")})
    return {"object": "list", "data": data}


@router.post("/v1/chat/completions")
def openai_compatible_chat_completion(
    request: Any = Body(...),
    _security_context: dict = Depends(require_openai_proxy_generation),
) -> Any:
    if not isinstance(request, dict):
        raise HTTPException(status_code=400, detail="OpenAI 兼容请求必须是 JSON 对象。")
    try:
        if request.get("stream") is True:
            return StreamingResponse(
                stream_openai_proxy_completion(request, security_context=_security_context),
                media_type="text/event-stream",
                headers={
                    "Cache-Control": "no-cache",
                    "Connection": "keep-alive",
                    "X-Accel-Buffering": "no",
                    "X-Agent-Supervisor-Proxy": "openai-compatible",
                },
            )
        return run_openai_proxy_completion(request, security_context=_security_context)
    except ModelProviderUnavailableError as exc:
        gateway_audit = exc.gateway_audit if isinstance(exc.gateway_audit, dict) else {}
        raise HTTPException(
            status_code=502,
            detail={
                "message": str(exc),
                "provider_failures": exc.failures,
                "degraded": False,
                # A failed upstream attempt is not the same as a pre-provider
                # block.  Keep the boundary fact explicit so operators do not
                # mistake a 502 after an outbound request for "never sent".
                "provider_called": bool(exc.failures),
                "provider_attempted": bool(exc.failures),
                "gateway_audit_id": str(gateway_audit.get("audit_id") or ""),
                "audit_id": str(gateway_audit.get("audit_id") or ""),
                "request_hash": _gateway_audit_request_hash(gateway_audit),
                "gateway_contract_evidence": "provider-failure",
            },
        ) from exc
    except ProxyResourceLimitError as exc:
        raise HTTPException(status_code=429, detail=exc.as_detail()) from exc
    except GatewayExecutionUncertainError as exc:
        raise HTTPException(
            status_code=409,
            detail={
                "message": str(exc),
                "execution_status": "unknown",
                "retry": "reconciliation-required",
            },
        ) from exc
    except ProxyPolicyRejectionError as exc:
        gateway_audit = exc.gateway_audit if isinstance(exc.gateway_audit, dict) else {}
        raise HTTPException(
            status_code=403,
            detail={
                "message": str(exc),
                "provider_called": False,
                "gateway_audit_id": str(gateway_audit.get("audit_id") or ""),
                "audit_id": str(gateway_audit.get("audit_id") or ""),
                "gateway_contract_evidence": "pre-provider-policy-block",
            },
        ) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

@router.post("/v1/responses")
def openai_compatible_responses(
    request: Any = Body(...),
    _security_context: dict = Depends(require_openai_proxy_generation),
) -> Any:
    """Expose a fail-closed, text/function subset of the Responses API.

    The enforcement engine remains the same Chat gateway path.  Translation is
    performed before it, and the response is projected back only after the
    Provider output, tool call and receipt boundaries have been applied.
    Unsupported Responses features return 400 instead of bypassing those
    controls through an unvalidated envelope.
    """

    if not isinstance(request, dict):
        raise HTTPException(status_code=400, detail="Responses 请求必须是 JSON 对象。")
    try:
        chat_request = responses_request_to_chat(request)
        chat_response = run_openai_proxy_completion(chat_request, security_context=_security_context)
        return chat_response_to_responses(chat_response, request)
    except ModelProviderUnavailableError as exc:
        gateway_audit = exc.gateway_audit if isinstance(exc.gateway_audit, dict) else {}
        raise HTTPException(
            status_code=502,
            detail={
                "message": str(exc),
                "provider_failures": exc.failures,
                "degraded": False,
                "provider_called": bool(exc.failures),
                "provider_attempted": bool(exc.failures),
                "gateway_audit_id": str(gateway_audit.get("audit_id") or ""),
                "audit_id": str(gateway_audit.get("audit_id") or ""),
                "request_hash": _gateway_audit_request_hash(gateway_audit),
                "gateway_contract_evidence": "provider-failure",
            },
        ) from exc
    except ProxyResourceLimitError as exc:
        raise HTTPException(status_code=429, detail=exc.as_detail()) from exc
    except GatewayExecutionUncertainError as exc:
        raise HTTPException(
            status_code=409,
            detail={
                "message": str(exc),
                "execution_status": "unknown",
                "retry": "reconciliation-required",
            },
        ) from exc
    except ProxyPolicyRejectionError as exc:
        gateway_audit = exc.gateway_audit if isinstance(exc.gateway_audit, dict) else {}
        raise HTTPException(
            status_code=403,
            detail={
                "message": str(exc),
                "provider_called": False,
                "gateway_audit_id": str(gateway_audit.get("audit_id") or ""),
                "audit_id": str(gateway_audit.get("audit_id") or ""),
                "gateway_contract_evidence": "pre-provider-policy-block",
            },
        ) from exc
    except ResponsesCompatibilityError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
