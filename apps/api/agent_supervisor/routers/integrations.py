import os
from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, Response
from fastapi.responses import StreamingResponse
from pydantic import ValidationError

from apps.api.agent_supervisor.adapters.integrations.agent_integrations import (
    build_agent_integration_bundle,
    build_agent_integration_markdown,
)
from apps.api.agent_supervisor.adapters.integrations.external_agent_demo import run_minimal_external_agent_demo
from apps.api.agent_supervisor.adapters.integrations.model_driven_agent import run_model_driven_agent
from apps.api.agent_supervisor.adapters.integrations.openclaw_adapter import build_openclaw_hook_example, build_openclaw_integration_bundle
from apps.api.agent_supervisor.adapters.integrations.openclaw_plugin_package import (
    build_openclaw_plugin_package_markdown,
    build_openclaw_plugin_package_summary,
    build_openclaw_plugin_validation_markdown,
    validate_openclaw_plugin_package,
    write_openclaw_plugin_package,
    write_openclaw_plugin_validation_report,
)
from apps.api.agent_supervisor.auth import (
    current_agent_identity,
    current_security_role,
    get_agent_token_bindings,
    require_agent_identity,
    require_any_role,
    require_api_token,
    restrict_executor_scope,
)
from apps.api.agent_supervisor.domains.attacks.attack_lab import (
    list_attack_lab_modules,
    run_attack_lab_module,
    run_custom_attack_chain,
    run_custom_attack_compare,
    verify_custom_attack_chain_source,
)
from apps.api.agent_supervisor.domains.attacks.attack_testsets import list_attack_testsets, run_attack_testset
from apps.api.agent_supervisor.domains.attacks.capability_replay import run_capability_replay
from apps.api.agent_supervisor.domains.attacks.penetration_lab import list_learning_scenarios, run_learning_attack
from apps.api.agent_supervisor.domains.attacks.redteam_lab import (
    run_authorized_target_test,
    run_dual_model_jailbreak,
    run_jailbreak_redteam,
    run_refusal_rewrite_evasion,
)
from apps.api.agent_supervisor.domains.attacks.target_lab import reset_target_lab, target_lab_snapshot
from apps.api.agent_supervisor.domains.runtime.event_stream import stream_runtime_events
from apps.api.agent_supervisor.domains.runtime.events import evaluate_agent_event
from apps.api.agent_supervisor.domains.runtime.execution_receipts import (
    ExecutionReceiptConflictError,
    complete_execution,
    get_execution_receipt,
    list_execution_receipts,
)
from apps.api.agent_supervisor.schemas.main_models import (
    AgentToolEvent,
    AttackLabRunRequest,
    AttackTestsetRunRequest,
    AuthorizedTargetRunRequest,
    BatchAgentToolEvents,
    CustomAttackChainRequest,
    CustomAttackCompareRequest,
    DualModelJailbreakRequest,
    ExecutionReceiptRequest,
    JailbreakRedteamRequest,
    LearningLabRunRequest,
    ModelDrivenAgentRequest,
    RefusalRewriteEvasionRequest,
)

from ..services.package_service import build_competition_package

router = APIRouter(dependencies=[Depends(require_api_token), Depends(restrict_executor_scope)])


def _require_executor_access(role: str = Depends(current_security_role)) -> None:
    require_any_role({"executor", "admin"}, role)


def _require_analyst_access(role: str = Depends(current_security_role)) -> None:
    require_any_role({"analyst", "admin"}, role)


def _require_admin_access(role: str = Depends(current_security_role)) -> None:
    require_any_role({"admin"}, role)


@router.get("/api/events/stream")
def runtime_event_stream() -> StreamingResponse:
    return StreamingResponse(
        stream_runtime_events(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/api/integrations/openclaw/schema")
def openclaw_schema() -> dict:
    return build_competition_package([])["adapter_schema"]


@router.get("/api/integrations/agents/bundle")
def agent_integration_bundle() -> dict:
    return build_agent_integration_bundle()


@router.get("/api/integrations/agents/bundle.md")
def agent_integration_bundle_markdown() -> Response:
    return Response(build_agent_integration_markdown(), media_type="text/markdown; charset=utf-8")


@router.get("/api/integrations/openclaw/adapter.py")
def openclaw_adapter_code() -> Response:
    return Response(build_openclaw_hook_example(), media_type="text/x-python; charset=utf-8")


@router.get("/api/integrations/openclaw/bundle")
def openclaw_integration_bundle() -> dict:
    return build_openclaw_integration_bundle()


@router.get("/api/integrations/openclaw/plugin_package")
def openclaw_plugin_package() -> dict:
    return build_openclaw_plugin_package_summary()


@router.get("/api/integrations/openclaw/plugin_package.md")
def openclaw_plugin_package_markdown() -> Response:
    return Response(build_openclaw_plugin_package_markdown(), media_type="text/markdown; charset=utf-8")


@router.post("/api/integrations/openclaw/plugin_package/write", dependencies=[Depends(_require_admin_access)])
def write_openclaw_plugin_package_endpoint() -> dict:
    return write_openclaw_plugin_package()


@router.get("/api/integrations/openclaw/plugin_package/validation")
def openclaw_plugin_package_validation() -> dict:
    return validate_openclaw_plugin_package()


@router.get("/api/integrations/openclaw/plugin_package/validation.md")
def openclaw_plugin_package_validation_markdown() -> Response:
    return Response(build_openclaw_plugin_validation_markdown(), media_type="text/markdown; charset=utf-8")


@router.post("/api/integrations/openclaw/plugin_package/validation/write", dependencies=[Depends(_require_admin_access)])
def write_openclaw_plugin_package_validation_endpoint(inspect_runtime: bool = False) -> dict:
    return write_openclaw_plugin_validation_report(inspect_runtime=inspect_runtime)


@router.post("/api/integrations/openclaw/minimal_agent_demo", dependencies=[Depends(_require_analyst_access)])
def openclaw_minimal_agent_demo() -> dict:
    return _run_external_agent_demo()


@router.post("/api/integrations/agents/minimal_demo", dependencies=[Depends(_require_analyst_access)])
def agent_minimal_demo() -> dict:
    return _run_external_agent_demo()


@router.post("/api/integrations/agents/model_driven_demo", dependencies=[Depends(_require_analyst_access)])
def agent_model_driven_demo(request: ModelDrivenAgentRequest) -> dict:
    try:
        return run_model_driven_agent(
            request.task,
            force_real_model=request.force_real_model,
            target_model=request.target_model,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def _run_external_agent_demo() -> dict:
    agent_tokens = get_agent_token_bindings()
    return run_minimal_external_agent_demo(
        api_token=(
            agent_tokens.get("minimal-external-agent", "")
            or os.getenv("AGENT_SUPERVISOR_API_TOKEN_EXECUTOR", "")
            or os.getenv("AGENT_SUPERVISOR_API_TOKEN", "")
        )
    )


@router.get("/api/attack_lab/modules")
def attack_lab_modules() -> dict:
    return list_attack_lab_modules()


@router.post("/api/attack_lab/run", dependencies=[Depends(_require_analyst_access)])
def attack_lab_run(request: AttackLabRunRequest) -> dict:
    try:
        return run_attack_lab_module(request.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/api/attack_lab/testsets")
def attack_lab_testsets() -> dict:
    return list_attack_testsets()


@router.post("/api/attack_lab/testsets/run", dependencies=[Depends(_require_analyst_access)])
def attack_lab_testset_run(request: AttackTestsetRunRequest) -> dict:
    try:
        return run_attack_testset(request.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/api/capability_replay/run", dependencies=[Depends(_require_analyst_access)])
def capability_replay_run() -> dict:
    return run_capability_replay()


@router.get("/api/learning_lab/scenarios")
def learning_lab_scenarios() -> dict:
    return list_learning_scenarios()


@router.post("/api/learning_lab/run", dependencies=[Depends(_require_analyst_access)])
def learning_lab_run(request: LearningLabRunRequest) -> dict:
    try:
        return run_learning_attack(request.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/api/redteam_lab/jailbreak/run", dependencies=[Depends(_require_analyst_access)])
def redteam_jailbreak_run(request: JailbreakRedteamRequest) -> dict:
    try:
        return run_jailbreak_redteam(request.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/api/redteam_lab/jailbreak/dual_model/run", dependencies=[Depends(_require_analyst_access)])
def redteam_dual_model_jailbreak_run(request: DualModelJailbreakRequest) -> dict:
    try:
        return run_dual_model_jailbreak(request.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/api/attack_lab/custom_compare", dependencies=[Depends(_require_analyst_access)])
def attack_lab_custom_compare(request: CustomAttackCompareRequest) -> dict:
    """Execute a user-supplied Agent tool call against equal local fixtures."""
    try:
        return run_custom_attack_compare(request.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/api/attack_lab/custom_chain/run", dependencies=[Depends(_require_analyst_access)])
def attack_lab_custom_chain_run(request: CustomAttackChainRequest) -> dict:
    """Continue the exact caller-authored tool call through a guarded Agent chain."""
    try:
        normalized_tool_call = {
            "tool": request.tool,
            "arguments": {
                **request.arguments,
                **({"command": request.command.strip()} if request.command.strip() else {}),
            },
        }
        source_evidence = verify_custom_attack_chain_source(
            request.source_comparison_id,
            payload=request.payload,
            tool_call=normalized_tool_call,
            agent_id=request.agent_id,
            agent_role=request.agent_role,
            context_sources=request.context_sources,
        )
        result = run_custom_attack_chain(request.model_dump(), guard_enabled=True)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "source_comparison_id": request.source_comparison_id,
        "source_comparison_trust": "verified",
        "source_comparison_evidence": source_evidence,
        **result,
    }


@router.post("/api/redteam_lab/jailbreak/refusal_rewrite/run", dependencies=[Depends(_require_analyst_access)])
def redteam_refusal_rewrite_evasion_run(request: RefusalRewriteEvasionRequest) -> dict:
    try:
        return run_refusal_rewrite_evasion(request.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/api/redteam_lab/authorized_target/run", dependencies=[Depends(_require_analyst_access)])
def redteam_authorized_target_run(request: AuthorizedTargetRunRequest) -> dict:
    try:
        return run_authorized_target_test(request.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/api/target_lab/state")
def target_lab_state() -> dict:
    return target_lab_snapshot()


@router.post("/api/target_lab/reset", dependencies=[Depends(_require_admin_access)])
def target_lab_reset() -> dict:
    return reset_target_lab()


@router.post("/api/integrations/openclaw/events", dependencies=[Depends(_require_executor_access)])
def openclaw_event(
    event: AgentToolEvent,
    role: str = Depends(current_security_role),
    authenticated_agent_id: str | None = Depends(current_agent_identity),
) -> dict:
    require_agent_identity(event.agent_id, role, authenticated_agent_id)
    try:
        result = evaluate_agent_event(
            _runtime_event_payload(event, role, authenticated_agent_id),
            guard_enabled=True,
            execute_in_sandbox=event.execute_in_sandbox,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "conversation_id": event.conversation_id,
        "agent_id": event.agent_id,
        "agent_role": event.agent_role,
        "tool_call": event.tool_call,
        **result,
    }


@router.post("/api/runtime/evaluate", dependencies=[Depends(_require_executor_access)])
@router.post("/api/supervisor/evaluate", dependencies=[Depends(_require_executor_access)])
def supervisor_evaluate(
    event: AgentToolEvent,
    role: str = Depends(current_security_role),
    authenticated_agent_id: str | None = Depends(current_agent_identity),
) -> dict:
    require_agent_identity(event.agent_id, role, authenticated_agent_id)
    try:
        return evaluate_agent_event(
            _runtime_event_payload(event, role, authenticated_agent_id),
            guard_enabled=True,
            execute_in_sandbox=event.execute_in_sandbox,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/api/runtime/executions/{audit_id}/complete", dependencies=[Depends(_require_executor_access)])
def runtime_execution_complete(
    audit_id: str,
    request: ExecutionReceiptRequest,
    role: str = Depends(current_security_role),
    authenticated_agent_id: str | None = Depends(current_agent_identity),
) -> dict:
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
def runtime_executions(limit: int = 200) -> dict:
    if limit < 1 or limit > 1000:
        raise HTTPException(status_code=400, detail="limit 必须在 1 到 1000 之间")
    return list_execution_receipts(limit=limit)


@router.get("/api/runtime/executions/{audit_id}", dependencies=[Depends(_require_analyst_access)])
def runtime_execution(audit_id: str) -> dict:
    try:
        return get_execution_receipt(audit_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"未知审计记录：{audit_id}") from exc


@router.post("/api/lab/evaluate", dependencies=[Depends(_require_analyst_access)])
def lab_evaluate(event: AgentToolEvent) -> dict:
    try:
        return evaluate_agent_event(
            event.model_dump(),
            guard_enabled=event.guard_enabled,
            execute_in_sandbox=event.execute_in_sandbox,
            review_scope="experiment",
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/api/runtime/batch_evaluate", dependencies=[Depends(_require_executor_access)])
@router.post("/api/supervisor/batch_evaluate", dependencies=[Depends(_require_executor_access)])
def supervisor_batch_evaluate(
    request: Any = Body(...),
    role: str = Depends(current_security_role),
    authenticated_agent_id: str | None = Depends(current_agent_identity),
) -> dict:
    return _batch_evaluate(
        request,
        allow_guard_toggle=False,
        role=role,
        authenticated_agent_id=authenticated_agent_id,
    )


@router.post("/api/lab/batch_evaluate", dependencies=[Depends(_require_analyst_access)])
def lab_batch_evaluate(request: Any = Body(...)) -> dict:
    return _batch_evaluate(request, allow_guard_toggle=True, role="analyst", authenticated_agent_id=None)


def _batch_evaluate(
    request: Any,
    *,
    allow_guard_toggle: bool,
    role: str,
    authenticated_agent_id: str | None,
) -> dict:
    try:
        if isinstance(request, list):
            batch = BatchAgentToolEvents(events=[AgentToolEvent(**event) for event in request])
        elif isinstance(request, dict):
            batch = BatchAgentToolEvents(**request)
        else:
            raise HTTPException(status_code=400, detail="批量事件必须是 JSON 数组，或包含 events 字段的对象。")
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if not allow_guard_toggle:
        for event in batch.events:
            require_agent_identity(event.agent_id, role, authenticated_agent_id)
    results = []
    for event in batch.events:
        try:
            results.append(
                evaluate_agent_event(
                    (
                        event.model_dump()
                        if allow_guard_toggle
                        else _runtime_event_payload(event, role, authenticated_agent_id)
                    ),
                    guard_enabled=(batch.guard_enabled and event.guard_enabled) if allow_guard_toggle else True,
                    execute_in_sandbox=batch.execute_in_sandbox or event.execute_in_sandbox,
                    review_scope="experiment" if allow_guard_toggle else "operational",
                )
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    controlled = [item for item in results if item["decision"] in {"拒绝", "询问", "隔离"}]
    return {
        "total": len(results),
        "controlled": len(controlled),
        "control_rate": round((len(controlled) / len(results)) * 100) if results else 0,
        "results": results,
    }


def _runtime_event_payload(event: AgentToolEvent, role: str, authenticated_agent_id: str | None) -> dict[str, Any]:
    payload = event.model_dump()
    payload.update(
        {
            "authenticated_role": role,
            "authenticated_agent_id": authenticated_agent_id or "",
            "agent_identity_verified": authenticated_agent_id == event.agent_id,
            "agent_identity_admin_override": role == "admin" and authenticated_agent_id is None,
            "agent_identity_shared_compatibility": role == "executor" and authenticated_agent_id is None,
        }
    )
    return payload

