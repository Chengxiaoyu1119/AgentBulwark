from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from apps.api.agent_supervisor.adapters.models.model_runtime_config import (
    PROFILE_IDS,
    get_model_runtime_config,
    update_model_runtime_config,
)
from apps.api.agent_supervisor.auth import (
    authenticated_operator,
    current_agent_identity,
    current_security_role,
    require_api_token,
    require_role,
    restrict_executor_scope,
)
from apps.api.agent_supervisor.domains.governance.tool_contract import SUPPORTED_TOOLS
from apps.api.agent_supervisor.domains.runtime.agent_credentials import can_execute_managed_tools
from apps.api.agent_supervisor.domains.runtime.mcp_access import mcp_access_capabilities
from apps.api.agent_supervisor.domains.runtime.memory_governance import (
    memory_governance_snapshot,
    rollback_latest_memory,
    update_memory_status,
)
from apps.api.agent_supervisor.domains.runtime.runtime_status import build_runtime_status
from apps.api.agent_supervisor.schemas.main_models import (
    ModelProviderProbeRequest,
    ModelRuntimeConfigUpdate,
    PolicySettingsUpdate,
    PolicyUpdate,
)
from apps.api.agent_supervisor.storage.data import (
    get_policies,
    get_policy_settings,
    update_policy,
    update_policy_settings,
)
from apps.api.agent_supervisor.storage.database import (
    latest_operational_audit_logs,
    list_policy_versions,
    runtime_metrics_snapshot,
)

from ..adapters.models.model_adapter import probe_provider, provider_status

router = APIRouter(dependencies=[Depends(require_api_token), Depends(restrict_executor_scope)])


def _require_analyst_access(role: str = Depends(current_security_role)) -> None:
    require_role("analyst", role)


def _provider_status_for_role(role: str, profile: str = "") -> list[dict[str, Any]]:
    """Return model readiness without leaking Provider routing topology.

    Observer credentials need model availability and names for the console, not
    the configured vendor URLs.  Analysts and admins can inspect destinations
    through the operational status endpoint when diagnosing a deployment.
    Keep this policy in one helper so overview, model discovery, and runtime
    status do not drift apart.
    """

    statuses = provider_status(profile)
    if role in {"analyst", "admin"}:
        return statuses
    return [{key: value for key, value in item.items() if key != "endpoint"} for item in statuses]


def _redact_observer_audit(log: dict[str, Any]) -> dict[str, Any]:
    """Project audit evidence to a summary-only observer contract.

    Audit rows are intentionally rich for analysts: tool arguments, model
    excerpts and upstream results are useful for incident response, but they
    are also untrusted Agent context and may contain tenant data.  A read-only
    observer should be able to see that a control fired without receiving the
    payload that triggered it.
    """
    safe_fields = {
        "id",
        "run_id",
        "step",
        "tool",
        "standard_capability",
        "decision",
        "risk_level",
        "risk_score",
        "policy_id",
        "execution_status",
        "execution_outcome",
        "execution_target",
        "execution_phase",
        "execution_evidence",
        "execution_observed_by_server",
        "timestamp",
        "created_at",
        "source_app",
        "audit_hash",
        "audit_signature",
        "provider_called",
        "forwarded",
        "upstream_route",
    }
    safe = {key: log[key] for key in safe_fields if key in log}
    safe.update(
        {
            "arguments": {},
            "standard_arguments": {},
            "tool_output": {},
            "model_input": "",
            "model_output": "",
            "reason": "审计正文按访问范围隐藏。",
            "recommendation": "请由 analyst/admin 查看详细上下文。",
            "risk_factors": [],
            "anomaly_signals": [],
            "stage_context": {},
            "access_scope": "summary-redacted",
        }
    )
    receipt = log.get("execution_receipt")
    if isinstance(receipt, dict):
        safe["execution_receipt"] = {
            key: receipt[key]
            for key in (
                "status",
                "execution_target",
                "execution_evidence",
                "execution_observed_by_server",
                "receipt_hash",
                "result_hash",
            )
            if key in receipt
        }
    return safe


def _redact_observer_run(run: dict[str, Any]) -> dict[str, Any]:
    """Keep dashboard metrics while removing model/tool payloads for observers."""
    safe = {
        key: run[key]
        for key in (
            "id",
            "run_id",
            "created_at",
            "guard_enabled",
            "attack_success",
            "metrics",
        )
        if key in run
    }
    attack_outcome = run.get("attack_outcome")
    if isinstance(attack_outcome, dict):
        safe["attack_outcome"] = {
            key: attack_outcome[key]
            for key in ("attack_success", "execution_outcome", "source", "evidence_verdict")
            if key in attack_outcome
        }
    scenario = run.get("scenario")
    if isinstance(scenario, dict):
        safe["scenario"] = {
            key: scenario[key]
            for key in ("id", "surface_id", "title", "severity", "tags")
            if key in scenario
        }
    model_result = run.get("model_result")
    if isinstance(model_result, dict):
        safe["model_result"] = {
            key: model_result[key]
            for key in ("provider", "model", "mode", "provider_called", "provider_endpoint_scope")
            if key in model_result
        }
    safe["agent_trace"] = []
    raw_logs = run.get("audit_logs")
    if isinstance(raw_logs, list):
        safe["audit_logs"] = [_redact_observer_audit(item) for item in raw_logs if isinstance(item, dict)]
    raw_alerts = run.get("alerts")
    if isinstance(raw_alerts, list):
        safe["alerts"] = [
            {
                key: item[key]
                for key in ("id", "run_id", "severity", "decision", "risk_score", "created_at")
                if key in item
            }
            for item in raw_alerts
            if isinstance(item, dict)
        ]
    safe["access_scope"] = "summary-redacted"
    return safe


def _redact_observer_policy_settings(settings: dict[str, Any]) -> dict[str, Any]:
    """Hide Agent IDs, API hosts and tool mapping descriptions from observers."""
    safe = {
        key: value
        for key, value in settings.items()
        if key
        not in {
            "agent_tool_allowlists",
            "agent_api_allowlists",
            "agent_model_allowlists",
            "agent_context_allowlists",
            "agent_tool_mappings",
        }
    }
    safe["agent_boundary_counts"] = {
        "tool_allowlists": len(settings.get("agent_tool_allowlists", {}))
        if isinstance(settings.get("agent_tool_allowlists"), dict)
        else 0,
        "api_allowlists": len(settings.get("agent_api_allowlists", {}))
        if isinstance(settings.get("agent_api_allowlists"), dict)
        else 0,
        "model_allowlists": len(settings.get("agent_model_allowlists", {}))
        if isinstance(settings.get("agent_model_allowlists"), dict)
        else 0,
        "context_allowlists": len(settings.get("agent_context_allowlists", {}))
        if isinstance(settings.get("agent_context_allowlists"), dict)
        else 0,
        "tool_mappings": sum(
            len(value) for value in settings.get("agent_tool_mappings", {}).values() if isinstance(value, dict)
        )
        if isinstance(settings.get("agent_tool_mappings"), dict)
        else 0,
    }
    safe["access_scope"] = "summary-redacted"
    return safe


@router.get("/api/health")
def health() -> dict:
    return {"ok": True, "service": "agent-security-supervisor"}


@router.get("/api/auth/context")
def auth_context(
    role: str = Depends(current_security_role),
    agent_id: str | None = Depends(current_agent_identity),
) -> dict:
    can_generate = role in {"executor", "analyst", "admin"}
    mcp_capabilities = mcp_access_capabilities(role, agent_id)
    return {
        "role": role,
        "agent_id": agent_id,
        "identity_bound": bool(agent_id),
        "permissions": {
            "can_edit_policy": role == "admin",
            "can_review_approval": role in {"admin", "analyst"},
            "can_execute_runtime": role in {"admin", "executor"},
            "can_generate": can_generate,
            "can_execute_managed_tools": can_execute_managed_tools(role, agent_id),
            **mcp_capabilities,
            "can_view": role in {"admin", "analyst", "observer"},
        },
    }


@router.get("/api/overview")
def overview(role: str = Depends(current_security_role)) -> dict:
    # ``experiment_runs`` is a legacy evidence store.  The operational
    # console uses gateway traces and must not present those historical
    # scenario payloads as current runtime traffic.
    runs: list[dict[str, Any]] = []
    alerts: list[dict[str, Any]] = []
    audit_logs: list[dict[str, Any]] = []
    total = len(runs)
    controlled_actions = sum(
        1
        for run in runs
        if run["metrics"]["blocked_count"] > 0
        or run["metrics"].get("asked_count", 0) > 0
        or run["metrics"].get("isolated_count", 0) > 0
    )
    guarded_runs = [run for run in runs if run.get("guard_enabled")]
    guarded_controlled = sum(1 for run in guarded_runs if not run.get("attack_success"))
    attack_successes = sum(1 for run in runs if run["attack_success"])
    payload = {
        "models": _provider_status_for_role(role),
        "recent_runs": runs,
        "alerts": alerts,
        "audit_logs": audit_logs,
        "summary": {
            "recent_run_count": total,
            "block_rate": round((controlled_actions / total) * 100) if total else 0,
            "guarded_run_count": len(guarded_runs),
            "guarded_controlled_count": guarded_controlled,
            "guarded_control_rate": round((guarded_controlled / len(guarded_runs)) * 100) if guarded_runs else 0,
            "attack_success_rate": round((attack_successes / total) * 100) if total else 0,
            "avg_latency_ms": round(sum(run["metrics"]["detection_latency_ms"] for run in runs) / total) if total else 0,
        },
    }
    if role == "observer":
        payload["recent_runs"] = [_redact_observer_run(run) for run in runs]
        payload["alerts"] = [
            {
                key: item[key]
                for key in ("id", "run_id", "severity", "decision", "risk_score", "created_at")
                if key in item
            }
            for item in alerts
            if isinstance(item, dict)
        ]
        payload["audit_logs"] = [_redact_observer_audit(item) for item in audit_logs if isinstance(item, dict)]
        payload["access_scope"] = "summary-redacted"
    return payload


@router.get("/api/policies")
def policies() -> list[dict]:
    return get_policies()


@router.patch("/api/policies/{policy_id}")
def update_policy_endpoint(
    policy_id: str,
    request: PolicyUpdate,
    role: str = Depends(current_security_role),
) -> dict:
    require_role("admin", role)
    updates: dict[str, Any] = request.model_dump(exclude_none=True)
    updates.pop("operator", None)
    operator = authenticated_operator(role)
    comment = str(updates.pop("comment", ""))
    try:
        return update_policy(policy_id, updates, operator=operator, comment=comment)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"未知策略：{policy_id}") from exc


@router.get("/api/policy_config")
def policy_config(role: str = Depends(current_security_role)) -> dict:
    settings = get_policy_settings()
    return {
        "policies": get_policies(),
        "settings": _redact_observer_policy_settings(settings) if role == "observer" else settings,
        "versions": list_policy_versions(limit=20),
    }


@router.get("/api/tool_registry")
def tool_registry(role: str = Depends(current_security_role)) -> dict:
    settings = get_policy_settings()
    if role == "observer":
        return {
            "supported_capabilities": sorted(SUPPORTED_TOOLS),
            "agent_boundary_counts": _redact_observer_policy_settings(settings)["agent_boundary_counts"],
            "mapping_contract": {
                "original_tool": "外部 Agent 的真实工具名称",
                "capability": "标准能力名称",
                "scope": "配置正文按访问范围隐藏",
            },
            "access_scope": "summary-redacted",
        }
    return {
        "supported_capabilities": sorted(SUPPORTED_TOOLS),
        "agent_tool_mappings": settings.get("agent_tool_mappings", {}),
        "agent_tool_allowlists": settings.get("agent_tool_allowlists", {}),
        "agent_api_allowlists": settings.get("agent_api_allowlists", {}),
        "agent_model_allowlists": settings.get("agent_model_allowlists", {}),
        "mapping_contract": {
            "original_tool": "外部 Agent 的真实工具名称，例如 browser.open 或 database.query",
                "capability": "file.read、api.call 等标准能力之一",
            "argument_mapping": "原始参数名到标准参数名的映射，例如 url -> endpoint",
            "required_arguments": "服务端校验的必填原始参数",
        },
    }


@router.patch("/api/policy_settings")
def update_policy_settings_endpoint(
    request: PolicySettingsUpdate,
    role: str = Depends(current_security_role),
) -> dict:
    require_role("admin", role)
    updates = request.model_dump(exclude_none=True)
    updates["operator"] = authenticated_operator(role)
    return update_policy_settings(updates)


@router.get("/api/policies/versions")
def policy_versions(
    policy_id: str | None = None,
    limit: int = Query(100, ge=1, le=500),
    role: str = Depends(current_security_role),
) -> list[dict]:
    rows = list_policy_versions(policy_id=policy_id, limit=limit)
    if role != "observer":
        return rows
    return [
        {
            key: item[key]
            for key in ("id", "policy_id", "created_at")
            if key in item
        }
        | {"access_scope": "summary-redacted"}
        for item in rows
    ]


@router.get("/api/models")
def models(
    profile: str | None = Query(default=None),
    role: str = Depends(current_security_role),
) -> list[dict[str, Any]]:
    requested_profile = str(profile or "").strip().lower()
    if requested_profile and requested_profile not in PROFILE_IDS:
        raise HTTPException(status_code=400, detail="模型 profile 无效")
    return _provider_status_for_role(role, requested_profile)


@router.get("/api/model_config")
def model_config() -> dict:
    return get_model_runtime_config()


@router.patch("/api/model_config")
def update_model_config_endpoint(
    request: ModelRuntimeConfigUpdate,
    role: str = Depends(current_security_role),
) -> dict:
    require_role("admin", role)
    return update_model_runtime_config(request.model_dump(exclude_none=True))


@router.post("/api/model_probe", dependencies=[Depends(_require_analyst_access)])
def model_probe(request: ModelProviderProbeRequest) -> dict[str, Any]:
    """Run one explicit real Provider connectivity and response-shape probe."""

    try:
        return probe_provider(profile=request.profile, provider_id=request.provider_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/api/runtime_status")
def runtime_status(
    role: str = Depends(current_security_role),
    agent_id: str | None = Depends(current_agent_identity),
) -> dict:
    # Provider endpoints and MCP route topology are operational secrets.  The
    # console still receives readiness flags as an observer, while analyst/admin
    # operators can inspect the configured destinations during diagnosis.
    status = build_runtime_status(expose_provider_endpoints=role in {"analyst", "admin"})
    # Keep the caller's effective identity beside the runtime facts.  A
    # gateway client must be able to distinguish "the Provider is unavailable"
    # from "this credential is observer-only" without guessing from a 403.
    status["security_context"] = {
        "role": role,
        "agent_id": agent_id or "",
        "identity_bound": bool(agent_id),
        "can_generate": role in {"executor", "analyst", "admin"},
        "can_execute_managed_tools": can_execute_managed_tools(role, agent_id),
        "can_view_console": role in {"observer", "analyst", "admin"},
        **mcp_access_capabilities(role, agent_id),
    }
    return status


@router.get("/api/observability/metrics")
def observability_metrics(limit: int = Query(500, ge=10, le=2000)) -> dict:
    return runtime_metrics_snapshot(limit=limit)


@router.get("/api/memory_governance")
def memory_governance(
    limit: int = Query(80, ge=1, le=500),
    role: str = Depends(current_security_role),
    authenticated_agent_id: str | None = Depends(current_agent_identity),
    agent_id: str | None = Query(default=None, max_length=160),
) -> dict:
    scoped_agent_id = _memory_scope_agent_id(role, authenticated_agent_id, agent_id)
    # Keep the domain snapshot immutable for the caller and for any concurrent
    # governance request; observer redaction is a response transformation.
    snapshot = dict(memory_governance_snapshot(limit=limit, agent_id=scoped_agent_id))
    snapshot["agent_id"] = scoped_agent_id or ""
    if role in {"analyst", "admin"}:
        snapshot["access_scope"] = "full"
        return snapshot

    # Memory contents are untrusted Agent context and may contain credentials,
    # prompt-injection text, or tenant data.  Read-only observer/executor
    # credentials can see counts and status, but the governance API must not
    # become a side channel that exposes the stored payload to them.
    redacted_items: list[dict[str, Any]] = []
    for item in snapshot.get("items", []):
        if not isinstance(item, dict):
            continue
        redacted = dict(item)
        redacted["content"] = "[记忆正文按访问范围隐藏]"
        redacted["content_redacted"] = True
        redacted_items.append(redacted)
    snapshot["items"] = redacted_items
    snapshot["access_scope"] = "summary-redacted"
    return snapshot


@router.patch("/api/memory_governance/{memory_id}")
def memory_status_update(
    memory_id: str,
    request: dict[str, Any],
    role: str = Depends(current_security_role),
    authenticated_agent_id: str | None = Depends(current_agent_identity),
) -> dict:
    require_role("analyst", role)
    scoped_agent_id = _memory_scope_agent_id(
        role,
        authenticated_agent_id,
        str(request.get("agent_id") or "").strip() or None,
    )
    try:
        return update_memory_status(
            memory_id,
            str(request.get("status", "")),
            operator=authenticated_operator(role),
            agent_id=scoped_agent_id,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"未知记忆：{memory_id}") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/api/memory_governance/rollback_latest")
def memory_rollback_latest(
    request: dict[str, Any] | None = None,
    role: str = Depends(current_security_role),
    authenticated_agent_id: str | None = Depends(current_agent_identity),
) -> dict:
    require_role("analyst", role)
    body = request or {}
    scoped_agent_id = _memory_scope_agent_id(
        role,
        authenticated_agent_id,
        str(body.get("agent_id") or "").strip() or None,
    )
    return rollback_latest_memory(
        operator=authenticated_operator(role),
        agent_id=scoped_agent_id,
    )


def _memory_scope_agent_id(
    role: str,
    authenticated_agent_id: str | None,
    requested_agent_id: str | None,
) -> str | None:
    """Keep governance reads/writes on the executor's authenticated scope."""

    requested = (requested_agent_id or "").strip()
    if authenticated_agent_id:
        if requested and requested != authenticated_agent_id:
            raise HTTPException(status_code=403, detail="记忆治理 Agent 范围与当前凭证不一致")
        return authenticated_agent_id
    if requested and role != "admin":
        raise HTTPException(status_code=403, detail="只有管理员可以选择其他 Agent 的记忆范围")
    return requested or None


@router.get("/api/audit_logs")
def audit_logs(
    limit: int = Query(100, ge=1, le=500),
    role: str = Depends(current_security_role),
) -> list[dict]:
    rows = latest_operational_audit_logs(limit)
    return [_redact_observer_audit(item) for item in rows] if role == "observer" else rows


@router.get("/api/alerts")
def alerts(
    limit: int = Query(100, ge=1, le=500),
    role: str = Depends(current_security_role),
) -> list[dict]:
    # Legacy alerts were synthesized from experiment_runs.  The operational
    # console reads gateway traces instead, so never expose historical lab
    # payloads through this compatibility endpoint.
    return []
