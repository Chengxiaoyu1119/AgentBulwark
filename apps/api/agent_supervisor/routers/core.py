from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from apps.api.agent_supervisor.adapters.models.model_runtime_config import get_model_runtime_config, update_model_runtime_config
from apps.api.agent_supervisor.auth import (
    current_agent_identity,
    current_security_role,
    require_api_token,
    require_role,
    restrict_executor_scope,
)
from apps.api.agent_supervisor.domains.governance.tool_contract import SUPPORTED_TOOLS
from apps.api.agent_supervisor.domains.runtime.memory_governance import (
    memory_governance_snapshot,
    rollback_latest_memory,
    update_memory_status,
)
from apps.api.agent_supervisor.domains.runtime.runtime_status import build_runtime_status
from apps.api.agent_supervisor.schemas.main_models import ModelRuntimeConfigUpdate, PolicySettingsUpdate, PolicyUpdate
from apps.api.agent_supervisor.storage.data import (
    get_attack_surfaces,
    get_policies,
    get_policy_settings,
    get_scenarios,
    get_student_competition_attack_map,
    update_policy,
    update_policy_settings,
)
from apps.api.agent_supervisor.storage.database import (
    latest_audit_logs,
    latest_runs,
    latest_scenario_run_pairs,
    list_policy_versions,
    runtime_metrics_snapshot,
)

from ..adapters.models.model_adapter import provider_status
from ..services.package_service import load_competition_package_snapshot, write_competition_package_snapshot

router = APIRouter(dependencies=[Depends(require_api_token), Depends(restrict_executor_scope)])


def _competition_package_runs() -> list[dict[str, Any]]:
    """Use the same fixed scenario evidence set as /api/report.

    Runtime telemetry is intentionally excluded from the competition package so
    the snapshot digest has one stable meaning across report and delivery APIs.
    """
    return latest_scenario_run_pairs([scenario["id"] for scenario in get_scenarios()])


@router.get("/api/health")
def health() -> dict:
    return {"ok": True, "service": "agent-security-supervisor"}


@router.get("/api/auth/context")
def auth_context(
    role: str = Depends(current_security_role),
    agent_id: str | None = Depends(current_agent_identity),
) -> dict:
    return {
        "role": role,
        "agent_id": agent_id,
        "permissions": {
            "can_edit_policy": role == "admin",
            "can_review_approval": role in {"admin", "analyst"},
            "can_execute_runtime": role in {"admin", "executor"},
            "can_view": role in {"admin", "analyst", "observer"},
        },
    }


@router.get("/api/overview")
def overview() -> dict:
    runs = latest_runs(12)
    alerts = [alert for run in runs for alert in run.get("alerts", [])][:8]
    audit_logs = latest_audit_logs(12)
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
    return {
        "attack_surfaces": get_attack_surfaces(),
        "student_competition_attack_map": get_student_competition_attack_map(),
        "scenarios": get_scenarios(),
        "models": provider_status(),
        "recent_runs": runs,
        "alerts": alerts,
        "audit_logs": audit_logs,
        "summary": {
            "surface_count": len(get_attack_surfaces()),
            "scenario_count": len(get_scenarios()),
            "recent_run_count": total,
            "block_rate": round((controlled_actions / total) * 100) if total else 0,
            "guarded_run_count": len(guarded_runs),
            "guarded_controlled_count": guarded_controlled,
            "guarded_control_rate": round((guarded_controlled / len(guarded_runs)) * 100) if guarded_runs else 0,
            "attack_success_rate": round((attack_successes / total) * 100) if total else 0,
            "avg_latency_ms": round(sum(run["metrics"]["detection_latency_ms"] for run in runs) / total) if total else 0,
        },
    }


@router.get("/api/student_competition_attack_map")
def student_competition_attack_map() -> list[dict]:
    return get_student_competition_attack_map()


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
    updates: dict[str, Any] = request.dict(exclude_none=True)
    operator = str(updates.pop("operator", "security-admin"))
    comment = str(updates.pop("comment", ""))
    try:
        return update_policy(policy_id, updates, operator=operator, comment=comment)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"未知策略：{policy_id}") from exc


@router.get("/api/policy_config")
def policy_config() -> dict:
    return {
        "policies": get_policies(),
        "settings": get_policy_settings(),
        "versions": list_policy_versions(limit=20),
    }


@router.get("/api/tool_registry")
def tool_registry() -> dict:
    settings = get_policy_settings()
    return {
        "supported_capabilities": sorted(SUPPORTED_TOOLS),
        "agent_tool_mappings": settings.get("agent_tool_mappings", {}),
        "agent_tool_allowlists": settings.get("agent_tool_allowlists", {}),
        "mapping_contract": {
            "original_tool": "外部 Agent 的真实工具名称，例如 browser.open 或 database.query",
            "capability": "file.read、api.call、code.run 等标准能力之一",
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
    return update_policy_settings(request.dict(exclude_none=True))


@router.get("/api/policies/versions")
def policy_versions(policy_id: str | None = None, limit: int = Query(100, ge=1, le=500)) -> list[dict]:
    return list_policy_versions(policy_id=policy_id, limit=limit)


@router.get("/api/models")
def models() -> list[dict]:
    return provider_status()


@router.get("/api/model_config")
def model_config() -> dict:
    return get_model_runtime_config()


@router.patch("/api/model_config")
def update_model_config_endpoint(
    request: ModelRuntimeConfigUpdate,
    role: str = Depends(current_security_role),
) -> dict:
    require_role("admin", role)
    return update_model_runtime_config(request.dict(exclude_none=True))


@router.get("/api/runtime_status")
def runtime_status() -> dict:
    return build_runtime_status()


@router.get("/api/observability/metrics")
def observability_metrics(limit: int = Query(500, ge=10, le=2000)) -> dict:
    return runtime_metrics_snapshot(limit=limit)


@router.get("/api/memory_governance")
def memory_governance(limit: int = Query(80, ge=1, le=500)) -> dict:
    return memory_governance_snapshot(limit=limit)


@router.patch("/api/memory_governance/{memory_id}")
def memory_status_update(
    memory_id: str,
    request: dict[str, Any],
    role: str = Depends(current_security_role),
) -> dict:
    require_role("analyst", role)
    try:
        return update_memory_status(
            memory_id,
            str(request.get("status", "")),
            operator=str(request.get("operator", "security-analyst")),
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"未知记忆：{memory_id}") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/api/memory_governance/rollback_latest")
def memory_rollback_latest(
    request: dict[str, Any] | None = None,
    role: str = Depends(current_security_role),
) -> dict:
    require_role("analyst", role)
    return rollback_latest_memory(operator=str((request or {}).get("operator", "security-analyst")))


@router.get("/api/audit_logs")
def audit_logs(limit: int = Query(100, ge=1, le=500)) -> list[dict]:
    return latest_audit_logs(limit)


@router.get("/api/alerts")
def alerts(limit: int = Query(100, ge=1, le=500)) -> list[dict]:
    runs = latest_runs(limit)
    enriched = []
    for run in runs:
        scenario = run.get("scenario", {})
        audit_logs = run.get("audit_logs", [])
        for alert in run.get("alerts", []):
            matched_log = next(
                (
                    log
                    for log in audit_logs
                    if log.get("decision") == alert.get("decision")
                    and log.get("reason") == alert.get("evidence")
                ),
                audit_logs[0] if audit_logs else {},
            )
            enriched.append(
                {
                    **alert,
                    "scenario_id": scenario.get("id", ""),
                    "scenario_title": scenario.get("title", ""),
                    "surface_id": scenario.get("surface_id", ""),
                    "target": scenario.get("target", ""),
                    "policy_id": matched_log.get("policy_id", "unknown"),
                    "tool": matched_log.get("tool", ""),
                    "arguments": matched_log.get("arguments", {}),
                    "recommendation": matched_log.get("recommendation", ""),
                    "tool_output": matched_log.get("tool_output", {}),
                }
            )
    return enriched[:limit]


@router.get("/api/deliverables")
def deliverables() -> dict:
    runs = _competition_package_runs()
    return load_competition_package_snapshot(runs) or write_competition_package_snapshot(runs)


@router.post("/api/deliverables/refresh")
def refresh_deliverables(role: str = Depends(current_security_role)) -> dict:
    require_role("analyst", role)
    return write_competition_package_snapshot(_competition_package_runs())

