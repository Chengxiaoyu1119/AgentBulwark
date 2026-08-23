from fastapi import APIRouter, Depends, HTTPException

from apps.api.agent_supervisor.auth import (
    current_security_role,
    require_any_role,
    require_api_token,
    restrict_executor_scope,
)
from apps.api.agent_supervisor.domains.attacks.agents import batch_compare_scenarios, compare_scenario, run_scenario
from apps.api.agent_supervisor.domains.attacks.attack_chains import (
    compare_attack_chain,
    list_attack_chains,
    run_attack_chain,
    write_attack_chain_report,
)
from apps.api.agent_supervisor.domains.governance.integrity import verify_audit_hashes
from apps.api.agent_supervisor.schemas.main_models import AttackChainRunRequest, BatchCompareRequest, RunRequest
from apps.api.agent_supervisor.storage.data import get_product_scenarios
from apps.api.agent_supervisor.storage.database import load_run

router = APIRouter(dependencies=[Depends(require_api_token), Depends(restrict_executor_scope)])


def _require_analyst_access(role: str = Depends(current_security_role)) -> None:
    require_any_role({"analyst", "admin"}, role)

@router.get("/api/scenarios", dependencies=[Depends(_require_analyst_access)])
def scenarios() -> list[dict]:
    return get_product_scenarios()


@router.get("/api/runs/{run_id}/audit_hash/verify")
def verify_run_audit_hash(run_id: str) -> dict:
    run = load_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail=f"未知运行记录：{run_id}")
    logs = run.get("audit_logs", [])
    if not logs:
        return {
            "run_id": run_id,
            "scenario_id": run.get("scenario", {}).get("id", ""),
            "created_at": run.get("created_at", ""),
            "valid": False,
            "checked": 0,
            "failures": [{"step": 0, "reason": "缺少审计日志"}],
        }
    if any("audit_hash" not in log or "previous_hash" not in log for log in logs):
        return {
            "run_id": run_id,
            "scenario_id": run.get("scenario", {}).get("id", ""),
            "created_at": run.get("created_at", ""),
            "valid": False,
            "checked": len(logs),
            "failures": [{"step": 0, "reason": "审计日志缺少 hash 字段"}],
        }
    verification = verify_audit_hashes(logs, seed=f"{run_id}:{run.get('created_at')}")
    return {
        "run_id": run_id,
        "scenario_id": run.get("scenario", {}).get("id", ""),
        "created_at": run.get("created_at", ""),
        "valid": verification["valid"],
        "checked": verification["checked"],
        "failures": verification["failures"],
        "first_hash": logs[0].get("audit_hash", ""),
        "last_hash": logs[-1].get("audit_hash", ""),
    }


@router.post("/api/run", dependencies=[Depends(_require_analyst_access)])
def run(request: RunRequest) -> dict:
    try:
        return run_scenario(request.scenario_id, request.guard_enabled)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"未知攻击脚本：{request.scenario_id}") from exc


@router.post("/api/compare", dependencies=[Depends(_require_analyst_access)])
def compare(request: RunRequest) -> dict:
    try:
        return compare_scenario(request.scenario_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"未知攻击脚本：{request.scenario_id}") from exc


@router.post("/api/batch_compare", dependencies=[Depends(_require_analyst_access)])
def batch_compare(request: BatchCompareRequest) -> dict:
    try:
        return batch_compare_scenarios(request.scenario_ids)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"未知攻击脚本：{exc.args[0]}") from exc


@router.get("/api/attack_chains", dependencies=[Depends(_require_analyst_access)])
def attack_chains() -> list[dict]:
    return list_attack_chains()


@router.post("/api/attack_chains/{chain_id}/run", dependencies=[Depends(_require_analyst_access)])
def run_attack_chain_endpoint(chain_id: str, request: AttackChainRunRequest) -> dict:
    try:
        return run_attack_chain(chain_id, guard_enabled=request.guard_enabled)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"未知组合攻击链：{exc.args[0]}") from exc


@router.post("/api/attack_chains/{chain_id}/compare", dependencies=[Depends(_require_analyst_access)])
def compare_attack_chain_endpoint(chain_id: str) -> dict:
    try:
        return compare_attack_chain(chain_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"未知组合攻击链：{exc.args[0]}") from exc


@router.post("/api/attack_chains/write", dependencies=[Depends(_require_analyst_access)])
def write_attack_chain_report_endpoint() -> dict:
    return write_attack_chain_report()

