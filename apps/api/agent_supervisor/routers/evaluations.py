import json
import re
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from fastapi.responses import FileResponse

from apps.api.agent_supervisor.auth import (
    current_agent_identity,
    current_security_role,
    require_agent_identity,
    require_any_role,
    require_api_token,
    require_role,
    restrict_executor_scope,
)
from apps.api.agent_supervisor.domains.attacks.agents import batch_compare_scenarios
from apps.api.agent_supervisor.domains.evaluations.ablation import (
    build_policy_ablation,
    build_policy_ablation_markdown,
    write_policy_ablation_report,
)
from apps.api.agent_supervisor.domains.evaluations.assessment import build_attack_effectiveness
from apps.api.agent_supervisor.domains.evaluations.benign import build_benign_cases_markdown, evaluate_benign_cases, get_benign_cases
from apps.api.agent_supervisor.domains.evaluations.benign_workflows import (
    build_benign_workflow_markdown,
    evaluate_benign_workflows,
    write_benign_workflow_report,
)
from apps.api.agent_supervisor.domains.evaluations.calibration import (
    build_anomaly_calibration,
    build_anomaly_calibration_markdown,
    write_anomaly_calibration_report,
)
from apps.api.agent_supervisor.domains.evaluations.competition_benchmark import (
    build_competition_benchmark,
    build_competition_benchmark_markdown,
    write_competition_benchmark_report,
)
from apps.api.agent_supervisor.domains.evaluations.datasets import build_attack_case_dataset, build_attack_case_markdown
from apps.api.agent_supervisor.domains.evaluations.demo_drill import (
    build_judge_demo_drill_markdown,
    load_judge_demo_drill_report,
    run_judge_demo_drill,
)
from apps.api.agent_supervisor.domains.evaluations.evidence import (
    build_output_filter_evidence,
    build_output_filter_markdown,
    build_surface_conclusions,
    build_surface_conclusions_markdown,
)
from apps.api.agent_supervisor.domains.evaluations.gap_rerun import run_gap_rerun
from apps.api.agent_supervisor.domains.evaluations.holdout import evaluate_adversarial_holdout
from apps.api.agent_supervisor.domains.governance.approvals import (
    build_approval_review_markdown,
    claim_approval_execution,
    complete_approval_execution,
    decide_approval_review,
    get_approval_review,
    list_approval_reviews,
    write_approval_review_report,
)
from apps.api.agent_supervisor.domains.runtime.runtime_evaluation import (
    build_real_model_evaluation,
    build_real_model_evaluation_markdown,
    load_real_model_evaluation_report,
    write_real_model_evaluation_report,
)
from apps.api.agent_supervisor.paths import SANDBOX_REPORTS_DIR
from apps.api.agent_supervisor.schemas.main_models import (
    ApprovalDecisionRequest,
    ApprovalExecutionClaimRequest,
    ApprovalExecutionCompleteRequest,
    RealModelEvaluationRequest,
)
from apps.api.agent_supervisor.storage.data import get_scenarios
from apps.api.agent_supervisor.storage.database import latest_runs, latest_scenario_run_pairs

from ..domains.reports.briefing_export import (
    EXPORT_DIR_NAME,
    build_briefing_sheet_export_markdown,
    load_briefing_sheet_export_report,
    write_briefing_sheet_exports,
)
from ..domains.reports.readiness import (
    build_competition_readiness,
    build_competition_readiness_markdown,
    write_competition_readiness_report,
)
from ..domains.reports.roadmap import build_project_roadmap, build_project_roadmap_markdown, write_project_roadmap
from ..domains.reports.surface_pack import (
    build_surface_briefing_sheet_html,
    build_surface_evidence_index,
    build_surface_evidence_index_markdown,
    build_surface_evidence_pack,
    build_surface_evidence_pack_markdown,
    write_all_surface_briefing_sheets,
    write_all_surface_evidence_packs,
    write_surface_briefing_sheet,
    write_surface_evidence_pack,
)
from ..services.report_service import build_report

router = APIRouter(dependencies=[Depends(require_api_token), Depends(restrict_executor_scope)])


def _competition_evidence_runs() -> list[dict[str, Any]]:
    return latest_scenario_run_pairs([scenario["id"] for scenario in get_scenarios()])


@router.get("/api/evaluations/real_model")
def real_model_evaluation(force_real: bool = True) -> dict:
    return build_real_model_evaluation(force_real=force_real)


@router.get("/api/evaluations/real_model.md")
def real_model_evaluation_markdown(force_real: bool = True) -> Response:
    data = build_real_model_evaluation(force_real=force_real)
    return Response(build_real_model_evaluation_markdown(data), media_type="text/markdown; charset=utf-8")


@router.post("/api/evaluations/real_model/write")
def write_real_model_evaluation(request: RealModelEvaluationRequest) -> dict:
    return write_real_model_evaluation_report(force_real=request.force_real)


@router.get("/api/evaluations/real_model/latest")
def latest_real_model_evaluation() -> dict:
    data = load_real_model_evaluation_report()
    if data is None:
        return {"available": False, "message": "尚未生成真实模型工具调用盲测报告。"}
    return {"available": True, **data}


@router.get("/api/evaluations/real_model/latest.md")
def latest_real_model_evaluation_markdown() -> Response:
    data = load_real_model_evaluation_report()
    if data is None:
        return Response("尚未生成真实模型工具调用盲测报告。", media_type="text/markdown; charset=utf-8")
    return Response(build_real_model_evaluation_markdown(data), media_type="text/markdown; charset=utf-8")


@router.get("/api/evaluations/competition_benchmark")
def competition_benchmark(
    repeats: int = Query(3, ge=1, le=50),
    concurrency: int = Query(20, ge=1, le=100),
) -> dict:
    return build_competition_benchmark(performance_repeats=repeats, concurrency=concurrency)


@router.get("/api/evaluations/competition_benchmark.md")
def competition_benchmark_markdown(
    repeats: int = Query(3, ge=1, le=50),
    concurrency: int = Query(20, ge=1, le=100),
) -> Response:
    data = build_competition_benchmark(performance_repeats=repeats, concurrency=concurrency)
    return Response(build_competition_benchmark_markdown(data), media_type="text/markdown; charset=utf-8")


@router.post("/api/evaluations/competition_benchmark/write")
def write_competition_benchmark(
    repeats: int = Query(10, ge=1, le=50),
    concurrency: int = Query(20, ge=1, le=100),
) -> dict:
    return write_competition_benchmark_report(performance_repeats=repeats, concurrency=concurrency)

@router.get("/api/approvals")
def approval_reviews(
    status: str = "全部",
    scope: str = "全部",
    limit: int = Query(100, ge=1, le=500),
) -> dict:
    try:
        return list_approval_reviews(status=status, limit=limit, scope=scope)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/api/approvals.md")
def approval_reviews_markdown(
    status: str = "全部",
    scope: str = "全部",
    limit: int = Query(100, ge=1, le=500),
) -> Response:
    try:
        data = list_approval_reviews(status=status, limit=limit, scope=scope)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return Response(build_approval_review_markdown(data), media_type="text/markdown; charset=utf-8")


@router.post("/api/approvals/write")
def write_approval_reviews() -> dict:
    return write_approval_review_report()


@router.get("/api/approvals/{review_id}")
def approval_review_detail(review_id: str) -> dict:
    try:
        return get_approval_review(review_id)
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
            operator=request.operator,
            comment=request.comment,
            execute_in_sandbox=request.execute_in_sandbox,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"未知复核单：{review_id}") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/api/datasets/attack_cases")
def attack_cases_dataset(surface_id: str | None = None) -> dict:
    return build_attack_case_dataset(surface_id)


@router.get("/api/datasets/attack_cases.md")
def attack_cases_markdown(surface_id: str | None = None) -> Response:
    return Response(build_attack_case_markdown(surface_id), media_type="text/markdown; charset=utf-8")


@router.get("/api/project_roadmap")
def project_roadmap() -> dict:
    return build_project_roadmap(_competition_evidence_runs())


@router.get("/api/project_roadmap.md")
def project_roadmap_markdown() -> Response:
    return Response(build_project_roadmap_markdown(_competition_evidence_runs()), media_type="text/markdown; charset=utf-8")


@router.post("/api/project_roadmap/write")
def write_project_roadmap_report() -> dict:
    return write_project_roadmap(runs=_competition_evidence_runs())


@router.get("/api/readiness")
def competition_readiness() -> dict:
    return build_competition_readiness(_competition_evidence_runs())


@router.get("/api/readiness.md")
def competition_readiness_markdown() -> Response:
    return Response(build_competition_readiness_markdown(build_competition_readiness(_competition_evidence_runs())), media_type="text/markdown; charset=utf-8")


@router.post("/api/readiness/write")
def write_competition_readiness() -> dict:
    return write_competition_readiness_report(runs=_competition_evidence_runs())


@router.get("/api/demo_drill")
def judge_demo_drill_preview() -> dict:
    return load_judge_demo_drill_report()


@router.get("/api/demo_drill.md")
def judge_demo_drill_markdown() -> Response:
    return Response(build_judge_demo_drill_markdown(load_judge_demo_drill_report()), media_type="text/markdown; charset=utf-8")


@router.post("/api/demo_drill/run")
def run_judge_demo_drill_endpoint() -> dict:
    return run_judge_demo_drill()


@router.post("/api/demo_drill/write")
def write_judge_demo_drill_endpoint() -> dict:
    return run_judge_demo_drill()


@router.get("/api/evaluations/anomaly_calibration")
def anomaly_calibration() -> dict:
    return build_anomaly_calibration()


@router.get("/api/evaluations/adversarial_holdout")
def adversarial_holdout() -> dict:
    return evaluate_adversarial_holdout()


@router.get("/api/evaluations/anomaly_calibration.md")
def anomaly_calibration_markdown() -> Response:
    return Response(build_anomaly_calibration_markdown(), media_type="text/markdown; charset=utf-8")


@router.post("/api/evaluations/anomaly_calibration/write")
def write_anomaly_calibration() -> dict:
    return write_anomaly_calibration_report()


@router.get("/api/attack_surfaces/evidence_packs")
def attack_surface_evidence_packs() -> dict:
    return build_surface_evidence_index(_competition_evidence_runs())


@router.get("/api/attack_surfaces/evidence_packs.md")
def attack_surface_evidence_packs_markdown() -> Response:
    return Response(build_surface_evidence_index_markdown(_competition_evidence_runs()), media_type="text/markdown; charset=utf-8")


@router.post("/api/attack_surfaces/evidence_packs/write")
def write_attack_surface_evidence_packs() -> dict:
    return write_all_surface_evidence_packs(runs=_competition_evidence_runs())


@router.post("/api/attack_surfaces/briefing_sheets/write")
def write_attack_surface_briefing_sheets() -> dict:
    return write_all_surface_briefing_sheets(runs=_competition_evidence_runs())


@router.get("/api/attack_surfaces/briefing_sheets/export")
def attack_surface_briefing_sheet_exports() -> dict:
    data = load_briefing_sheet_export_report()
    if data:
        return data
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "ok": False,
        "reason": "尚未运行攻击面评测单页 PNG/PDF 导出。",
        "summary": {"png_count": 0, "pdf_count": 0, "output_dir": ""},
        "export": {"files": []},
    }


@router.get("/api/attack_surfaces/briefing_sheets/export.md")
def attack_surface_briefing_sheet_exports_markdown() -> Response:
    return Response(build_briefing_sheet_export_markdown(), media_type="text/markdown; charset=utf-8")


@router.post("/api/attack_surfaces/briefing_sheets/export")
def write_attack_surface_briefing_sheet_exports(format_: str = Query("both", alias="format")) -> dict:
    try:
        return write_briefing_sheet_exports(format_)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/api/attack_surfaces/briefing_sheets/export/files/{surface_id}.{file_format}")
def attack_surface_briefing_sheet_export_file(surface_id: str, file_format: str) -> FileResponse:
    if file_format not in {"png", "pdf"}:
        raise HTTPException(status_code=400, detail="file_format must be png or pdf")
    if not re.fullmatch(r"[A-Za-z0-9_-]+", surface_id):
        raise HTTPException(status_code=400, detail="invalid surface_id")

    file_path = SANDBOX_REPORTS_DIR / EXPORT_DIR_NAME / f"{surface_id}.{file_format}"
    if not file_path.exists() or not file_path.is_file():
        raise HTTPException(status_code=404, detail="导出文件不存在，请先运行攻击面评测单页 PNG/PDF 导出。")

    media_type = "image/png" if file_format == "png" else "application/pdf"
    return FileResponse(
        file_path,
        media_type=media_type,
        headers={
            "Content-Disposition": f'inline; filename="{file_path.name}"',
            "Cache-Control": "no-store",
        },
    )


@router.get("/api/attack_surfaces/{surface_id}/evidence_pack")
def attack_surface_evidence_pack(surface_id: str) -> dict:
    try:
        return build_surface_evidence_pack(surface_id, _competition_evidence_runs())
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"未知攻击面：{surface_id}") from exc


@router.get("/api/attack_surfaces/{surface_id}/evidence_pack.md")
def attack_surface_evidence_pack_markdown(surface_id: str) -> Response:
    try:
        return Response(build_surface_evidence_pack_markdown(surface_id, _competition_evidence_runs()), media_type="text/markdown; charset=utf-8")
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"未知攻击面：{surface_id}") from exc


@router.post("/api/attack_surfaces/{surface_id}/evidence_pack/write")
def write_attack_surface_evidence_pack(surface_id: str) -> dict:
    try:
        return write_surface_evidence_pack(surface_id, runs=_competition_evidence_runs())
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"未知攻击面：{surface_id}") from exc


@router.get("/api/attack_surfaces/{surface_id}/briefing_sheet.html")
def attack_surface_briefing_sheet(surface_id: str) -> Response:
    try:
        return Response(build_surface_briefing_sheet_html(surface_id, _competition_evidence_runs()), media_type="text/html; charset=utf-8")
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"未知攻击面：{surface_id}") from exc


@router.post("/api/attack_surfaces/{surface_id}/briefing_sheet/write")
def write_attack_surface_briefing_sheet(surface_id: str) -> dict:
    try:
        return write_surface_briefing_sheet(surface_id, runs=_competition_evidence_runs())
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"未知攻击面：{surface_id}") from exc


@router.get("/api/datasets/benign_cases")
def benign_cases_dataset(category: str | None = None) -> dict:
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "filter": {"category": category},
        "cases": get_benign_cases(category),
    }


@router.get("/api/datasets/benign_cases.md")
def benign_cases_markdown(category: str | None = None) -> Response:
    return Response(build_benign_cases_markdown(category), media_type="text/markdown; charset=utf-8")


@router.get("/api/evaluations/benign")
def benign_evaluation(category: str | None = None, guard_enabled: bool = True) -> dict:
    return evaluate_benign_cases(category, guard_enabled=guard_enabled)


@router.get("/api/evaluations/benign_workflows")
def benign_workflow_evaluation(guard_enabled: bool = True) -> dict:
    return evaluate_benign_workflows(guard_enabled=guard_enabled)


@router.get("/api/evaluations/benign_workflows.md")
def benign_workflow_markdown() -> Response:
    return Response(build_benign_workflow_markdown(), media_type="text/markdown; charset=utf-8")


@router.post("/api/evaluations/benign_workflows/write")
def write_benign_workflow_report_endpoint() -> dict:
    return write_benign_workflow_report()


@router.get("/api/evaluations/surface_conclusions")
def surface_conclusions() -> dict:
    return build_surface_conclusions(latest_runs(50))


@router.get("/api/evaluations/surface_conclusions.md")
def surface_conclusions_markdown() -> Response:
    return Response(build_surface_conclusions_markdown(latest_runs(50)), media_type="text/markdown; charset=utf-8")


@router.get("/api/evaluations/output_filter")
def output_filter_evidence() -> dict:
    return build_output_filter_evidence()


@router.get("/api/evaluations/output_filter.md")
def output_filter_markdown() -> Response:
    return Response(build_output_filter_markdown(), media_type="text/markdown; charset=utf-8")


@router.get("/api/evaluations/attack_effectiveness")
def attack_effectiveness() -> dict:
    return build_attack_effectiveness(_competition_evidence_runs())


@router.post("/api/evaluations/attack_effectiveness/run")
def run_attack_effectiveness() -> dict:
    run_result = batch_compare_scenarios()
    return {
        "run_result": run_result,
        "attack_effectiveness": build_attack_effectiveness(_competition_evidence_runs()),
    }


@router.post("/api/evaluations/gap_rerun/run")
def run_gap_rerun_evaluation() -> dict:
    return run_gap_rerun()


@router.get("/api/evaluations/policy_ablation")
def policy_ablation() -> dict:
    return build_policy_ablation()


@router.get("/api/evaluations/policy_ablation.md")
def policy_ablation_markdown() -> Response:
    return Response(build_policy_ablation_markdown(), media_type="text/markdown; charset=utf-8")


@router.post("/api/evaluations/policy_ablation/write")
def write_policy_ablation() -> dict:
    return write_policy_ablation_report()


@router.get("/api/evaluations/requirements")
def requirement_alignment() -> list[dict]:
    return build_attack_effectiveness(_competition_evidence_runs())["requirement_alignment"]


@router.post("/api/submission_package")
def submission_package() -> dict:
    raise HTTPException(status_code=410, detail="提交包生成功能已停用，请使用报告材料中心复制或下载单个材料。")


@router.post("/api/submission_package/clean")
def clean_submission_package() -> dict:
    raise HTTPException(status_code=410, detail="提交包生成功能已停用，请使用报告材料中心复制或下载单个材料。")


@router.get("/api/report")
def report() -> Response:
    return Response(
        content=json.dumps(build_report(), ensure_ascii=False),
        media_type="application/json",
        headers={"Cache-Control": "no-store"},
    )
