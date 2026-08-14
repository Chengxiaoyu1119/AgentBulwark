from __future__ import annotations

import json
import os
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ...paths import REPO_ROOT, SANDBOX_REPORTS_DIR
from ...storage.data import get_attack_surfaces, get_policies, get_policy_settings, get_scenarios, get_student_competition_attack_map
from ...storage.database import latest_scenario_run_pairs
from ..attacks.attack_chains import list_attack_chains
from ..evaluations.benign import evaluate_benign_cases
from ..evaluations.benign_workflows import evaluate_benign_workflows
from ..evaluations.calibration import build_anomaly_calibration
from ..evaluations.datasets import build_attack_case_dataset
from ..evaluations.demo_drill import load_judge_demo_drill_report
from ..governance.approvals import list_approval_reviews
from .readiness_checks import (
    _approval_review_check,
    _attack_dataset_check,
    _attack_surface_check,
    _benign_check,
    _benign_workflow_check,
    _calibration_check,
    _competition_benchmark_check,
    _demo_drill_check,
    _deployment_security_check,
    _end_to_end_benchmark_check,
    _external_agent_e2e_check,
    _next_actions,
    _runtime_governance_check,
    _student_competition_domain_check,
    _submission_materials_check,
    _supervisor_check,
)
from .roadmap import build_project_roadmap

REPORT_ROOT = SANDBOX_REPORTS_DIR


def build_competition_readiness(
    runs: list[dict[str, Any]] | None = None,
    package_snapshot: dict[str, Any] | None = None,
) -> dict[str, Any]:
    surfaces = get_attack_surfaces()
    scenarios = get_scenarios()
    runs = runs if runs is not None else latest_scenario_run_pairs([scenario["id"] for scenario in scenarios])
    policies = get_policies()
    student_profiles = get_student_competition_attack_map()
    attack_chains = list_attack_chains()
    attack_dataset = build_attack_case_dataset()
    benign = evaluate_benign_cases()
    workflows = evaluate_benign_workflows()
    calibration = build_anomaly_calibration()
    roadmap = build_project_roadmap(runs)
    approval_inventory = list_approval_reviews(limit=200)
    approvals = list_approval_reviews(limit=200, scope="demo")
    operational_approvals = list_approval_reviews(limit=200, scope="operational")
    experiment_approvals = list_approval_reviews(limit=200, scope="experiment")
    demo_drill = load_judge_demo_drill_report()
    openclaw_validation = _openclaw_validation_for_readiness()
    competition_benchmark = _competition_benchmark_for_readiness()
    external_agent_e2e = _load_report("最小外部Agent接入运行证据.json")
    end_to_end_benchmark = _load_report("HTTP-SQLite-审计完整链路性能评测.json")
    reproducibility = _load_report("独立复现一致性验收报告.json")
    eligibility = _load_report("上海信息安全参赛资格审查.json")
    submission_materials = package_snapshot or _submission_materials_for_readiness()
    deployment_security = _deployment_security_for_readiness()
    policy_settings = get_policy_settings()
    checks = [
        _attack_surface_check(surfaces, scenarios),
        _student_competition_domain_check(student_profiles, scenarios, attack_chains),
        _attack_dataset_check(attack_dataset),
        _supervisor_check(policies, scenarios, runs),
        _benign_check(benign),
        _benign_workflow_check(workflows),
        _calibration_check(calibration),
        _approval_review_check(approvals),
        _demo_drill_check(demo_drill),
        _competition_benchmark_check(competition_benchmark),
        _external_agent_e2e_check(external_agent_e2e),
        _end_to_end_benchmark_check(end_to_end_benchmark),
        _runtime_governance_check(policy_settings),
        _deployment_security_check(deployment_security),
        _submission_materials_check(submission_materials),
    ]
    total_weight = sum(item["weight"] for item in checks)
    readiness_score = round(sum(item["earned_score"] for item in checks) / total_weight * 100) if total_weight else 0
    blockers = [item for item in checks if item["status"] == "blocked"]
    warnings = [item for item in checks if item["status"] == "warning"]
    passed = [item for item in checks if item["status"] == "passed"]

    if blockers:
        overall_status = "has-p0-proof-gap"
        status_label = "有 P0 补证项"
        verdict = "项目主体已经可演示、可打包，但仍有 P0 证据项未通过，详见阻塞项。"
    elif warnings:
        overall_status = "ready-with-warning"
        status_label = "可提交但建议补强"
        verdict = "核心材料已经成型，剩余问题不影响本地演示，但会影响答辩说服力。"
    else:
        overall_status = "ready"
        status_label = "可提交"
        verdict = "核心功能、证据和演示链路均已通过本地体检。"

    next_actions = _next_actions(checks)
    return {
        "project": "智安哨：面向大模型智能体工具调用链的运行时行为防火墙与评测系统",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "overall_status": overall_status,
        "status_label": status_label,
        "verdict": verdict,
        "readiness_score": readiness_score,
        "summary": {
            "check_count": len(checks),
            "passed_count": len(passed),
            "warning_count": len(warnings),
            "blocker_count": len(blockers),
            "surface_count": len(surfaces),
            "scenario_count": len(scenarios),
            "student_profile_count": len(student_profiles),
            "student_scenario_count": sum(
                1 for scenario in scenarios if str(scenario.get("id", "")).startswith(("TEAM-", "SUBMISSION-", "CHALLENGE-", "JUDGE-", "CAMPUS-"))
            ),
            "attack_chain_count": len(attack_chains),
            "student_attack_chain_ready": any(chain.get("id") == "student-competition-portal-chain" for chain in attack_chains),
            "policy_count": len(policies),
            "benign_case_count": benign["summary"]["case_count"],
            "benign_false_positive_rate": benign["summary"]["false_positive_rate"],
            "benign_workflow_count": workflows["summary"]["workflow_count"],
            "benign_workflow_false_positive_rate": workflows["summary"]["false_positive_rate"],
            "recommended_threshold": calibration["summary"]["recommended_threshold"],
            "approval_review_count": approval_inventory["summary"]["total"],
            "pending_approval_count": approval_inventory["summary"]["pending_count"],
            "resolved_approval_count": approval_inventory["summary"]["approved_count"] + approval_inventory["summary"]["rejected_count"],
            "approval_scope_counts": approval_inventory["summary"]["scope_counts"],
            "approval_demo_evidence_count": approvals["summary"]["total"],
            "operational_pending_approval_count": operational_approvals["summary"]["pending_count"],
            "experiment_pending_approval_count": experiment_approvals["summary"]["pending_count"],
            "demo_drill_stage_count": demo_drill["summary"]["stage_count"],
            "demo_drill_review_hash_count": demo_drill["summary"]["review_hash_count"],
            "roadmap_score": roadmap["summary"]["overall_score"],
            "roadmap_p0_backlog_count": roadmap["summary"]["p0_backlog_count"],
            "competition_benchmark_case_count": competition_benchmark.get("dataset", {}).get("case_count", 0),
            "competition_benchmark_sha256": competition_benchmark.get("dataset", {}).get("sha256", ""),
            "competition_benchmark_baseline_count": len(competition_benchmark.get("baselines", [])),
            "competition_benchmark_call_count": competition_benchmark.get("performance", {}).get("call_count", 0),
            "external_agent_task_count": external_agent_e2e.get("summary", {}).get("task_count", 0),
            "end_to_end_benchmark_call_count": end_to_end_benchmark.get("performance", {}).get("call_count", 0),
            "reproducibility_trial_count": reproducibility.get("summary", {}).get("trial_count", 0),
            "reproducibility_passed_count": reproducibility.get("summary", {}).get("passed_count", 0),
            "reproducibility_stable": reproducibility.get("summary", {}).get("passed", False),
            "reproducibility_external_validation": reproducibility.get("method", {}).get("external_validation", False),
            "eligibility_status": eligibility.get("status", "未生成"),
            "prior_submission_detected": eligibility.get("prior_submission_detected", False),
            "local_award_match_found": eligibility.get("local_award_match_found", False),
            "submission_material_ready_count": submission_materials.get("ready_count", 0),
            "submission_material_required_count": submission_materials.get("required_count", 3),
            "agent_tool_allowlist_count": len(policy_settings.get("agent_tool_allowlists", {})),
            "openclaw_contract_e2e_passed": openclaw_validation.get("contract_e2e_passed", False),
            "openclaw_runtime_inspect_passed": openclaw_validation.get("runtime_inspect_passed", False),
        },
        "checks": checks,
        "blockers": [
            {
                "id": item["id"],
                "title": item["title"],
                "severity": item["severity"],
                "evidence": item["evidence"],
                "next_action": item["next_action"],
            }
            for item in blockers
        ],
        "next_actions": next_actions,
        "acceptance_commands": [
            "node scripts/agent-supervisor-cli.mjs competition-benchmark --output apps/api/sandbox/reports",
            "node scripts/agent-supervisor-cli.mjs http-e2e-benchmark --output apps/api/sandbox/reports",
            "node scripts/agent-supervisor-cli.mjs external-agent-demo --managed-server --output apps/api/sandbox/reports",
            "node scripts/agent-supervisor-cli.mjs repro-check --trials 3 --operator OPERATOR --operator-role ROLE --output apps/api/sandbox/reports",
            "python -X utf8 scripts/audit_shanghai_eligibility.py",
            "node scripts/agent-supervisor-cli.mjs readiness --write --output apps/api/sandbox/reports",
            "npm run build",
        ],
        "latest_package": submission_materials,
        "qualification_audit": {
            "status": eligibility.get("status", "未生成"),
            "prior_submission_detected": eligibility.get("prior_submission_detected", False),
            "local_award_match_found": eligibility.get("local_award_match_found", False),
            "team_attestation_required": eligibility.get("team_attestation_required", True),
            "conclusion": eligibility.get("conclusion", "先运行参赛资格审查，确认历史参赛获奖情况。"),
        },
    }


def _openclaw_validation_for_readiness() -> dict[str, Any]:
    validation_report = REPORT_ROOT / "OpenClaw源码级插件包验收报告.json"
    if validation_report.exists():
        try:
            payload = json.loads(validation_report.read_text(encoding="utf-8"))
            validation = payload.get("validation", payload)
            if validation.get("runtime_inspect_passed") is True:
                return validation
        except (OSError, json.JSONDecodeError):
            pass
    return {}


def _competition_benchmark_for_readiness() -> dict[str, Any]:
    benchmark_report = REPORT_ROOT / "200条冻结集与基线性能评测.json"
    if not benchmark_report.exists():
        return {}
    try:
        payload = json.loads(benchmark_report.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _load_report(filename: str) -> dict[str, Any]:
    path = REPORT_ROOT / filename
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _submission_materials_for_readiness() -> dict[str, Any]:
    material_dir = REPO_ROOT / "docs" / "上海信息安全" / "参赛材料草稿"
    requirements = {
        "technical_report": ("技术报告", {".docx", ".pdf"}),
        "registration_form": ("报名表", {".xlsx"}),
        "originality_declaration": ("原创性声明", {".docx", ".pdf"}),
    }
    items: dict[str, Any] = {}
    for item_id, (label, extensions) in requirements.items():
        candidates = [
            path
            for path in material_dir.glob(f"*{label}*")
            if path.is_file() and path.suffix.lower() in extensions
        ] if material_dir.exists() else []
        candidates.sort(key=lambda path: (bool(_pending_markers(path)), path.name))
        selected = candidates[0] if candidates else None
        markers = _pending_markers(selected) if selected else []
        items[item_id] = {
            "label": label,
            "path": _relative_path(selected) if selected else "",
            "exists": selected is not None,
            "ready": selected is not None and not markers,
            "pending_markers": markers,
            "candidate_count": len(candidates),
        }
    ready_count = sum(1 for item in items.values() if item["ready"])
    missing_items = [item["label"] for item in items.values() if not item["exists"]]
    pending_items = [item["label"] for item in items.values() if item["exists"] and not item["ready"]]
    return {
        "directory": _relative_path(material_dir),
        "required_count": len(requirements),
        "ready_count": ready_count,
        "submission_ready": ready_count == len(requirements),
        "missing_items": missing_items,
        "pending_items": pending_items,
        "items": items,
    }


def _pending_markers(path: Path | None) -> list[str]:
    if path is None:
        return []
    markers = ("待补个人信息", "手机号/学号待补", "待签署", "待提交", "待填写", "队伍信息待填写")
    found = {marker for marker in markers if marker in path.name}
    if path.suffix.lower() not in {".docx", ".xlsx"}:
        return sorted(found)
    try:
        with zipfile.ZipFile(path) as archive:
            total = 0
            for info in archive.infolist():
                if not info.filename.endswith(".xml"):
                    continue
                total += info.file_size
                if total > 12 * 1024 * 1024:
                    break
                text = archive.read(info).decode("utf-8", errors="ignore")
                found.update(marker for marker in markers if marker in text)
    except (OSError, zipfile.BadZipFile):
        found.add("文件不可读取")
    return sorted(found)


def _deployment_security_for_readiness() -> dict[str, Any]:
    local_env = _read_env_file(REPO_ROOT / ".env")
    example_env = _read_env_file(REPO_ROOT / ".env.example")
    auth_disabled = (local_env.get("AGENT_SUPERVISOR_AUTH_DISABLED") or "false").strip().lower() in {"1", "true", "yes", "on"}
    token_keys = (
        "AGENT_SUPERVISOR_API_TOKEN",
        "AGENT_SUPERVISOR_API_TOKEN_ADMIN",
        "AGENT_SUPERVISOR_API_TOKEN_ANALYST",
        "AGENT_SUPERVISOR_API_TOKEN_OBSERVER",
    )
    return {
        "auth_enabled": not auth_disabled,
        "api_token_configured": any(bool(local_env.get(key, "").strip()) for key in token_keys),
        "hmac_configured": bool(local_env.get("AGENT_SUPERVISOR_AUDIT_HMAC_KEY", "").strip()),
        "example_safe_default": (example_env.get("AGENT_SUPERVISOR_AUTH_DISABLED") or "false").strip().lower() == "false",
        "host": local_env.get("AGENT_SUPERVISOR_API_HOST", os.getenv("AGENT_SUPERVISOR_API_HOST", "127.0.0.1")),
        "source": ".env（仅返回是否配置，不返回密钥内容）",
    }


def _read_env_file(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    values: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def _relative_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(REPO_ROOT.resolve())).replace("\\", "/")
    except ValueError:
        return str(path.resolve())


def build_competition_readiness_markdown(data: dict[str, Any] | None = None) -> str:
    data = data or build_competition_readiness()
    summary = data["summary"]
    lines = [
        "# 赛前一键体检报告",
        "",
        f"- 总体状态：{data['status_label']}",
        f"- 就绪分：{data['readiness_score']}%",
        f"- 结论：{data['verdict']}",
        f"- 通过/警告/阻塞：{summary['passed_count']} / {summary['warning_count']} / {summary['blocker_count']}",
        f"- 攻击面/脚本：{summary['surface_count']} / {summary['scenario_count']}",
        f"- 正常业务任务误报率：{summary['benign_false_positive_rate']}%",
        f"- 连续流程误报率：{summary['benign_workflow_false_positive_rate']}%",
        f"- 人工复核闭环：{summary['approval_review_count']} 条复核单，待处理 {summary['pending_approval_count']}，已处理 {summary['resolved_approval_count']}",
        f"- 答辩一键演示：{summary['demo_drill_stage_count']} 步，复核 hash {summary['demo_drill_review_hash_count']} 个",
        f"- 冻结评测集：{summary['competition_benchmark_case_count']} 条，四组基线 {summary['competition_benchmark_baseline_count']}/4，判定 {summary['competition_benchmark_call_count']} 次",
        f"- 通用 Agent 端到端任务：{summary['external_agent_task_count']} 条",
        f"- 完整链路性能请求：{summary['end_to_end_benchmark_call_count']} 条",
        f"- 正式提交材料：{summary['submission_material_ready_count']} / {summary['submission_material_required_count']} 就绪",
        f"- 可选 OpenClaw 兼容：契约 {'通过' if summary['openclaw_contract_e2e_passed'] else '未验证'}，runtime inspect {'通过' if summary['openclaw_runtime_inspect_passed'] else '未验证'}",
        "",
        "## 检查项",
        "",
        "| 检查项 | 状态 | 权重 | 证据 | 下一步 |",
        "|---|---|---:|---|---|",
    ]
    for item in data["checks"]:
        lines.append(
            "| {title} | {status} | {weight} | {evidence} | {next_action} |".format(
                title=item["title"],
                status=item["status_label"],
                weight=item["weight"],
                evidence=item["evidence"],
                next_action=item["next_action"],
            )
        )

    if data["blockers"]:
        lines.extend(["", "## P0 补证项", ""])
        for item in data["blockers"]:
            lines.append(f"- {item['title']}：{item['next_action']}")

    lines.extend(["", "## 建议命令", ""])
    lines.extend(f"```powershell\n{command}\n```" for command in data["acceptance_commands"])
    return "\n".join(lines)


def write_competition_readiness_report(
    output_root: str | Path | None = None,
    package_snapshot: dict[str, Any] | None = None,
    runs: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    root = Path(output_root) if output_root else REPORT_ROOT
    root.mkdir(parents=True, exist_ok=True)
    data = build_competition_readiness(runs=runs, package_snapshot=package_snapshot)
    json_path = root / "赛前一键体检报告.json"
    markdown_path = root / "赛前一键体检报告.md"
    json_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    markdown_path.write_text(build_competition_readiness_markdown(data), encoding="utf-8")
    return {
        "generated_at": data["generated_at"],
        "json_path": str(json_path.resolve()),
        "markdown_path": str(markdown_path.resolve()),
        "summary": data["summary"],
        "readiness_score": data["readiness_score"],
        "overall_status": data["overall_status"],
        "blockers": data["blockers"],
        "readiness": data,
    }
