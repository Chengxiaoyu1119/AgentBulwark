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
from ..evaluations.benign_workflows import load_benign_workflow_report
from ..evaluations.calibration import build_anomaly_calibration
from ..evaluations.datasets import build_attack_case_dataset
from ..evaluations.demo_drill import load_judge_demo_drill_report
from ..governance.approvals import list_approval_reviews
from ..runtime.runtime_evaluation import load_real_model_evaluation_report
from .readiness_checks import (
    _approval_review_check,
    _attack_dataset_check,
    _attack_surface_check,
    _benign_check,
    _benign_workflow_check,
    _calibration_check,
    _dependency_security_check,
    _deployment_security_check,
    _end_to_end_benchmark_check,
    _external_agent_e2e_check,
    _gateway_boundary_check,
    _gateway_causal_control_check,
    _next_actions,
    _real_gateway_agent_evidence_check,
    _real_model_evidence_check,
    _resource_governance_check,
    _runtime_governance_check,
    _submission_materials_check,
    _supervisor_check,
)
from .roadmap import build_project_roadmap

REPORT_ROOT = SANDBOX_REPORTS_DIR


def _completion_claim_allowed(
    blockers: list[dict[str, Any]],
    warnings: list[dict[str, Any]],
) -> bool:
    """Allow a whole-project completion claim only after every check passes."""

    return not blockers and not warnings


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
    workflows = load_benign_workflow_report()
    calibration = build_anomaly_calibration()
    roadmap = build_project_roadmap(runs)
    approval_inventory = list_approval_reviews(limit=200)
    approvals = list_approval_reviews(limit=200, scope="demo")
    operational_approvals = list_approval_reviews(limit=200, scope="operational")
    experiment_approvals = list_approval_reviews(limit=200, scope="experiment")
    demo_drill = load_judge_demo_drill_report()
    openclaw_validation = _openclaw_validation_for_readiness()
    competition_benchmark = _competition_benchmark_for_readiness()
    real_model_evaluation = load_real_model_evaluation_report()
    external_agent_e2e = _load_report("最小外部Agent接入运行证据.json")
    end_to_end_benchmark = _load_report("HTTP-SQLite-审计完整链路性能评测.json")
    reproducibility = _load_report("独立复现一致性验收报告.json")
    dependency_security = _load_report("dependency-security-audit.json")
    eligibility = _load_report("上海信息安全参赛资格审查.json")
    submission_materials = package_snapshot or _submission_materials_for_readiness()
    deployment_security = _deployment_security_for_readiness()
    policy_settings = get_policy_settings()
    gateway_boundary = _gateway_boundary_check()
    resource_governance = _resource_governance_check()
    checks = [
        _attack_surface_check(surfaces, scenarios),
        gateway_boundary,
        _real_gateway_agent_evidence_check(),
        _gateway_causal_control_check(),
        _attack_dataset_check(attack_dataset),
        _supervisor_check(policies, scenarios, runs),
        _benign_check(benign),
        _benign_workflow_check(workflows),
        _calibration_check(calibration),
        _approval_review_check(operational_approvals),
        _real_model_evidence_check(real_model_evaluation),
        _external_agent_e2e_check(external_agent_e2e),
        _end_to_end_benchmark_check(end_to_end_benchmark),
        _runtime_governance_check(policy_settings),
        resource_governance,
        _deployment_security_check(deployment_security),
        _dependency_security_check(dependency_security),
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
        verdict = "核心代码链可以运行和验证，但当前仍有 P0 证据或提交材料缺口，不能按最终参赛作品宣称完成。"
    elif warnings:
        overall_status = "ready-with-warning"
        status_label = "可提交但建议补强"
        verdict = "核心材料已经成型，剩余问题不影响本地演示，但会影响答辩说服力。"
    else:
        overall_status = "ready"
        status_label = "可提交"
        verdict = "核心功能、证据和演示链路均已通过本地体检。"

    next_actions = _next_actions(checks)
    # ``overall_status`` is kept for compatibility with the competition
    # material API.  It is intentionally not the production readiness
    # verdict: historical fixture/approval checks can produce warnings that
    # do not describe the live LLM gateway, while a deployment can be unsafe
    # even when the local gateway harness is green.  Expose a separate,
    # fail-closed claim gate so the console and evidence writers cannot turn a
    # warning-heavy report into an accidental "完成" statement.
    # A production claim is about the live gateway trust boundary, not about
    # historical evaluation or competition paperwork.  The previous
    # implementation mixed every P0 checklist blocker into this boolean, so a
    # missing baseline comparison could make an otherwise closed gateway look
    # unavailable (or, conversely, a hand-picked subset could omit a new
    # gateway check).  Derive the claim from the same domain partition exposed
    # to the console and include every check marked as required for that
    # domain.
    readiness_domains = _readiness_domains(checks, gateway_boundary)
    gateway_check_ids = {
        str(item.get("id"))
        for item in checks
        if str(item.get("id")) in set(readiness_domains.get("gateway", {}).get("check_ids", []))
    }
    production_gaps = [
        item
        for item in checks
        if str(item.get("id")) in gateway_check_ids and item.get("status") != "passed"
    ]
    production_ready = bool(gateway_check_ids) and not production_gaps
    completion_claim_allowed = _completion_claim_allowed(blockers, warnings)
    production_verdict = (
        "生产网关主线已通过当前配置与实时接入证据检查；模型行为评测与因果对照另列为支持证据。"
        if production_ready
        else "核心网关链可以运行，但仍有生产配置或实时接入证据缺口；当前不能宣称项目功能全部完成。"
    )
    return {
        "project": "智安哨：面向 LLM Agent、OpenAI 兼容 API 与 MCP 的运行时安全网关",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "overall_status": overall_status,
        "status_label": status_label,
        "verdict": verdict,
        "production_ready": production_ready,
        "production_claim_allowed": production_ready,
        "completion_claim_allowed": completion_claim_allowed,
        "gateway_ready": readiness_domains["gateway"]["status"] == "passed",
        "evaluation_ready": readiness_domains["evaluation"]["status"] == "passed",
        "production_verdict": production_verdict,
        # The old report score intentionally remains for compatibility with
        # competition material APIs.  Operators should use these domain states
        # to distinguish the live gateway from model research and submission
        # paperwork; a large historical evaluation score must not look like a
        # production security claim.
        "readiness_domains": readiness_domains,
        "production_gaps": [
            {
                "id": item["id"],
                "title": item["title"],
                "status": item["status"],
                "severity": item["severity"],
                "evidence": item["evidence"],
                "next_action": item["next_action"],
            }
            for item in production_gaps
        ],
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
            "real_model_case_count": (real_model_evaluation or {}).get("summary", {}).get("case_count", 0),
            "real_model_strict_ready": (real_model_evaluation or {}).get("summary", {}).get("strict_real_api_ready", False),
            "real_model_evidence_verdict": (real_model_evaluation or {}).get("summary", {}).get("evidence_verdict", "missing"),
            "real_model_freshness_current": (real_model_evaluation or {}).get("freshness_verification", {}).get("current", False),
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
            "agent_api_allowlist_count": len(policy_settings.get("agent_api_allowlists", {})),
            "agent_model_allowlist_count": len(policy_settings.get("agent_model_allowlists", {})),
            "agent_context_allowlist_count": len(policy_settings.get("agent_context_allowlists", {})),
            "agent_resource_governance": resource_governance.get("details", {}),
            "dependency_audit_status": dependency_security.get("status", "missing"),
            "dependency_audit_high_count": dependency_security.get("projects", [{}])[0].get("vulnerability_counts", {}).get("high", 0)
            if isinstance(dependency_security.get("projects"), list) and dependency_security.get("projects")
            else 0,
            "openclaw_contract_e2e_passed": openclaw_validation.get("contract_e2e_passed", False),
            "openclaw_runtime_inspect_passed": openclaw_validation.get("runtime_inspect_passed", False),
            "gateway_probe_passed": gateway_boundary.get("details", {}).get("gateway_probe_passed", False),
            "gateway_probe_endpoint": gateway_boundary.get("details", {}).get("gateway_probe_endpoint", ""),
            "gateway_agent_run_passed": gateway_boundary.get("details", {}).get("gateway_agent_run_passed", False),
            "gateway_agent_run_endpoint": gateway_boundary.get("details", {}).get("gateway_agent_run_endpoint", ""),
            "mcp_probe_passed": gateway_boundary.get("details", {}).get("mcp_probe_passed", False),
            "mcp_probe_endpoint": gateway_boundary.get("details", {}).get("mcp_probe_endpoint", ""),
            "mcp_operator_evidence_requested": gateway_boundary.get("details", {}).get(
                "mcp_operator_evidence_requested", False
            ),
            "mcp_operator_evidence_passed": gateway_boundary.get("details", {}).get(
                "mcp_operator_evidence_passed"
            ),
            "gateway_boundary_evidence_passed": gateway_boundary.get("details", {}).get("boundary_evidence_passed", False),
            "gateway_causal_control_passed": next(
                (item["status"] == "passed" for item in checks if item["id"] == "gateway-causal-control"),
                False,
            ),
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
            "node scripts/agent-supervisor-cli.mjs gateway-agent-run --input=apps/api/sandbox/examples/gateway-agent-cases.json --output apps/api/sandbox/reports",
            "node scripts/agent-supervisor-cli.mjs real-model-eval --output apps/api/sandbox/reports",
            "node scripts/agent-supervisor-cli.mjs http-e2e-benchmark --output apps/api/sandbox/reports",
            "node scripts/agent-supervisor-cli.mjs external-agent-demo --managed-server --output apps/api/sandbox/reports",
            "python -m pytest apps/api/tests -q",
            "npm run verify",
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


def _readiness_domains(
    checks: list[dict[str, Any]],
    gateway_boundary: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    """Partition the legacy checklist into product-facing state domains.

    The project is an LLM Agent/API gateway.  Frozen datasets, model behavior
    studies and submission material are supporting evidence, not interchangeable
    with a live gateway boundary.  Keeping the partition in the returned
    contract lets the console show the useful answer without deleting the
    historical checks that existing competition exports consume.
    """

    groups: dict[str, tuple[str, set[str]]] = {
        "gateway": (
            "生产网关",
            {
                "llm-gateway-execution-boundary",
                "real-gateway-agent-evidence",
                "agent-tool-least-privilege",
                "agent-resource-governance",
                "deployment-auth-and-hmac",
            },
        ),
        "evaluation": (
            "模型与对抗评测",
            {
                "gateway-causal-control",
                "real-model-agent-evidence",
                "generic-agent-runtime-e2e",
                "http-sqlite-audit-benchmark",
                "benign-single-step",
                "benign-workflows",
                "anomaly-calibration",
                "attack-sample-dataset",
                "supervisor-policy-runtime",
            },
        ),
        "competition": (
            "赛事材料与历史能力",
            {"attack-surface-coverage", "human-approval-loop", "formal-submission-materials"},
        ),
        "supply_chain": (
            "依赖与供应链",
            {"dependency-security-audit"},
        ),
    }
    by_id = {str(item.get("id")): item for item in checks}
    domains: dict[str, dict[str, Any]] = {}
    for domain_id, (label, check_ids) in groups.items():
        selected = [by_id[item_id] for item_id in check_ids if item_id in by_id]
        statuses = [str(item.get("status") or "warning") for item in selected]
        status = (
            "blocked"
            if any(value == "blocked" for value in statuses)
            else "warning"
            if any(value == "warning" for value in statuses)
            else "passed"
            if selected
            else "unknown"
        )
        domains[domain_id] = {
            "label": label,
            "status": status,
            "required_for_gateway_claim": domain_id == "gateway",
            "check_count": len(selected),
            "passed_count": sum(value == "passed" for value in statuses),
            "warning_count": sum(value == "warning" for value in statuses),
            "blocked_count": sum(value == "blocked" for value in statuses),
            "check_ids": sorted(check_ids),
            "gaps": [
                {
                    "id": item.get("id", ""),
                    "title": item.get("title", ""),
                    "status": item.get("status", ""),
                    "next_action": item.get("next_action", ""),
                }
                for item in selected
                if item.get("status") != "passed"
            ],
        }

    gateway_details = gateway_boundary.get("details", {}) if isinstance(gateway_boundary, dict) else {}
    mcp_configured = bool(gateway_details.get("gateway_enabled"))
    mcp_probe_passed = bool(gateway_details.get("mcp_probe_passed"))
    mcp_operator_evidence_requested = bool(gateway_details.get("mcp_operator_evidence_requested"))
    mcp_operator_evidence_passed = gateway_details.get("mcp_operator_evidence_passed")
    domains["mcp_adapter"] = {
        "label": "MCP 可选适配器",
        "status": "passed" if mcp_configured and mcp_probe_passed else "warning" if mcp_configured else "not-configured",
        "status_label": "已验证" if mcp_configured and mcp_probe_passed else "已配置待验证" if mcp_configured else "未启用（可选）",
        "required_for_gateway_claim": False,
        "configured": mcp_configured,
        "probe_passed": mcp_probe_passed,
        "operator_evidence_requested": mcp_operator_evidence_requested,
        "operator_evidence_passed": mcp_operator_evidence_passed,
        "next_action": (
            "保持 MCP 上游命令、工具目录和回执探针绑定当前代码。"
            if mcp_configured and mcp_probe_passed
            else "配置 MCP 上游后运行 mcp-probe；未使用 MCP 时无需为主线就绪额外补齐。"
            if not mcp_configured
            else "运行 mcp-probe 补齐 initialize、tools/list、tools/call、operator 工具/上下文证据和审计回执证据。"
        ),
    }
    return domains


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
    # Deployment environments commonly inject secrets and flags through the
    # process environment (Docker/Kubernetes/CI) instead of writing them to a
    # repository `.env` file.  Readiness must use the same precedence as the
    # runtime loader: an explicitly present environment variable wins over the
    # file, while a missing variable falls back to the local file.
    effective_env = dict(local_env)
    for name in {
        "AGENT_SUPERVISOR_AUTH_DISABLED",
        "AGENT_SUPERVISOR_API_TOKEN",
        "AGENT_SUPERVISOR_API_TOKEN_ADMIN",
        "AGENT_SUPERVISOR_API_TOKEN_ANALYST",
        "AGENT_SUPERVISOR_API_TOKEN_OBSERVER",
        "AGENT_SUPERVISOR_AGENT_TOKENS_JSON",
        "AGENT_SUPERVISOR_AUDIT_HMAC_KEY",
        "AGENT_SUPERVISOR_API_HOST",
    }:
        if name in os.environ:
            effective_env[name] = os.environ[name]
    auth_disabled = (effective_env.get("AGENT_SUPERVISOR_AUTH_DISABLED") or "false").strip().lower() in {"1", "true", "yes", "on"}
    token_keys = (
        "AGENT_SUPERVISOR_API_TOKEN",
        "AGENT_SUPERVISOR_API_TOKEN_ADMIN",
        "AGENT_SUPERVISOR_API_TOKEN_ANALYST",
        "AGENT_SUPERVISOR_API_TOKEN_OBSERVER",
    )
    agent_tokens_configured = _agent_tokens_configured(effective_env.get("AGENT_SUPERVISOR_AGENT_TOKENS_JSON", ""))
    return {
        "auth_enabled": not auth_disabled,
        "api_token_configured": any(bool(effective_env.get(key, "").strip()) for key in token_keys)
        or agent_tokens_configured,
        "agent_tokens_configured": agent_tokens_configured,
        "hmac_configured": bool(effective_env.get("AGENT_SUPERVISOR_AUDIT_HMAC_KEY", "").strip()),
        "example_safe_default": (example_env.get("AGENT_SUPERVISOR_AUTH_DISABLED") or "false").strip().lower() == "false",
        "host": effective_env.get("AGENT_SUPERVISOR_API_HOST", "127.0.0.1"),
        "source": ".env + process environment（仅返回是否配置，不返回密钥内容）",
    }


def _agent_tokens_configured(raw_value: str) -> bool:
    """Match the runtime credential contract without exposing token values.

    Production deployments may intentionally configure only
    ``AGENT_SUPERVISOR_AGENT_TOKENS_JSON``.  Readiness used to inspect only the
    role-token variables and therefore reported such a deployment as
    unauthenticated even though ``auth.py`` would accept the bound Agent token.
    """

    try:
        payload = json.loads(str(raw_value or ""))
    except (TypeError, ValueError, json.JSONDecodeError):
        return False
    if not isinstance(payload, dict):
        return False
    return any(isinstance(token, str) and token.strip() for token in payload.values())


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
        "# AI Agent 安全网关就绪检查",
        "",
        f"- 总体状态：{data['status_label']}",
        f"- 就绪分：{data['readiness_score']}%",
        f"- 结论：{data['verdict']}",
        f"- 生产主线就绪：{'是' if data.get('production_ready') else '否'}",
        f"- 完成声明允许：{'是' if data.get('completion_claim_allowed') else '否'}",
        f"- 生产主线结论：{data.get('production_verdict', '未生成')}",
        f"- 通过/警告/阻塞：{summary['passed_count']} / {summary['warning_count']} / {summary['blocker_count']}",
        f"- LLM Agent 攻击面/样本：{summary['surface_count']} / {summary['scenario_count']}",
        f"- 正常业务任务误报率：{summary['benign_false_positive_rate']}%",
        f"- 连续流程误报率：{summary['benign_workflow_false_positive_rate']}%",
        f"- 人工复核闭环：{summary['approval_review_count']} 条复核单，待处理 {summary['pending_approval_count']}，已处理 {summary['resolved_approval_count']}",
        f"- 真实模型证据：{summary['real_model_case_count']} 条，严格就绪 {'是' if summary['real_model_strict_ready'] else '否'}，状态 {summary['real_model_evidence_verdict']}",
        f"- OpenAI 网关契约探针：{'通过' if summary.get('gateway_probe_passed') else '缺失或失败'}",
        f"- 通用 Agent 端到端任务：{summary['external_agent_task_count']} 条",
        f"- 完整链路性能请求：{summary['end_to_end_benchmark_call_count']} 条",
        f"- 历史赛事/fixture 材料：{summary['submission_material_ready_count']} / {summary['submission_material_required_count']}（不计入运行时主线）",
        "",
        "## 产品状态分域",
        "",
        "| 分域 | 状态 | 通过/警告/阻塞 | 说明 |",
        "|---|---|---:|---|",
    ]
    for domain_id, domain in data.get("readiness_domains", {}).items():
        status_label = domain.get("status_label") or {
            "passed": "通过",
            "warning": "需补强",
            "blocked": "阻塞",
            "not-configured": "未启用（可选）",
        }.get(str(domain.get("status")), "未知")
        counts = (
            f"{domain.get('passed_count', 0)} / {domain.get('warning_count', 0)} / "
            f"{domain.get('blocked_count', 0)}"
        )
        note = (
            "MCP 未启用不阻塞 LLM API 主线。"
            if domain_id == "mcp_adapter" and domain.get("status") == "not-configured"
            else "生产主线状态以本分域为准。"
            if domain_id == "gateway"
            else "支持证据，不等同于 Provider 已被网关保护。"
        )
        lines.append(f"| {domain.get('label', domain_id)} | {status_label} | {counts} | {note} |")

    lines.extend([
        "",
        "## 检查项",
        "",
        "| 检查项 | 状态 | 权重 | 证据 | 下一步 |",
        "|---|---|---:|---|---|",
    ])
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
        lines.extend(["", "## 必须补齐的运行时证据", ""])
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
    json_path = root / "AI Agent安全网关就绪检查.json"
    markdown_path = root / "AI Agent安全网关就绪检查.md"
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
