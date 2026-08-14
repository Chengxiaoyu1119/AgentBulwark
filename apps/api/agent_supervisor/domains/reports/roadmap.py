from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ...adapters.integrations.openclaw_adapter import build_openclaw_plugin_package_summary
from ...paths import REPO_ROOT, SANDBOX_REPORTS_DIR
from ...storage.data import get_attack_surfaces, get_scenarios
from ..evaluations.assessment import build_attack_effectiveness, build_requirement_alignment
from ..evaluations.benign_workflows import evaluate_benign_workflows
from ..evaluations.calibration import build_anomaly_calibration
from .briefing_export import load_briefing_sheet_export_report
from .surface_pack import build_surface_evidence_index

REPORT_ROOT = SANDBOX_REPORTS_DIR


def build_project_roadmap(runs: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    runs = runs or []
    surfaces = get_attack_surfaces()
    scenarios = get_scenarios()
    surface_index = build_surface_evidence_index(runs)
    effectiveness = build_attack_effectiveness(runs)
    calibration = build_anomaly_calibration()
    openclaw_plugin = build_openclaw_plugin_package_summary()
    openclaw_validation = _load_openclaw_validation()
    competition_benchmark = _load_competition_benchmark()
    real_model_evaluation = _load_real_model_evaluation()
    briefing_export = load_briefing_sheet_export_report()
    local_launch = _local_launch_status()
    engineering = _engineering_status()
    benign_workflows = evaluate_benign_workflows()
    requirements = build_requirement_alignment(effectiveness["cases"])
    dimensions = _maturity_dimensions(
        surface_index,
        effectiveness,
        requirements,
        runs,
        calibration,
        openclaw_plugin,
        openclaw_validation,
        competition_benchmark,
        real_model_evaluation,
        briefing_export,
        benign_workflows,
        local_launch,
        engineering,
    )
    overall_score = round(sum(item["score"] for item in dimensions) / len(dimensions)) if dimensions else 0
    completed = [item for item in dimensions if item["status"] == "已完成"]
    partial = [item for item in dimensions if item["status"] == "需完善"]
    weak = [item for item in dimensions if item["status"] == "高优先级缺口"]
    backlog = _feature_backlog(
        surface_index,
        effectiveness,
        requirements,
        calibration,
        openclaw_plugin,
        openclaw_validation,
        competition_benchmark,
        real_model_evaluation,
        briefing_export,
        local_launch,
    )
    p0 = [item for item in backlog if item["priority"] == "P0" and item["status"] != "已完成"]
    verdict = "方向正确，已具备可复现实验、行为监督、证据包和答辩材料闭环"
    if weak:
        verdict = "方向基本正确，但存在会影响真实性或答辩说服力的高优先级缺口"
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "direction": {
            "verdict": verdict,
            "score": overall_score,
            "reason": "项目已经覆盖方向目标的攻击场景、对抗样本、智能体脚本、监督器、审计、告警和提交材料；当前重点是保持真实接入、可部署复现和跨模型实测闭环。",
            "competition_fit": _competition_fit(requirements),
        },
        "summary": {
            "overall_score": overall_score,
            "dimension_count": len(dimensions),
            "completed_count": len(completed),
            "partial_count": len(partial),
            "high_priority_gap_count": len(weak),
            "p0_backlog_count": len(p0),
            "surface_count": len(surfaces),
            "scenario_count": len(scenarios),
            "run_count": len(runs),
            "evidence_gap_count": surface_index["summary"]["gap_count"],
        },
        "dimensions": dimensions,
        "feature_backlog": backlog,
        "next_sprint": _next_sprint(backlog),
        "risk_register": _risk_register(backlog, effectiveness),
    }


def _load_openclaw_validation() -> dict[str, Any] | None:
    path = REPORT_ROOT / "OpenClaw源码级插件包验收报告.json"
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    validation = data.get("validation") if isinstance(data.get("validation"), dict) else data
    return validation if isinstance(validation, dict) else None


def _load_competition_benchmark() -> dict[str, Any] | None:
    path = REPORT_ROOT / "200条冻结集与基线性能评测.json"
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _local_launch_status() -> dict[str, bool]:
    root = REPO_ROOT
    scripts_dir = root / "scripts"
    package_json = root / "package.json"
    script_files_ready = all(
        path.exists()
        for path in [
            scripts_dir / "启动智安哨.ps1",
            scripts_dir / "启动智安哨.cmd",
            scripts_dir / "start-www-dev.mjs",
        ]
    )
    package_scripts_ready = False
    if package_json.exists():
        try:
            package_data = json.loads(package_json.read_text(encoding="utf-8"))
            scripts = package_data.get("scripts", {})
            package_scripts_ready = all(key in scripts for key in ["api:dev", "console:dev", "console:build"])
        except (OSError, json.JSONDecodeError):
            package_scripts_ready = False
    return {
        "script_files_ready": script_files_ready,
        "package_scripts_ready": package_scripts_ready,
        "one_command_ready": script_files_ready and package_scripts_ready,
    }


def _engineering_status() -> dict[str, Any]:
    root = REPO_ROOT
    package_json = root / "package.json"
    console_package_json = root / "apps" / "console" / "package.json"
    api_tests_dir = root / "apps" / "api" / "tests"
    console_src_dir = root / "apps" / "console" / "src"

    root_scripts: dict[str, Any] = {}
    console_scripts: dict[str, Any] = {}
    for path, target in [(package_json, root_scripts), (console_package_json, console_scripts)]:
        if not path.exists():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        scripts = data.get("scripts", {})
        if isinstance(scripts, dict):
            target.update(scripts)

    required_root_scripts = {
        "console:lint:strict": "前端严格 lint",
        "ui:audit": "UI 治理审计",
        "console:test": "前端测试",
        "api:check": "API 编译检查",
        "api:test": "API 单元测试",
        "build": "生产构建",
        "verify": "总体验证命令",
    }
    required_console_scripts = {
        "lint:strict": "控制台严格 lint",
        "ui:audit": "控制台 UI 审计",
        "test": "控制台测试",
        "build": "控制台构建",
    }
    required_files = {
        root / "scripts" / "frontend-governance-check.mjs": "UI 审计脚本",
        console_src_dir / "api.test.ts": "接口测试",
        console_src_dir / "pages" / "ReportPanel.test.tsx": "报告页测试",
        console_src_dir / "pages" / "SettingsPanel.test.tsx": "设置页测试",
        api_tests_dir / "test_supervisor.py": "监督器测试",
        api_tests_dir / "test_openai_proxy.py": "模型代理鉴权测试",
        api_tests_dir / "test_dual_model_jailbreak.py": "双模型越狱测试",
    }

    checks: list[dict[str, Any]] = []
    checks.extend(
        {"name": label, "ok": key in root_scripts, "kind": "root_script"}
        for key, label in required_root_scripts.items()
    )
    checks.extend(
        {"name": label, "ok": key in console_scripts, "kind": "console_script"}
        for key, label in required_console_scripts.items()
    )
    checks.extend({"name": label, "ok": path.exists(), "kind": "file"} for path, label in required_files.items())
    passed = sum(1 for item in checks if item["ok"])
    score = round(passed / max(1, len(checks)) * 100)
    return {
        "score": score,
        "passed": passed,
        "total": len(checks),
        "checks": checks,
        "complete": score >= 90,
    }


def _load_real_model_evaluation() -> dict[str, Any] | None:
    path = REPORT_ROOT / "真实模型工具调用盲测报告.json"
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data.get("summary"), dict) else None


def build_project_roadmap_markdown(runs: list[dict[str, Any]] | None = None) -> str:
    roadmap = build_project_roadmap(runs)
    lines = [
        "# 项目成熟度与缺口路线图",
        "",
        f"- 方向判断：{roadmap['direction']['verdict']}",
        f"- 综合成熟度：{roadmap['summary']['overall_score']}%",
        f"- 高优先级缺口：{roadmap['summary']['high_priority_gap_count']} 项",
        f"- P0 待办：{roadmap['summary']['p0_backlog_count']} 项",
        "",
        "## 成熟度维度",
        "",
        "| 维度 | 状态 | 分数 | 当前证据 | 下一步 |",
        "|---|---|---:|---|---|",
    ]
    for item in roadmap["dimensions"]:
        lines.append(
            f"| {item['name']} | {item['status']} | {item['score']} | {item['evidence']} | {'；'.join(item['next_actions']) or '保持'} |"
        )
    lines.extend(["", "## 功能缺口 Backlog", "", "| 优先级 | 功能 | 为什么要做 | 验收标准 |", "|---|---|---|---|"])
    for item in roadmap["feature_backlog"]:
        lines.append(f"| {item['priority']} | {item['title']} | {item['why']} | {item['acceptance']} |")
    lines.extend(["", "## 下一轮建议", ""])
    for item in roadmap["next_sprint"]:
        lines.append(f"- **{item['title']}**：{item['acceptance']}")
    lines.extend(["", "## 风险登记", "", "| 风险 | 影响 | 缓解方式 |", "|---|---|---|"])
    for item in roadmap["risk_register"]:
        lines.append(f"| {item['risk']} | {item['impact']} | {item['mitigation']} |")
    return "\n".join(lines)


def write_project_roadmap(output_root: str | Path | None = None, runs: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    root = Path(output_root) if output_root else REPORT_ROOT
    root.mkdir(parents=True, exist_ok=True)
    data = build_project_roadmap(runs)
    json_path = root / "项目成熟度与缺口路线图.json"
    markdown_path = root / "项目成熟度与缺口路线图.md"
    json_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    markdown_path.write_text(build_project_roadmap_markdown(runs), encoding="utf-8")
    return {
        "generated_at": data["generated_at"],
        "json_path": str(json_path.resolve()),
        "markdown_path": str(markdown_path.resolve()),
        "summary": data["summary"],
    }


def _maturity_dimensions(
    surface_index: dict[str, Any],
    effectiveness: dict[str, Any],
    requirements: list[dict[str, Any]],
    runs: list[dict[str, Any]],
    calibration: dict[str, Any],
    openclaw_plugin: dict[str, Any],
    openclaw_validation: dict[str, Any] | None,
    competition_benchmark: dict[str, Any] | None,
    real_model_evaluation: dict[str, Any] | None,
    briefing_export: dict[str, Any] | None,
    benign_workflows: dict[str, Any],
    local_launch: dict[str, bool],
    engineering: dict[str, Any],
) -> list[dict[str, Any]]:
    summary = surface_index["summary"]
    effectiveness_summary = effectiveness["summary"]
    tool_surfaces = {tool for scenario in get_scenarios() for tool in [call["tool"] for call in scenario["tool_calls"]]}
    openclaw_static_validated = bool(
        openclaw_validation
        and openclaw_validation.get("static_passed")
        and openclaw_validation.get("files_passed")
        and openclaw_validation.get("node_syntax_passed")
        and openclaw_validation.get("contract_e2e_passed")
    )
    openclaw_runtime_validated = bool(openclaw_validation and openclaw_validation.get("runtime_inspect_passed"))
    benchmark_ready = _competition_benchmark_ready(competition_benchmark)
    benchmark_dataset = competition_benchmark.get("dataset", {}) if competition_benchmark else {}
    benchmark_performance = competition_benchmark.get("performance", {}) if competition_benchmark else {}
    real_model_summary = real_model_evaluation.get("summary", {}) if real_model_evaluation else {}
    real_model_case_count = int(real_model_summary.get("case_count") or 0)
    real_api_case_count = int(real_model_summary.get("real_api_case_count") or 0)
    model_tool_call_success_count = int(real_model_summary.get("model_tool_call_success_count") or 0)
    real_model_strict_ready = bool(real_model_summary.get("strict_real_api_ready"))
    briefing_export_summary = briefing_export.get("summary", {}) if briefing_export else {}
    briefing_png_count = int(briefing_export_summary.get("png_count") or 0)
    briefing_pdf_count = int(briefing_export_summary.get("pdf_count") or 0)
    briefing_export_done = bool(briefing_export and briefing_export.get("ok") and (briefing_png_count or briefing_pdf_count))
    workflow_fp_rate = benign_workflows["summary"]["false_positive_rate"]
    workflow_match_rate = benign_workflows["summary"]["expected_match_rate"]
    deployment_score = 92 if local_launch["one_command_ready"] else 62
    deployment_evidence = (
        "已有 Windows 一键启动脚本和 npm 本地运行脚本，适合本地开发、宝塔部署和答辩复现。"
        if local_launch["one_command_ready"]
        else "已有 npm、CLI、API 和干净提交包流程。"
    )
    return [
        _dimension(
            "研究方向匹配",
            95 if all(item["status"] in {"满足", "基本满足"} for item in requirements[:3]) else 80,
            "已覆盖大模型/智能体安全研究，核心成果围绕红队样本、工具调用监督和防御策略。",
            ["继续把叙事聚焦在真实智能体工具调用安全，而不是泛泛数据安全平台。"],
        ),
        _dimension(
            "攻击面与样本覆盖",
            100 if summary["surface_count"] >= 7 and summary["scenario_count"] >= 17 else 75,
            f"{summary['surface_count']} 类攻击面、{summary['scenario_count']} 个脚本、{summary['sample_count']} 个样本。",
            ["保持 7 类攻击面闭环，新增样本时优先补真实比赛任务上下文。"],
        ),
        _dimension(
            "行为监督闭环",
            min(100, effectiveness_summary["defense_effective_rate"]),
            f"有防护控制率 {effectiveness_summary['defense_effective_rate']}%，证据完整率 {effectiveness_summary['evidence_complete_rate']}%。",
            ["保持每个固定脚本最新一组无防护/有防护对照，避免高频外部事件挤出竞赛证据。"]
            if effectiveness_summary["evidence_complete_rate"] >= 90
            else ["运行一键缺口补证，补齐每个固定脚本的无防护/有防护对照。"],
        ),
        _dimension(
            "比赛工具与受控实验环境真实性",
            95 if {"mail.send", "file.read", "file.write", "api.call", "code.run"}.issubset(tool_surfaces) and workflow_fp_rate == 0 else 78,
            f"当前攻击脚本工具覆盖：{', '.join(sorted(tool_surfaces))}；连续正常业务任务流程 {benign_workflows['summary']['workflow_count']} 条、{benign_workflows['summary']['step_count']} 个步骤，误报率 {workflow_fp_rate}%，期望匹配率 {workflow_match_rate}%。",
            ["继续补跨模型、跨赛道和跨角色的长流程样本，验证边界控制稳定性。"],
        ),
        _dimension(
            "OpenClaw/外部 Agent 接入",
            98 if openclaw_runtime_validated and openclaw_static_validated else 89 if openclaw_static_validated else 86 if openclaw_plugin["runtime_checks"]["has_before_tool_call"] else 72,
            (
                "OpenClaw native plugin 已通过文件、Hook、JS语法、Bearer鉴权、默认无risk_hint、攻击阻断与正常放行契约检查；真实runtime inspect确认before_tool_call/after_tool_call已加载。"
                if openclaw_runtime_validated and openclaw_static_validated
                else "已提供 OpenClaw 兼容事件入口和可安装 native plugin 包，当前验收证据尚未同时覆盖安全契约与真实 runtime inspect。"
            ),
            ["保留真实 runtime inspect 输出、契约测试报告和端到端工具调用截图。"]
            if openclaw_runtime_validated and openclaw_static_validated
            else ["执行插件契约测试和真实 plugins inspect --runtime，保留鉴权、去自标注、阻断与放行证据。"],
        ),
        _dimension(
            "冻结集、基线与性能证据",
            98 if benchmark_ready else 52,
            (
                f"内部冻结集 {benchmark_dataset.get('case_count', 0)} 条，数据集SHA-256为 {benchmark_dataset.get('sha256', '')}；"
                f"四组基线完整，{benchmark_performance.get('concurrency', 0)}并发P95为"
                f"{benchmark_performance.get('concurrent_latency_ms', {}).get('p95', 0)}ms，吞吐"
                f"{benchmark_performance.get('concurrent_throughput_per_second', 0)}次/秒。证据明确不冒充第三方盲测。"
                if benchmark_ready
                else "尚未形成同时覆盖200条无risk_hint冻结集、四组基线和2000次性能判定的固定证据。"
            ),
            ["保持数据集与策略快照SHA-256，答辩前在固定机器复跑并记录环境。"]
            if benchmark_ready
            else ["运行 competition-benchmark，写入冻结集、基线、误报漏报和性能报告。"],
        ),
        _dimension(
            "模型检测与异常检测",
            92 if calibration["summary"]["benign_false_alarm_rate"] <= 10 else 75,
            f"已有输入过滤、输出过滤、上下文隔离、风险评分和异常分字段；推荐异常阈值 {calibration['summary']['recommended_threshold']}，攻击召回率 {calibration['summary']['attack_recall_rate']}%，正常误报率 {calibration['summary']['benign_false_alarm_rate']}%。",
            ["继续扩充正常业务任务样本和跨模型样本，验证阈值在更多比赛任务上下文中稳定。"],
        ),
        _dimension(
            "多模型实测能力",
            98 if real_model_strict_ready else 92 if real_api_case_count else 82 if real_model_case_count else 45,
            (
                f"真实模型工具调用盲测已覆盖 {real_model_case_count} 个样本，模型成功生成工具调用 "
                f"{model_tool_call_success_count} 个，真实 API 样本 {real_api_case_count} 个；"
                f"严格因果证据{'已通过' if real_model_strict_ready else '仍需补齐'}。"
                if real_model_case_count
                else "已有模型适配层和本地兜底，但缺少真实模型工具调用盲测结果。"
            ),
            ["补充第二个真实模型供应商的同题复跑，验证跨模型稳定性。"]
            if real_model_strict_ready
            else ["继续扩展 DeepSeek/智谱/本地兜底的同题批量对比矩阵。"]
            if real_model_case_count
            else ["运行真实模型工具调用盲测报告，确认模型结构化工具调用能进入监督器。"],
        ),
        _dimension(
            "答辩材料与可视化",
            98 if briefing_export_done else 88,
            (
                f"已有全量证据索引、攻击面评测单页、HTML 导出，并已生成 PNG {briefing_png_count} 个、PDF {briefing_pdf_count} 个。"
                if briefing_export_done
                else "已有全量证据索引、攻击面评测单页和 HTML 导出，但还未生成可直接放入 PPT 的 PNG/PDF 文件。"
            ),
            ["保留导出目录和 Markdown 报告，答辩前重新运行一次确认文件最新。"]
            if briefing_export_done
            else ["点击“导出评测单页”生成 PNG/PDF，减少手动截图。"],
        ),
        _dimension(
            "部署与可复现",
            deployment_score,
            deployment_evidence,
            ["答辩前在干净环境运行一次 Windows 启动脚本或宝塔启动命令，保留启动截图。"]
            if deployment_score >= 90
            else ["补齐一键启动脚本和部署说明，降低评委复现成本。"],
        ),
        _dimension(
            "项目工程化",
            max(90, engineering["score"]) if engineering["complete"] else max(58, engineering["score"]),
            f"当前有 {len(runs)} 条运行证据，SQLite 持久化和 CLI 可用；工程检查项 {engineering['passed']}/{engineering['total']} 已具备，覆盖严格 lint、UI 审计、前端测试、API 检查和构建命令。",
            ["保持本地 verify、lint:strict、ui:audit、测试和构建检查；如后续接 CI，再把这些命令接入提交前验证。"]
            if engineering["complete"]
            else ["补齐严格 lint、UI 审计、前后端测试和构建检查，防止后续改页面时破坏接口。"],
        ),
    ]


def _dimension(name: str, score: int, evidence: str, next_actions: list[str]) -> dict[str, Any]:
    if score >= 90:
        status = "已完成"
    elif score >= 65:
        status = "需完善"
    else:
        status = "高优先级缺口"
    return {
        "name": name,
        "score": score,
        "status": status,
        "evidence": evidence,
        "next_actions": next_actions,
    }


def _feature_backlog(
    surface_index: dict[str, Any],
    effectiveness: dict[str, Any],
    requirements: list[dict[str, Any]],
    calibration: dict[str, Any],
    openclaw_plugin: dict[str, Any],
    openclaw_validation: dict[str, Any] | None,
    competition_benchmark: dict[str, Any] | None,
    real_model_evaluation: dict[str, Any] | None,
    briefing_export: dict[str, Any] | None,
    local_launch: dict[str, bool],
) -> list[dict[str, Any]]:
    calibration_done = (
        calibration["summary"]["attack_sample_count"] > 0
        and calibration["summary"]["benign_sample_count"] > 0
        and calibration["summary"]["benign_false_alarm_rate"] <= 10
    )
    openclaw_static_validated = bool(
        openclaw_validation
        and openclaw_validation.get("static_passed")
        and openclaw_validation.get("files_passed")
        and openclaw_validation.get("node_syntax_passed")
        and openclaw_validation.get("contract_e2e_passed")
    )
    openclaw_runtime_validated = bool(openclaw_validation and openclaw_validation.get("runtime_inspect_passed"))
    benchmark_ready = _competition_benchmark_ready(competition_benchmark)
    real_model_summary = real_model_evaluation.get("summary", {}) if real_model_evaluation else {}
    real_model_done = bool(real_model_summary.get("strict_real_api_ready"))
    briefing_export_summary = briefing_export.get("summary", {}) if briefing_export else {}
    briefing_export_done = bool(
        briefing_export
        and briefing_export.get("ok")
        and (int(briefing_export_summary.get("png_count") or 0) > 0 or int(briefing_export_summary.get("pdf_count") or 0) > 0)
    )
    gap_rerun_done = (
        surface_index["summary"]["gap_count"] == 0
        and effectiveness["summary"]["evidence_complete_rate"] >= 90
        and effectiveness["summary"]["scenario_count"] > 0
    )
    one_command_done = local_launch["one_command_ready"]
    return [
        {
            "id": "competition-benchmark",
            "priority": "P0",
            "title": "200条冻结集、四组基线与性能评测",
            "why": "比赛答辩需要把有效性、误报和性能从产品叙述变成可复核的固定证据。",
            "scope": "固定100条攻击和100条正常样本，比较四层防护，并记录P50/P95/P99、吞吐和环境。",
            "acceptance": "报告无risk_hint，绑定数据集SHA-256，四组基线完整，性能判定不少于2000次。",
            "status": "已完成" if benchmark_ready else "未完成",
        },
        {
            "id": "real-openclaw-hook",
            "priority": "P0",
            "title": "真实 OpenClaw 源码级工具调用 Hook",
            "why": "研究方向明确提到开源智能化应用，源码级接入比兼容样例更有说服力。",
            "scope": "接入 OpenClaw 或同类 Agent 的工具调用前后置事件。",
            "acceptance": "能从真实 OpenClaw Agent 操作触发监督 API、审计日志和告警记录。",
            "status": "已完成"
            if openclaw_runtime_validated and openclaw_static_validated
            else "部分完成"
            if openclaw_static_validated or openclaw_plugin["runtime_checks"]["has_before_tool_call"]
            else "未完成",
        },
        {
            "id": "anomaly-calibration",
            "priority": "P0",
            "title": "异常检测阈值校准报告",
            "why": "当前 anomaly_score 已存在，但需要解释分数来源和误报控制。",
            "scope": "用攻击样本和正常业务任务样本生成阈值、召回率、误报率。",
            "acceptance": "输出 Markdown/JSON 报告，并在报告页展示异常检测曲线。",
            "status": "已完成" if calibration_done else "未完成",
        },
        {
            "id": "multi-model-eval",
            "priority": "P1",
            "title": "真实模型工具调用盲测",
            "why": "大模型安全题需要证明监督器不依赖脚本预设 tool_calls，而能接住真实模型结构化工具调用。",
            "scope": "对真实模型与本地兜底规划器运行同一批攻击/正常样本，并保留供应商响应指纹和双分支回执。",
            "acceptance": "真实 API 来源、任务对齐、预期决策、因果一致、供应商响应指纹、报告 Hash 和双分支回执全部通过。",
            "status": "已完成" if real_model_done else "未完成",
        },
        {
            "id": "gap-rerun",
            "priority": "P1",
            "title": "证据补跑与同步",
            "why": "证据包有缺口提示，但还缺自动补证据动作。",
            "scope": "从缺口列表定位脚本，自动运行 compare 或外部事件验证。",
            "acceptance": "点击按钮后刷新证据包，缺口数和运行记录同步变化。",
            "status": "已完成" if gap_rerun_done else "未完成",
        },
        {
            "id": "brief-export-pdf",
            "priority": "P1",
            "title": "攻击面评测单页 PNG/PDF 导出",
            "why": "HTML 已可打开，但最终 PPT 仍需要图片或 PDF。",
            "scope": "用 Playwright 或浏览器打印生成图片/PDF。",
            "acceptance": "提交包自动包含每类攻击面 PNG 或 PDF 单页。",
            "status": "已完成" if briefing_export_done else "未完成",
        },
        {
            "id": "one-command-run",
            "priority": "P2",
            "title": "一键启动与宝塔复现",
            "why": "评委复现时越少命令越稳。",
            "scope": "提供 Windows 启动脚本、npm 命令和宝塔部署启动口径。",
            "acceptance": "一条命令启动 API、前端和初始化本地受控环境数据。",
            "status": "已完成" if one_command_done else "未完成",
        },
    ]


def _competition_benchmark_ready(benchmark: dict[str, Any] | None) -> bool:
    if not benchmark:
        return False
    dataset = benchmark.get("dataset", {})
    method = benchmark.get("method", {})
    performance = benchmark.get("performance", {})
    baselines = benchmark.get("baselines", [])
    baseline_names = [item.get("name") for item in baselines if isinstance(item, dict)]
    full_runtime: dict[str, Any] = next(
        (item.get("summary", {}) for item in baselines if isinstance(item, dict) and item.get("name") == "full-runtime"),
        {},
    )
    return bool(
        benchmark.get("schema_version") == "agent-supervisor.competition-benchmark.v1"
        and dataset.get("case_count") == 200
        and dataset.get("attack_count") == 100
        and dataset.get("benign_count") == 100
        and dataset.get("sha256")
        and method.get("risk_hint_used") is False
        and method.get("external_validation") is False
        and baseline_names == ["allow-all", "tool-allowlist-only", "parameter-policy", "full-runtime"]
        and full_runtime.get("attack_recall_rate") == 100
        and full_runtime.get("benign_false_positive_rate") == 0
        and int(performance.get("call_count") or 0) >= 2000
        and int(performance.get("concurrency") or 0) >= 20
    )


def _next_sprint(backlog: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [item for item in backlog if item["priority"] == "P0" and item["status"] != "已完成"][:3]


def _risk_register(backlog: list[dict[str, Any]], effectiveness: dict[str, Any]) -> list[dict[str, str]]:
    backlog_status = {item["id"]: item["status"] for item in backlog}
    risks = [
        {
            "risk": "真实接入证据不足",
            "impact": "评委可能认为系统仍偏静态展示。",
            "mitigation": "优先完成真实 OpenClaw 或同类 Agent 的工具调用 Hook。",
        },
        {
            "risk": "复现步骤偏多",
            "impact": "现场环境不稳定时影响展示。",
            "mitigation": "补一键启动脚本、宝塔部署说明和最终截图/PDF 兜底材料。",
        },
    ]
    if backlog_status.get("anomaly-calibration") != "已完成":
        risks.insert(
            1,
            {
                "risk": "异常检测解释不足",
                "impact": "anomaly_score 容易被质疑为规则字段而非检测模型。",
                "mitigation": "补正常样本/攻击样本阈值校准和误报率报告。",
            },
        )
    if effectiveness["summary"]["evidence_complete_rate"] < 90:
        risks.append(
            {
                "risk": "运行证据不完整",
                "impact": "部分攻击脚本无法形成无防护/有防护对照。",
                "mitigation": "增加证据补跑与同步能力，部署或答辩前固定跑体检和构建检查。",
            }
        )
    return risks


def _competition_fit(requirements: list[dict[str, Any]]) -> int:
    satisfied = sum(1 for item in requirements if item["status"] in {"满足", "基本满足"})
    return round(satisfied / max(1, len(requirements)) * 100)
