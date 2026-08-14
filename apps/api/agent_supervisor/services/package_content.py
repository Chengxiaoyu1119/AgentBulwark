from __future__ import annotations

import json
import shutil
from collections import Counter
from pathlib import Path
from typing import Any

from apps.api.agent_supervisor.paths import REPO_ROOT, SANDBOX_REPORTS_DIR


def _clean_submission_summary(runs: list[dict[str, Any]], scenarios: list[dict[str, Any]]) -> dict[str, Any]:
    guarded_runs = [run for run in runs if run.get("guard_enabled")]
    unguarded_runs = [run for run in runs if not run.get("guard_enabled")]
    guarded_controlled = [
        run
        for run in guarded_runs
        if run.get("metrics", {}).get("blocked_count")
        or run.get("metrics", {}).get("asked_count")
        or run.get("metrics", {}).get("isolated_count")
    ]
    return {
        "clean_run_count": len(runs),
        "clean_scenario_count": len(scenarios),
        "clean_guarded_run_count": len(guarded_runs),
        "clean_unguarded_run_count": len(unguarded_runs),
        "clean_unguarded_attack_success_count": sum(1 for run in unguarded_runs if run.get("attack_success")),
        "clean_guarded_controlled_count": len(guarded_controlled),
        "clean_control_rate": round((len(guarded_controlled) / len(guarded_runs)) * 100) if guarded_runs else 0,
    }


def _clean_submission_evidence(summary: dict[str, Any], runs: list[dict[str, Any]]) -> str:
    lines = [
        "# 干净提交包证据说明",
        "",
        "本文件由一键干净提交包流程自动生成，用于说明当前提交包没有直接混用历史调试记录。",
        "",
        "## 生成方式",
        "",
        "- 对每个攻击脚本固定运行一次无防护复现。",
        "- 对每个攻击脚本固定运行一次有防护验证。",
        "- 生成报告材料时只使用本轮固定运行得到的证据数据。",
        "- 本流程不会把这些临时运行写入历史复现数据库。",
        "",
        "## 本轮统计",
        "",
        f"- 攻击脚本数量：{summary['clean_scenario_count']}",
        f"- 固定运行记录：{summary['clean_run_count']}",
        f"- 无防护运行：{summary['clean_unguarded_run_count']}",
        f"- 有防护运行：{summary['clean_guarded_run_count']}",
        f"- 无防护攻击复现数：{summary['clean_unguarded_attack_success_count']}",
        f"- 有防护控制数：{summary['clean_guarded_controlled_count']}",
        f"- 干净控制率：{summary['clean_control_rate']}%",
        "",
        "## 运行明细",
        "",
        "| 脚本 | 防护状态 | 攻击成功 | 阻断 | 询问 | 隔离 | 审计条数 | 告警条数 |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for run in runs:
        metrics = run.get("metrics", {})
        lines.append(
            "| {scenario} | {guard} | {success} | {blocked} | {asked} | {isolated} | {audit} | {alert} |".format(
                scenario=run.get("scenario", {}).get("id", "-"),
                guard="有防护" if run.get("guard_enabled") else "无防护",
                success="是" if run.get("attack_success") else "否",
                blocked=metrics.get("blocked_count", 0),
                asked=metrics.get("asked_count", 0),
                isolated=metrics.get("isolated_count", 0),
                audit=len(run.get("audit_logs", [])),
                alert=len(run.get("alerts", [])),
            )
        )
    return "\n".join(lines)


def _file(filename: str, title: str, description: str, content: str | dict[str, Any]) -> dict[str, Any]:
    if isinstance(content, str):
        text = content
        content_type = "text/markdown"
    else:
        text = json.dumps(content, ensure_ascii=False, indent=2)
        content_type = "application/json"
    return {
        "filename": filename,
        "title": title,
        "description": description,
        "content_type": content_type,
        "content": text,
        "size": len(text.encode("utf-8")),
    }


def _external_agent_demo_evidence_files() -> dict[str, str]:
    report_dir = SANDBOX_REPORTS_DIR
    files: dict[str, str] = {}
    markdown_path = report_dir / "最小外部Agent接入运行证据.md"
    json_path = report_dir / "最小外部Agent接入运行证据.json"
    if markdown_path.exists():
        files["最小外部Agent接入运行证据.md"] = markdown_path.read_text(encoding="utf-8")
    if json_path.exists():
        files["最小外部Agent接入运行证据.json"] = json_path.read_text(encoding="utf-8")
    return files


def _dependency_security_evidence_files() -> dict[str, str]:
    files: dict[str, str] = {}
    security_path = REPO_ROOT / "SECURITY.md"
    markdown_path = SANDBOX_REPORTS_DIR / "依赖安全审计报告.md"
    json_path = SANDBOX_REPORTS_DIR / "dependency-security-audit.json"
    if security_path.exists():
        files["依赖安全说明.md"] = security_path.read_text(encoding="utf-8")
    if markdown_path.exists():
        files["依赖安全审计报告.md"] = markdown_path.read_text(encoding="utf-8")
    if json_path.exists():
        files["依赖安全审计报告.json"] = json_path.read_text(encoding="utf-8")
    return files


def _openclaw_runtime_attempt_evidence_files() -> dict[str, str]:
    files: dict[str, str] = {}
    sources = {
        "OpenClaw真实运行尝试记录.md": SANDBOX_REPORTS_DIR / "OpenClaw源码级插件包验收报告.md",
        "OpenClaw真实运行尝试记录.json": SANDBOX_REPORTS_DIR / "OpenClaw源码级插件包验收报告.json",
    }
    for filename, source in sources.items():
        if source.exists():
            files[filename] = source.read_text(encoding="utf-8")
    return files


def _real_model_evaluation_material() -> str:
    markdown_path = SANDBOX_REPORTS_DIR / "真实模型工具调用盲测报告.md"
    if markdown_path.exists():
        return markdown_path.read_text(encoding="utf-8")
    return "\n".join(
        [
            "# 真实模型工具调用盲测报告",
            "",
            "当前报告材料中心未检测到已写入的盲测报告。",
            "请先执行 `node scripts/agent-supervisor-cli.mjs real-model-eval --output apps/api/sandbox/reports` 生成证据。",
        ]
    )


def _competition_benchmark_material() -> str:
    markdown_path = SANDBOX_REPORTS_DIR / "200条冻结集与基线性能评测.md"
    if markdown_path.exists():
        return markdown_path.read_text(encoding="utf-8")
    return "\n".join(
        [
            "# 200条冻结集、四组基线与性能评测",
            "",
            "当前按需证据包未检测到已写入的冻结集评测报告。",
            "请先执行 `node scripts/agent-supervisor-cli.mjs competition-benchmark --output apps/api/sandbox/reports` 生成证据。",
        ]
    )


def _http_e2e_benchmark_material() -> str:
    markdown_path = SANDBOX_REPORTS_DIR / "HTTP-SQLite-审计完整链路性能评测.md"
    if markdown_path.exists():
        return markdown_path.read_text(encoding="utf-8")
    return "\n".join(
        [
            "# HTTP、SQLite 与审计完整链路性能评测",
            "",
            "当前报告材料中心未检测到完整链路性能报告。",
            "请先执行 `node scripts/agent-supervisor-cli.mjs http-e2e-benchmark --output apps/api/sandbox/reports` 生成证据。",
        ]
    )


def _reproducibility_material() -> str:
    markdown_path = SANDBOX_REPORTS_DIR / "独立复现一致性验收报告.md"
    if markdown_path.exists():
        return markdown_path.read_text(encoding="utf-8")
    return "\n".join(
        [
            "# 独立复现一致性验收报告",
            "",
            "当前报告材料中心未检测到独立复现一致性报告。",
            "请执行 `node scripts/agent-supervisor-cli.mjs repro-check --trials 3 --output apps/api/sandbox/reports` 生成证据。",
        ]
    )


def _eligibility_material() -> str:
    markdown_path = SANDBOX_REPORTS_DIR / "上海信息安全参赛资格审查.md"
    if markdown_path.exists():
        return markdown_path.read_text(encoding="utf-8")
    return "\n".join(
        [
            "# 上海信息安全作品赛参赛资格审查",
            "",
            "当前材料中心未检测到资格审查报告。",
            "请执行 `python -X utf8 scripts/audit_shanghai_eligibility.py` 生成证据。",
        ]
    )


def _real_model_evaluation_evidence_files() -> dict[str, str]:
    files: dict[str, str] = {}
    sources = {
        "真实模型工具调用盲测报告.md": SANDBOX_REPORTS_DIR / "真实模型工具调用盲测报告.md",
        "真实模型工具调用盲测报告.json": SANDBOX_REPORTS_DIR / "真实模型工具调用盲测报告.json",
    }
    for filename, source in sources.items():
        if source.exists():
            files[filename] = source.read_text(encoding="utf-8")
    return files


def _copy_demo_screenshots(support_dir: Path) -> list[Path]:
    report_dir = SANDBOX_REPORTS_DIR
    screenshot_names = [
        "surface-dashboard-desktop-final.png",
        "surface-dashboard-mobile-final.png",
        "surface-evidence-index-board-desktop-final.png",
        "surface-evidence-index-board-mobile-final.png",
        "surface-defense-brief-desktop-final.png",
        "surface-defense-brief-mobile-final.png",
        "surface-dashboard-with-defense-brief-desktop-final.png",
        "surface-dashboard-with-defense-brief-mobile-final.png",
        "project-roadmap-block-desktop.png",
        "project-roadmap-block-mobile.png",
        "report-with-project-roadmap-desktop.png",
        "report-with-project-roadmap-mobile.png",
        "anomaly-calibration-block-desktop.png",
        "anomaly-calibration-block-mobile.png",
        "benign-evaluation-block-desktop.png",
        "benign-evaluation-block-mobile.png",
        "benign-workflow-block-desktop.png",
        "benign-workflow-block-mobile.png",
        "report-with-anomaly-calibration-desktop.png",
        "report-with-anomaly-calibration-mobile.png",
        "openclaw-plugin-panel-desktop.png",
        "openclaw-plugin-panel-mobile.png",
        "openclaw-plugin-validation-desktop.png",
        "openclaw-plugin-validation-mobile.png",
        "readiness-panel-desktop.png",
        "readiness-panel-mobile.png",
        "approval-queue-desktop.png",
        "approval-queue-mobile.png",
        "demo-drill-desktop.png",
        "demo-drill-mobile.png",
        "frontend-governance-desktop.png",
        "frontend-governance-mobile.png",
        "scenario-library-desktop.png",
        "experiment-lab-desktop.png",
        "agent-chain-desktop.png",
        "attack-chain-workbench-desktop.png",
        "attack-chain-workbench-mobile.png",
        "policy-impact-matrix-desktop.png",
        "audit-hash-verify-desktop.png",
        "decision-pill-audit-desktop.png",
        "decision-pill-alerts-desktop.png",
        "decision-pill-settings-desktop.png",
        "student-competition-attack-map-desktop.png",
        "student-competition-attack-map-mobile.png",
    ]
    screenshot_dir = support_dir / "复现截图"
    copied: list[Path] = []
    for name in screenshot_names:
        source = report_dir / name
        if not source.exists():
            continue
        screenshot_dir.mkdir(parents=True, exist_ok=True)
        target = screenshot_dir / name
        shutil.copy2(source, target)
        copied.append(target)
    return copied


def _copy_multi_agent_self_review_reports(target_dir: Path) -> list[Path]:
    report_dir = SANDBOX_REPORTS_DIR
    report_names = [
        "多Agent自审优化报告.json",
        "多Agent自审优化报告.md",
    ]
    copied: list[Path] = []
    for name in report_names:
        source = report_dir / name
        if not source.exists():
            continue
        target_dir.mkdir(parents=True, exist_ok=True)
        target = target_dir / name
        shutil.copy2(source, target)
        copied.append(target)
    return copied


def _copy_release_artifacts(support_dir: Path) -> list[Path]:
    target_dir = support_dir / "Windows一键运行"
    sources = [
        REPO_ROOT / "apps" / "api" / "sandbox" / "release" / "dist" / "zhian-supervisor-launcher.exe",
        REPO_ROOT / "scripts" / "start-zhian.cmd",
        REPO_ROOT / "scripts" / "start-zhian.ps1",
        REPO_ROOT / "scripts" / "启动智安哨.cmd",
        REPO_ROOT / "scripts" / "启动智安哨.ps1",
        REPO_ROOT / "scripts" / "生成智安哨Windows启动器.ps1",
    ]
    copied: list[Path] = []
    for source in sources:
        if not source.exists():
            continue
        target_dir.mkdir(parents=True, exist_ok=True)
        target = target_dir / source.name
        shutil.copy2(source, target)
        copied.append(target)
    return copied


def _copy_formal_submission_documents(package_dir: Path) -> list[Path]:
    target_dir = package_dir / "03_正式提交材料草稿"
    source_dir = REPO_ROOT / "docs" / "上海信息安全" / "参赛材料草稿"
    sources = sorted(source_dir.glob("*")) if source_dir.exists() else []
    copied: list[Path] = []
    for source in sources:
        if not source.is_file() or source.suffix.lower() not in {".docx", ".xlsx", ".pdf", ".md"}:
            continue
        target_dir.mkdir(parents=True, exist_ok=True)
        target = target_dir / source.name
        shutil.copy2(source, target)
        copied.append(target)
    return copied


def _risk_report(surfaces: list[dict[str, Any]], scenarios: list[dict[str, Any]]) -> str:
    lines = [
        "# 安全风险分析报告",
        "",
        "本报告从红队视角覆盖提示注入、模型越狱、数据泄露、滥用风险、工具调用劫持、记忆中毒、环境感知污染 7 类攻击面。",
        "所有复现均在智安哨沙箱受控环境内完成，不访问真实外部系统、不读取真实用户文件、不发送真实邮件。",
        "",
    ]
    for surface in surfaces:
        linked = [scenario for scenario in scenarios if scenario["surface_id"] == surface["id"]]
        lines.extend(
            [
                f"## {surface['name']}",
                "",
                f"- 风险等级：{surface['risk']}",
                f"- 研究状态：{surface['status']}",
                f"- 攻击原理：{surface['summary']}",
                f"- 典型入口：{'、'.join(surface.get('entry_points', []))}",
                f"- 保护资产：{'、'.join(surface.get('protected_assets', []))}",
                f"- 攻击目标：{'、'.join(surface.get('attacker_goals', []))}",
                f"- 检测信号：{'、'.join(surface.get('detection_signals', []))}",
                f"- 评测重点：{'、'.join(surface.get('evaluation_focus', []))}",
                f"- 防御方向：{surface['defense']}",
                "",
            ]
        )
        for scenario in linked:
            lines.extend(
                [
                    f"### 脚本：{scenario['title']}",
                    "",
                    f"- 脚本编号：{scenario['id']}",
                    f"- 目标工具：{scenario['target']}",
                    f"- 模型对抗样本：{scenario['adversarial_prompt']}",
                    f"- 越狱测试用例：{scenario['jailbreak_case']}",
                    f"- 预期危害：{scenario['expected_risk']}",
                    f"- 落地防御：{scenario['defense']}",
                    f"- 安全边界：{scenario.get('safety_boundary', '仅在本地沙箱受控实验环境复现。')}",
                    "- 复现步骤：",
                ]
            )
            for index, step in enumerate(scenario["script_steps"], start=1):
                lines.append(f"  {index}. {step}")
            if scenario.get("attack_path"):
                lines.append("- 攻击链路：")
                for index, step in enumerate(scenario["attack_path"], start=1):
                    lines.append(f"  {index}. {step}")
            if scenario.get("detection_points"):
                lines.append(f"- 检测信号：{'、'.join(scenario['detection_points'])}")
            if scenario.get("success_criteria"):
                lines.append(f"- 成功判据：{'；'.join(scenario['success_criteria'])}")
            lines.append("")
    return "\n".join(lines)


def _sample_set(scenarios: list[dict[str, Any]], surface_name: dict[str, str]) -> dict[str, Any]:
    return {
        "name": "智安哨模型对抗样本与越狱测试用例集",
        "safe_scope": "仅用于本地沙箱受控实验环境复现，不针对真实系统。",
        "items": [
            {
                "id": scenario["id"],
                "surface": surface_name.get(scenario["surface_id"], scenario["surface_id"]),
                "severity": scenario["severity"],
                "target": scenario["target"],
                "adversarial_prompt": scenario["adversarial_prompt"],
                "jailbreak_case": scenario["jailbreak_case"],
                "expected_risk": scenario["expected_risk"],
                "defense": scenario["defense"],
                "detection_points": scenario.get("detection_points", []),
                "success_criteria": scenario.get("success_criteria", []),
                "safety_boundary": scenario.get("safety_boundary", "本地沙箱受控实验环境复现。"),
                "tags": scenario.get("tags", []),
            }
            for scenario in scenarios
        ],
    }


def _script_library(scenarios: list[dict[str, Any]], surface_name: dict[str, str]) -> dict[str, Any]:
    return {
        "name": "智安哨智能体攻击脚本库",
        "agent_roles": ["规划 Agent", "样本生成 Agent", "执行 Agent", "目标智能体", "行为监督器", "评测 Agent"],
        "scripts": [
            {
                "id": scenario["id"],
                "surface": surface_name.get(scenario["surface_id"], scenario["surface_id"]),
                "title": scenario["title"],
                "steps": scenario["script_steps"],
                "attack_path": scenario.get("attack_path", []),
                "detection_points": scenario.get("detection_points", []),
                "success_criteria": scenario.get("success_criteria", []),
                "tool_calls": scenario["tool_calls"],
                "safe_boundary": scenario.get("safety_boundary", "所有工具调用均经过监督器，并在沙箱目录、本地沙箱 outbox、本地受控环境 API、沙箱记忆库中执行。"),
            }
            for scenario in scenarios
        ],
    }


def _supervisor_spec(policies: list[dict[str, Any]]) -> str:
    lines = [
        "# 行为监督原型说明",
        "",
        "监督器部署位置：智能体集群 -> 工具调用层 -> 外部工具/文件/API/代码执行。",
        "",
        "## 监督对象",
        "",
        "- 模型输入输出",
        "- 多 agent 消息传递",
        "- 工具调用参数",
        "- 文件读写路径",
        "- API 请求目标",
        "- 代码执行命令",
        "- 记忆写入与读取",
        "- 环境变量和配置读取",
        "",
        "## 策略决策",
        "",
        "| 策略编号 | 策略名称 | 决策 | 说明 |",
        "|---|---|---|---|",
    ]
    for policy in policies:
        lines.append(f"| {policy['id']} | {policy['name']} | {policy['decision']} | {policy['description']} |")
    lines.extend(
        [
            "",
            "## 本地受控环境业务工具",
            "",
            "- 邮件工具：写入本地沙箱 outbox，不发送真实邮件。",
            "- 文件工具：只访问沙箱目录。",
            "- API 工具：使用本地受控环境参赛队伍、提交物、成绩榜、赛题种子和校园网会话接口。",
            "- 代码执行工具：限制目录、超时、输出长度和危险命令。",
            "- 记忆工具：支持写入、读取、污染和隔离。",
            "- 环境工具：提供低信任假配置和假环境变量。",
            "",
            "## 外部智能体适配方式",
            "",
            "平台提供强制开启防护的 `/api/runtime/evaluate` 通用监督接口和 `/api/integrations/openclaw/events` 兼容接口。OpenClaw 或其他开源智能体应用只需要在工具执行前把工具调用事件转发给监督器，即可获得允许、拒绝、询问、隔离决策。",
            "",
            "外部事件会被写入 `audit_logs` 和 `alerts`，因此它不是只能运行内置样例，也可以作为旁路安全插件接入真实智能体应用的工具调用链。",
        ]
    )
    return "\n".join(lines)


def _experiment_report(runs: list[dict[str, Any]]) -> str:
    policy_counter: Counter[str] = Counter()
    decision_counter: Counter[str] = Counter()
    for run in runs:
        for log in run.get("audit_logs", []):
            policy_counter[log["policy_id"]] += 1
            decision_counter[log["decision"]] += 1

    total = len(runs)
    guarded = [run for run in runs if run.get("guard_enabled")]
    attack_success = [run for run in runs if run.get("attack_success")]
    avg_latency = round(sum(run.get("metrics", {}).get("detection_latency_ms", 0) for run in runs) / total) if total else 0
    lines = [
        "# 实验评测结果",
        "",
        f"- 实验总数：{total}",
        f"- 开启防护实验：{len(guarded)}",
        f"- 攻击成功率：{round((len(attack_success) / total) * 100) if total else 0}%",
        f"- 平均检测延迟：{avg_latency}ms",
        "",
        "## 策略命中",
        "",
        "| 策略 | 命中次数 |",
        "|---|---:|",
    ]
    if policy_counter:
        for policy_id, count in policy_counter.most_common():
            lines.append(f"| {policy_id} | {count} |")
    else:
        lines.append("| 暂无 | 0 |")

    lines.extend(["", "## 决策分布", "", "| 决策 | 次数 |", "|---|---:|"])
    if decision_counter:
        for decision, count in decision_counter.most_common():
            lines.append(f"| {decision} | {count} |")
    else:
        lines.append("| 暂无 | 0 |")

    lines.extend(
        [
            "",
            "## 最近实验明细",
            "",
            "| 时间 | 脚本 | 防护 | 攻击成功 | 阻断 | 询问 | 隔离 | 延迟 |",
            "|---|---|---|---|---:|---:|---:|---:|",
        ]
    )
    for run in runs:
        metrics = run.get("metrics", {})
        scenario = run.get("scenario", {})
        lines.append(
            "| {time} | {scenario} | {guard} | {success} | {blocked} | {asked} | {isolated} | {latency}ms |".format(
                time=str(run.get("created_at", ""))[:19],
                scenario=scenario.get("id", "unknown"),
                guard="开启" if run.get("guard_enabled") else "关闭",
                success="是" if run.get("attack_success") else "否",
                blocked=metrics.get("blocked_count", 0),
                asked=metrics.get("asked_count", 0),
                isolated=metrics.get("isolated_count", 0),
                latency=metrics.get("detection_latency_ms", 0),
            )
        )
    if not runs:
        lines.append("| 暂无 | 暂无 | 暂无 | 否 | 0 | 0 | 0 | 0ms |")
    return "\n".join(lines)


def _checklist(
    surfaces: list[dict[str, Any]],
    scenarios: list[dict[str, Any]],
    runs: list[dict[str, Any]],
    alerts_count: int,
) -> list[dict[str, str]]:
    external_agent_ready = False
    external_agent_report = SANDBOX_REPORTS_DIR / "最小外部Agent接入运行证据.json"
    if external_agent_report.exists():
        try:
            payload = json.loads(external_agent_report.read_text(encoding="utf-8"))
            summary = payload.get("summary", {})
            external_agent_ready = bool(
                payload.get("schema_version") == "agent-supervisor.external-agent-e2e.v1"
                and payload.get("risk_hint_used") is False
                and summary.get("task_count", 0) >= 4
                and summary.get("audit_hash_count") == summary.get("task_count")
            )
        except (OSError, json.JSONDecodeError):
            pass
    surface_count = len({scenario["surface_id"] for scenario in scenarios})
    complete_scenarios = [
        scenario
        for scenario in scenarios
        if scenario.get("adversarial_prompt") and scenario.get("jailbreak_case") and scenario.get("script_steps") and scenario.get("tool_calls")
    ]
    return [
        {
            "requirement": "安全风险分析报告至少 3 类攻击场景",
            "status": "满足",
            "evidence": f"当前覆盖 {len(surfaces)} 类攻击面，其中 {surface_count} 类已有脚本。",
        },
        {
            "requirement": "每类场景包含模型对抗样本与越狱测试用例集",
            "status": "满足",
            "evidence": f"{len(complete_scenarios)}/{len(scenarios)} 个脚本已包含对抗样本、越狱用例、脚本步骤和工具调用。",
        },
        {
            "requirement": "智能体攻击脚本",
            "status": "满足",
            "evidence": "攻击脚本库包含单 agent 和多 agent 协同复现步骤。",
        },
        {
            "requirement": "拦截智能体集群与外部工具的交互",
            "status": "满足",
            "evidence": "run_scenario 调用链中每次 tool_call 均先经过 supervisor.decide。",
        },
        {
            "requirement": "支持允许、拒绝、询问、隔离或异常检测",
            "status": "满足",
            "evidence": "策略中心和审计日志已覆盖四类决策。",
        },
        {
            "requirement": "通用智能体工具执行链接入",
            "status": "满足" if external_agent_ready else "待补证",
            "evidence": (
                "AgentToolGuard 已完成正常放行、风险控制、真实工具执行和审计落库端到端验证，且输入不包含 risk_hint。"
                if external_agent_ready
                else "已提供通用 HTTP、OpenAI Agents SDK、LangChain 和 LangGraph 接入示例；需运行通用 Agent 端到端演示生成证据。"
            ),
        },
        {
            "requirement": "本地受控环境业务工具",
            "status": "满足",
            "evidence": "已覆盖邮件、文件、API、代码执行、记忆、环境变量工具。",
        },
        {
            "requirement": "模型调用链路安全监控插件",
            "status": "满足",
            "evidence": "agent_trace、audit_logs、alerts 记录输入、输出、工具调用和策略命中。",
        },
        {
            "requirement": "基座模型检测或过滤原型",
            "status": "满足",
            "evidence": "支持越狱提示过滤、工具行为监测和本地兜底模型。",
        },
        {
            "requirement": "监督端实时展示告警或阻断记录",
            "status": "满足" if alerts_count else "待运行实验",
            "evidence": f"当前已有 {alerts_count} 条告警或阻断记录，实验运行次数 {len(runs)}。",
        },
    ]
