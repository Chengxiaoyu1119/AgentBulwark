from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ...paths import SANDBOX_REPORTS_DIR
from ...storage.data import get_attack_surfaces, get_policies, get_scenarios
from ..evaluations.datasets import build_attack_case_dataset
from ..governance.supervisor import decide
from .surface_pack_html import render_briefing_sheet_index_html, render_surface_briefing_sheet_html

REPORT_ROOT = SANDBOX_REPORTS_DIR
CONTROL_DECISIONS = {"拒绝", "询问", "隔离"}


def build_surface_evidence_pack(surface_id: str, runs: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    surface = _find_surface(surface_id)
    scenarios = [scenario for scenario in get_scenarios() if scenario["surface_id"] == surface_id]
    policies = {policy["id"]: policy for policy in get_policies()}
    dataset = build_attack_case_dataset(surface_id)
    scenario_ids = {scenario["id"] for scenario in scenarios}
    relevant_runs = _runs_for_surface(runs or [], surface_id, scenario_ids)
    attack_runs = [run for run in relevant_runs if run.get("scenario", {}).get("id") in scenario_ids]
    scenario_cards = [_scenario_card(surface, scenario, relevant_runs) for scenario in scenarios]
    guarded_runs = [run for run in attack_runs if run.get("guard_enabled")]
    controlled_runs = [run for run in guarded_runs if _is_controlled_run(run)]
    latest_guarded_results = [
        card["latest_guarded_result"]
        for card in scenario_cards
        if card["latest_guarded_result"]["status"] != "暂无运行证据"
    ]
    latest_controlled_results = [
        result
        for result in latest_guarded_results
        if result["status"] == "已控制"
    ]
    policy_counter = Counter(
        expectation["policy_id"]
        for card in scenario_cards
        for expectation in card["expected_decisions"]
        if expectation["policy_id"] != "guard-disabled"
    )
    tool_counter = Counter(
        tool_call["tool"]
        for scenario in scenarios
        for tool_call in scenario.get("tool_calls", [])
    )

    coverage_checks = {
        "has_surface_profile": bool(surface.get("entry_points") and surface.get("protected_assets") and surface.get("detection_signals")),
        "has_adversarial_samples": dataset["summary"]["adversarial_sample_count"] > 0,
        "has_jailbreak_cases": dataset["summary"]["jailbreak_case_count"] > 0,
        "has_agent_scripts": dataset["summary"]["agent_script_count"] > 0,
        "has_policy_expectations": bool(policy_counter),
        "has_runtime_evidence": bool(relevant_runs),
    }
    readiness_score = round(
        sum(1 for value in coverage_checks.values() if value) / max(1, len(coverage_checks)) * 100
    )
    summary = {
        "scenario_count": len(scenarios),
        "sample_count": dataset["summary"]["adversarial_sample_count"],
        "jailbreak_case_count": dataset["summary"]["jailbreak_case_count"],
        "agent_script_count": dataset["summary"]["agent_script_count"],
        "tool_call_count": dataset["summary"]["tool_call_count"],
        "unique_tool_count": len(tool_counter),
        "expected_policy_count": len(policy_counter),
        "run_count": len(relevant_runs),
        "attack_run_count": len(attack_runs),
        "external_run_count": len(relevant_runs) - len(attack_runs),
        "guarded_run_count": len(guarded_runs),
        "controlled_run_count": len(controlled_runs),
        "latest_guarded_scenario_count": len(latest_guarded_results),
        "latest_controlled_scenario_count": len(latest_controlled_results),
        "control_rate": round((len(latest_controlled_results) / len(latest_guarded_results)) * 100) if latest_guarded_results else 0,
        "guarded_attack_success_rate": _rate([run for run in guarded_runs if run.get("attack_success")], guarded_runs),
        "readiness_score": readiness_score,
    }
    gaps = _evidence_gaps(surface, scenario_cards, summary, coverage_checks)
    summary["gap_count"] = len(gaps)

    return {
        "name": f"智安哨攻击面证据包：{surface['name']}",
        "version": "0.4.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "surface": surface,
        "summary": summary,
        "coverage_checks": coverage_checks,
        "gaps": gaps,
        "threat_chain": _threat_chain(surface, scenarios, policy_counter),
        "policy_distribution": [
            {
                "policy_id": policy_id,
                "policy_name": policies.get(policy_id, {}).get("name", policy_id),
                "count": count,
                "decision": policies.get(policy_id, {}).get("decision", "未记录"),
            }
            for policy_id, count in policy_counter.most_common()
        ],
        "tool_coverage": [
            {"tool": tool, "count": count}
            for tool, count in tool_counter.most_common()
        ],
        "replay_commands": _replay_commands(surface_id, [scenario["id"] for scenario in scenarios]),
        "scenarios": scenario_cards,
        "dataset_summary": dataset["summary"],
    }


def build_surface_evidence_pack_markdown(surface_id: str, runs: list[dict[str, Any]] | None = None) -> str:
    pack = build_surface_evidence_pack(surface_id, runs)
    surface = pack["surface"]
    summary = pack["summary"]
    lines = [
        f"# 攻击面证据包：{surface['name']}",
        "",
        "该文件把单个攻击面的攻击样本、越狱用例、智能体脚本、预期监督策略、运行证据和复现入口汇总到一起，用于说明该攻击面可复现、可审计、可防御。",
        "",
        "## 证据概览",
        "",
        f"- 攻击面编号：`{surface['id']}`",
        f"- 风险等级：{surface['risk']}",
        f"- 脚本数量：{summary['scenario_count']}",
        f"- 对抗样本：{summary['sample_count']}",
        f"- 越狱用例：{summary['jailbreak_case_count']}",
        f"- 智能体脚本：{summary['agent_script_count']}",
        f"- 运行记录：{summary['run_count']}（攻击脚本 {summary['attack_run_count']}，外部事件 {summary['external_run_count']}），有防护控制率：{summary['control_rate']}%",
        f"- 证据完整度：{summary['readiness_score']}%",
        f"- 待补强项：{summary['gap_count']}",
        "",
        "## 威胁链路",
        "",
        "| 阶段 | 内容 |",
        "|---|---|",
    ]
    for node in pack["threat_chain"]:
        lines.append(f"| {node['stage']} | {node['text']} |")

    lines.extend(["", "## 策略与工具覆盖", "", "| 类型 | 明细 |", "|---|---|"])
    lines.append("| 预期命中策略 | " + " / ".join(item["policy_id"] for item in pack["policy_distribution"]) + " |")
    lines.append("| 目标工具 | " + " / ".join(item["tool"] for item in pack["tool_coverage"]) + " |")
    lines.append("| 防御加固 | " + " / ".join(surface.get("mitigations") or [surface.get("defense", "")]) + " |")

    lines.extend(["", "## 可复现实验入口", ""])
    for command in pack["replay_commands"]:
        lines.append(f"- {command['label']}：`{command['value']}`")

    lines.extend(["", "## 证据缺口提示", ""])
    if pack["gaps"]:
        lines.extend(["| 优先级 | 缺口 | 当前证据 | 建议动作 |", "|---|---|---|---|"])
        for gap in pack["gaps"]:
            action = gap["action"]
            if gap.get("command"):
                action = f"{action} `{gap['command']}`"
            lines.append(f"| {gap['severity']} | {gap['title']} | {gap['evidence']} | {action} |")
    else:
        lines.append("当前攻击面的样本、脚本、策略和运行证据已形成闭环，暂无高优先级补强项。")

    lines.extend(["", "## 脚本证据明细", ""])
    for card in pack["scenarios"]:
        lines.extend(
            [
                f"### {card['id']}：{card['title']}",
                "",
                f"- 目标工具：`{card['target']}`",
                f"- 风险等级：{card['severity']}",
                f"- 攻击路径：{' -> '.join(card['attack_path']) if card['attack_path'] else '待补充'}",
                f"- 最近有防护结果：{card['latest_guarded_result']['status']}",
                "",
                "| 预期工具 | 决策 | 策略 | 风险分 |",
                "|---|---|---|---:|",
            ]
        )
        for item in card["expected_decisions"]:
            lines.append(f"| {item['tool']} | {item['decision']} | {item['policy_id']} | {item['risk_score']} |")
        lines.append("")
    return "\n".join(lines)


def build_surface_evidence_index(runs: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    packs = [build_surface_evidence_pack(surface["id"], runs) for surface in get_attack_surfaces()]
    summaries = [
        {
            "surface_id": pack["surface"]["id"],
            "surface_name": pack["surface"]["name"],
            "risk": pack["surface"]["risk"],
            "scenario_count": pack["summary"]["scenario_count"],
            "sample_count": pack["summary"]["sample_count"],
            "agent_script_count": pack["summary"]["agent_script_count"],
            "expected_policy_count": pack["summary"]["expected_policy_count"],
            "unique_tool_count": pack["summary"]["unique_tool_count"],
            "run_count": pack["summary"]["run_count"],
            "control_rate": pack["summary"]["control_rate"],
            "readiness_score": pack["summary"]["readiness_score"],
            "gap_count": pack["summary"]["gap_count"],
            "top_policies": [item["policy_id"] for item in pack["policy_distribution"][:4]],
            "tools": [item["tool"] for item in pack["tool_coverage"]],
            "gaps": pack["gaps"],
        }
        for pack in packs
    ]
    total_scenarios = sum(item["scenario_count"] for item in summaries)
    total_samples = sum(item["sample_count"] for item in summaries)
    total_scripts = sum(item["agent_script_count"] for item in summaries)
    total_gaps = sum(item["gap_count"] for item in summaries)
    return {
        "name": "智安哨全部攻击面证据包索引",
        "version": "0.4.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "surface_count": len(packs),
            "scenario_count": total_scenarios,
            "sample_count": total_samples,
            "agent_script_count": total_scripts,
            "avg_readiness_score": round(sum(item["readiness_score"] for item in summaries) / len(summaries)) if summaries else 0,
            "avg_control_rate": round(sum(item["control_rate"] for item in summaries) / len(summaries)) if summaries else 0,
            "gap_count": total_gaps,
            "runtime_evidence_surface_count": sum(1 for item in summaries if item["run_count"] > 0),
            "complete_surface_count": sum(1 for item in summaries if item["gap_count"] == 0),
        },
        "surfaces": summaries,
    }


def build_surface_evidence_index_markdown(runs: list[dict[str, Any]] | None = None) -> str:
    index = build_surface_evidence_index(runs)
    lines = [
        "# 攻击面证据包索引",
        "",
        "该索引用于快速检查 7 类攻击面的证据成熟度、策略覆盖和运行证据。每个攻击面均可通过 API 或 CLI 单独导出完整证据包。",
        "",
        "## 总览",
        "",
        f"- 攻击面数量：{index['summary']['surface_count']}",
        f"- 攻击脚本数量：{index['summary']['scenario_count']}",
        f"- 对抗样本数量：{index['summary']['sample_count']}",
        f"- 智能体脚本数量：{index['summary']['agent_script_count']}",
        f"- 平均证据完整度：{index['summary']['avg_readiness_score']}%",
        f"- 平均控制率：{index['summary']['avg_control_rate']}%",
        f"- 待补强项：{index['summary']['gap_count']}",
        "",
        "| 攻击面 | 风险 | 脚本 | 样本 | 脚本 | 策略数 | 控制率 | 完整度 | 缺口 |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for surface in index["surfaces"]:
        lines.append(
            f"| {surface['surface_name']} | {surface['risk']} | {surface['scenario_count']} | {surface['sample_count']} | {surface['agent_script_count']} | {surface['expected_policy_count']} | {surface['control_rate']}% | {surface['readiness_score']}% | {surface['gap_count']} |"
        )
    lines.extend(
        [
            "",
            "## 待补强项",
            "",
            "| 攻击面 | 优先级 | 缺口 | 建议动作 |",
            "|---|---|---|---|",
        ]
    )
    gap_rows = [
        (surface["surface_name"], gap)
        for surface in index["surfaces"]
        for gap in surface["gaps"]
    ]
    if gap_rows:
        for surface_name, gap in gap_rows:
            lines.append(f"| {surface_name} | {gap['severity']} | {gap['title']} | {gap['action']} |")
    else:
        lines.append("| 全部攻击面 | low | 暂无高优先级缺口 | 保持当前证据链并补充最终截图即可 |")
    lines.extend(
        [
            "",
            "## 复现与导出入口",
            "",
            "- JSON API：`GET /api/attack_surfaces/{surface_id}/evidence_pack`",
            "- Markdown API：`GET /api/attack_surfaces/{surface_id}/evidence_pack.md`",
            "- 单攻击面 CLI：`node scripts/agent-supervisor-cli.mjs surface-pack --surface prompt-injection --output apps/api/sandbox/reports`",
            "- 全量证据包 CLI：`node scripts/agent-supervisor-cli.mjs surface-packs --output apps/api/sandbox/reports`",
        ]
    )
    return "\n".join(lines)


def build_surface_briefing_sheet_html(surface_id: str, runs: list[dict[str, Any]] | None = None) -> str:
    return render_surface_briefing_sheet_html(build_surface_evidence_pack(surface_id, runs))

def write_surface_briefing_sheet(
    surface_id: str,
    output_root: str | Path | None = None,
    runs: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    root = Path(output_root) if output_root else REPORT_ROOT
    root.mkdir(parents=True, exist_ok=True)
    pack = build_surface_evidence_pack(surface_id, runs)
    html_path = root / f"攻击面评测单页-{surface_id}.html"
    html_path.write_text(build_surface_briefing_sheet_html(surface_id, runs), encoding="utf-8")
    return {
        "surface_id": surface_id,
        "surface_name": pack["surface"]["name"],
        "html_path": str(html_path.resolve()),
        "summary": pack["summary"],
    }


def write_all_surface_briefing_sheets(
    output_root: str | Path | None = None,
    runs: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    root = Path(output_root) if output_root else REPORT_ROOT
    root.mkdir(parents=True, exist_ok=True)
    sheets = [
        write_surface_briefing_sheet(surface["id"], root, runs)
        for surface in get_attack_surfaces()
    ]
    index_path = root / "攻击面评测单页索引.html"
    index_path.write_text(render_briefing_sheet_index_html(sheets), encoding="utf-8")
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "output_dir": str(root.resolve()),
        "index_html_path": str(index_path.resolve()),
        "surface_count": len(sheets),
        "file_count": len(sheets) + 1,
        "sheets": sheets,
    }


def write_surface_evidence_pack(
    surface_id: str,
    output_root: str | Path | None = None,
    runs: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    root = Path(output_root) if output_root else REPORT_ROOT
    root.mkdir(parents=True, exist_ok=True)
    data = build_surface_evidence_pack(surface_id, runs)
    json_path = root / f"攻击面证据包-{surface_id}.json"
    markdown_path = root / f"攻击面证据包-{surface_id}.md"
    json_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    markdown_path.write_text(build_surface_evidence_pack_markdown(surface_id, runs), encoding="utf-8")
    return {
        "surface_id": surface_id,
        "json_path": str(json_path.resolve()),
        "markdown_path": str(markdown_path.resolve()),
        "summary": data["summary"],
    }


def write_all_surface_evidence_packs(
    output_root: str | Path | None = None,
    runs: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    root = Path(output_root) if output_root else REPORT_ROOT
    root.mkdir(parents=True, exist_ok=True)
    written = []
    for surface in get_attack_surfaces():
        written.append(write_surface_evidence_pack(surface["id"], root, runs))
    index = build_surface_evidence_index(runs)
    index_json_path = root / "攻击面证据包索引.json"
    index_markdown_path = root / "攻击面证据包索引.md"
    index_json_path.write_text(json.dumps(index, ensure_ascii=False, indent=2), encoding="utf-8")
    index_markdown_path.write_text(build_surface_evidence_index_markdown(runs), encoding="utf-8")
    return {
        "generated_at": index["generated_at"],
        "output_dir": str(root.resolve()),
        "index_json_path": str(index_json_path.resolve()),
        "index_markdown_path": str(index_markdown_path.resolve()),
        "surface_count": len(written),
        "file_count": len(written) * 2 + 2,
        "summary": index["summary"],
        "packs": written,
    }


def _find_surface(surface_id: str) -> dict[str, Any]:
    for surface in get_attack_surfaces():
        if surface["id"] == surface_id:
            return surface
    raise KeyError(surface_id)


def _runs_for_surface(runs: list[dict[str, Any]], surface_id: str, scenario_ids: set[str]) -> list[dict[str, Any]]:
    return [
        run
        for run in runs
        if run.get("scenario", {}).get("id") in scenario_ids
        or run.get("scenario", {}).get("surface_id") == surface_id
    ]


def _scenario_card(surface: dict[str, Any], scenario: dict[str, Any], runs: list[dict[str, Any]]) -> dict[str, Any]:
    scenario_runs = [run for run in runs if run.get("scenario", {}).get("id") == scenario["id"]]
    guarded_runs = [run for run in scenario_runs if run.get("guard_enabled")]
    unguarded_runs = [run for run in scenario_runs if not run.get("guard_enabled")]
    expectations = []
    for index, tool_call in enumerate(scenario.get("tool_calls", []), start=1):
        decision = decide(tool_call, True, scenario["adversarial_prompt"])
        expectations.append(
            {
                "step": index,
                "tool": tool_call["tool"],
                "risk_hint": tool_call.get("risk_hint", ""),
                "decision": decision.decision,
                "policy_id": decision.policy_id,
                "risk_level": decision.risk_level,
                "risk_score": decision.risk_score,
                "anomaly_score": decision.anomaly_score,
                "reason": decision.reason,
            }
        )
    return {
        "id": scenario["id"],
        "surface_id": surface["id"],
        "title": scenario["title"],
        "severity": scenario["severity"],
        "target": scenario["target"],
        "attack_path": scenario.get("attack_path", []),
        "detection_points": scenario.get("detection_points", []),
        "success_criteria": scenario.get("success_criteria", []),
        "safety_boundary": scenario.get("safety_boundary", "仅在本地沙箱受控实验环境复现。"),
        "tool_calls": scenario.get("tool_calls", []),
        "script_steps": scenario.get("script_steps", []),
        "expected_decisions": expectations,
        "latest_guarded_result": _latest_run_summary(guarded_runs),
        "latest_unguarded_result": _latest_run_summary(unguarded_runs),
    }


def _evidence_gaps(
    surface: dict[str, Any],
    scenario_cards: list[dict[str, Any]],
    summary: dict[str, Any],
    coverage_checks: dict[str, bool],
) -> list[dict[str, str]]:
    gaps: list[dict[str, str]] = []
    if not coverage_checks["has_surface_profile"]:
        gaps.append(
            {
                "severity": "high",
                "title": "攻击面画像不完整",
                "evidence": "入口、保护资产或检测信号字段缺失。",
                "action": "补齐攻击入口、保护资产、攻击目标和检测信号，避免只有脚本没有研究说明。",
            }
        )
    if summary["sample_count"] < max(3, summary["scenario_count"] * 3):
        gaps.append(
            {
                "severity": "medium",
                "title": "对抗样本数量偏少",
                "evidence": f"当前 {summary['sample_count']} 条样本，脚本 {summary['scenario_count']} 个。",
                "action": "为每个脚本保留原始输入、间接注入包装和多 Agent 转述包装。",
                "command": f"node scripts/agent-supervisor-cli.mjs samples --surface {surface['id']} --format md",
            }
        )
    if summary["run_count"] == 0:
        gaps.append(
            {
                "severity": "high",
                "title": "缺少运行证据",
                "evidence": "当前攻击面还没有写入实验运行记录。",
                "action": "在页面选择该攻击面并点击“验证当前攻击面”，或运行批量对比命令。",
                "command": "node scripts/agent-supervisor-cli.mjs batch --guard compare",
            }
        )
    if summary["guarded_run_count"] < summary["scenario_count"]:
        missing = summary["scenario_count"] - summary["guarded_run_count"]
        gaps.append(
            {
                "severity": "medium",
                "title": "有防护运行覆盖不足",
                "evidence": f"脚本 {summary['scenario_count']} 个，有防护运行记录 {summary['guarded_run_count']} 条，至少还需补 {max(0, missing)} 条。",
                "action": "对该攻击面的所有脚本执行有防护验证，补齐最近运行证据。",
            }
        )
    if summary["guarded_run_count"] and summary["control_rate"] < 100:
        gaps.append(
            {
                "severity": "high",
                "title": "防护控制率未达满分",
                "evidence": f"当前有防护控制率为 {summary['control_rate']}%。",
                "action": "检查未控制脚本的策略命中，补充规则或异常检测兜底。",
            }
        )
    missing_guarded = [
        card["id"]
        for card in scenario_cards
        if card["latest_guarded_result"]["status"] == "暂无运行证据"
    ]
    if missing_guarded:
        gaps.append(
            {
                "severity": "medium",
                "title": "部分脚本缺少最近有防护结果",
                "evidence": "缺少：" + " / ".join(missing_guarded[:5]),
                "action": "优先运行这些脚本，保证每张证据卡都有最近结果。",
            }
        )
    return gaps


def _latest_run_summary(runs: list[dict[str, Any]]) -> dict[str, Any]:
    if not runs:
        return {"status": "暂无运行证据", "run_id": "", "decision": "未记录", "policy_id": "未记录", "attack_success": None}
    run = sorted(runs, key=lambda item: item.get("created_at", ""), reverse=True)[0]
    first_log = (run.get("audit_logs") or [{}])[0]
    controlled = _is_controlled_run(run)
    return {
        "status": "已控制" if controlled else ("攻击成功" if run.get("attack_success") else "已运行"),
        "run_id": run.get("run_id", ""),
        "created_at": run.get("created_at", ""),
        "decision": first_log.get("decision", "未记录"),
        "policy_id": first_log.get("policy_id", "未记录"),
        "risk_score": first_log.get("risk_score"),
        "audit_hash": first_log.get("audit_hash", ""),
        "attack_success": run.get("attack_success"),
    }


def _is_controlled_run(run: dict[str, Any]) -> bool:
    metrics = run.get("metrics", {})
    return bool(metrics.get("blocked_count") or metrics.get("asked_count") or metrics.get("isolated_count"))


def _rate(numerator: list[Any], denominator: list[Any]) -> int:
    return round((len(numerator) / len(denominator)) * 100) if denominator else 0


def _threat_chain(surface: dict[str, Any], scenarios: list[dict[str, Any]], policies: Counter[str]) -> list[dict[str, str]]:
    first_scenario = scenarios[0] if scenarios else {}
    tools = sorted({tool_call["tool"] for scenario in scenarios for tool_call in scenario.get("tool_calls", [])})
    return [
        {"stage": "攻击入口", "text": " / ".join((surface.get("entry_points") or [])[:3]) or "待补充"},
        {"stage": "保护资产", "text": " / ".join((surface.get("protected_assets") or [])[:3]) or "待补充"},
        {"stage": "攻击目标", "text": " / ".join((surface.get("attacker_goals") or [])[:3]) or first_scenario.get("expected_risk", "待补充")},
        {"stage": "工具调用", "text": " / ".join(tools) or "待补充"},
        {"stage": "监督策略", "text": " / ".join(policy_id for policy_id, _ in policies.most_common(4)) or "待补充"},
        {"stage": "防御加固", "text": " / ".join((surface.get("mitigations") or [surface.get("defense", "")])[:3])},
    ]


def _replay_commands(surface_id: str, scenario_ids: list[str]) -> list[dict[str, str]]:
    return [
        {
            "label": "页面验证",
            "value": f"在攻击面研究台选择 {surface_id}，点击“验证当前攻击面”",
        },
        {
            "label": "批量对比 CLI",
            "value": "node scripts/agent-supervisor-cli.mjs batch --guard compare",
        },
        {
            "label": "攻击样本导出",
            "value": f"node scripts/agent-supervisor-cli.mjs samples --surface {surface_id} --format md --output apps/api/sandbox/reports/攻击样本-{surface_id}.md",
        },
        {
            "label": "证据包导出",
            "value": f"node scripts/agent-supervisor-cli.mjs surface-pack --surface {surface_id} --output apps/api/sandbox/reports",
        },
        {
            "label": "JSON API",
            "value": f"GET /api/attack_surfaces/{surface_id}/evidence_pack",
        },
        {
            "label": "Markdown API",
            "value": f"GET /api/attack_surfaces/{surface_id}/evidence_pack.md",
        },
        {
            "label": "关联脚本",
            "value": ", ".join(scenario_ids) or "暂无",
        },
    ]
