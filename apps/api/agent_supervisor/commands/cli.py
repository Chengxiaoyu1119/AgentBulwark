from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from apps.api.agent_supervisor.adapters.integrations.external_agent_demo import (
    run_managed_external_agent_demo,
    run_minimal_external_agent_demo,
)
from apps.api.agent_supervisor.adapters.integrations.openclaw_plugin_package import (
    write_openclaw_plugin_package,
    write_openclaw_plugin_validation_report,
)
from apps.api.agent_supervisor.domains.attacks.agents import compare_scenario, run_scenario
from apps.api.agent_supervisor.domains.attacks.attack_chains import (
    build_attack_chain_catalog_markdown,
    compare_attack_chain,
    list_attack_chains,
    run_attack_chain,
    write_attack_chain_report,
)
from apps.api.agent_supervisor.domains.evaluations.ablation import write_policy_ablation_report
from apps.api.agent_supervisor.domains.evaluations.assessment import build_attack_effectiveness
from apps.api.agent_supervisor.domains.evaluations.benign import build_benign_cases_markdown, evaluate_benign_cases
from apps.api.agent_supervisor.domains.evaluations.benign_workflows import (
    build_benign_workflow_markdown,
    evaluate_benign_workflows,
    write_benign_workflow_report,
)
from apps.api.agent_supervisor.domains.evaluations.calibration import write_anomaly_calibration_report
from apps.api.agent_supervisor.domains.evaluations.competition_benchmark import write_competition_benchmark_report
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
from apps.api.agent_supervisor.domains.evaluations.http_e2e_benchmark import write_http_e2e_benchmark_report
from apps.api.agent_supervisor.domains.evaluations.reproducibility_check import write_reproducibility_report
from apps.api.agent_supervisor.domains.governance.approvals import (
    build_approval_review_markdown,
    list_approval_reviews,
    write_approval_review_report,
)
from apps.api.agent_supervisor.domains.reports.readiness import (
    build_competition_readiness,
    build_competition_readiness_markdown,
    write_competition_readiness_report,
)
from apps.api.agent_supervisor.domains.reports.roadmap import write_project_roadmap
from apps.api.agent_supervisor.domains.reports.surface_pack import (
    write_all_surface_briefing_sheets,
    write_all_surface_evidence_packs,
    write_surface_briefing_sheet,
    write_surface_evidence_pack,
)
from apps.api.agent_supervisor.domains.runtime.events import evaluate_agent_event
from apps.api.agent_supervisor.domains.runtime.runtime_evaluation import write_real_model_evaluation_report
from apps.api.agent_supervisor.domains.runtime.tools import init_sandbox
from apps.api.agent_supervisor.storage.data import get_scenarios
from apps.api.agent_supervisor.storage.database import init_db, latest_runs, latest_scenario_run_pairs


def _competition_evidence_runs() -> list[dict[str, Any]]:
    return latest_scenario_run_pairs([scenario["id"] for scenario in get_scenarios()])


def cmd_run(args: argparse.Namespace) -> None:
    scenario = args.scenario or args.scenario_pos
    guard = args.guard or args.guard_pos or "on"
    if not scenario:
        raise SystemExit("缺少攻击脚本编号，例如：run TOOL-HIJACK-001 on")
    result = run_scenario(scenario, guard_enabled=guard == "on")
    print(json.dumps(_brief(result), ensure_ascii=False, indent=2))


def cmd_batch(args: argparse.Namespace) -> None:
    init_db()
    init_sandbox()
    outputs = []
    for scenario in get_scenarios():
        if args.guard == "compare":
            outputs.append(compare_scenario(scenario["id"]))
        else:
            outputs.append(run_scenario(scenario["id"], guard_enabled=args.guard == "on"))
    print(json.dumps(outputs, ensure_ascii=False, indent=2))


def cmd_export(args: argparse.Namespace) -> None:
    runs = latest_runs(50)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# 智安哨 CLI 实验导出",
        "",
        "| 时间 | 脚本 | 防护 | 攻击成功 | 阻断 | 询问 | 隔离 | 延迟 |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for run in runs:
        lines.append(
            f"| {run['created_at'][:19]} | {run['scenario']['id']} | {'开启' if run['guard_enabled'] else '关闭'} | {'是' if run['attack_success'] else '否'} | {run['metrics']['blocked_count']} | {run['metrics']['asked_count']} | {run['metrics']['isolated_count']} | {run['metrics']['detection_latency_ms']}ms |"
        )
    output.write_text("\n".join(lines), encoding="utf-8")
    print(f"已导出：{output}")


def cmd_samples(args: argparse.Namespace) -> None:
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    if args.format == "md":
        output.write_text(build_attack_case_markdown(args.surface), encoding="utf-8")
    else:
        output.write_text(json.dumps(build_attack_case_dataset(args.surface), ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"已导出攻击样本数据集：{output}")


def cmd_benign(args: argparse.Namespace) -> None:
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    if args.format == "md":
        output.write_text(build_benign_cases_markdown(args.category), encoding="utf-8")
    else:
        data = evaluate_benign_cases(args.category, guard_enabled=args.guard == "on")
        output.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"已导出正常业务任务样本误报评测：{output}")


def cmd_benign_workflows(args: argparse.Namespace) -> None:
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    if args.format == "md":
        output.write_text(build_benign_workflow_markdown(), encoding="utf-8")
    else:
        data = evaluate_benign_workflows(guard_enabled=args.guard == "on")
        output.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"已导出连续正常业务任务流程误报评测：{output}")


def cmd_benign_workflows_write(args: argparse.Namespace) -> None:
    result = write_benign_workflow_report(output_root=args.output)
    print(json.dumps(result, ensure_ascii=False, indent=2))


def cmd_conclusions(args: argparse.Namespace) -> None:
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    runs = latest_runs(50)
    if args.format == "md":
        output.write_text(build_surface_conclusions_markdown(runs), encoding="utf-8")
    else:
        output.write_text(json.dumps(build_surface_conclusions(runs), ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"已导出攻击面实验结论：{output}")


def cmd_output_filter(args: argparse.Namespace) -> None:
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    if args.format == "md":
        output.write_text(build_output_filter_markdown(), encoding="utf-8")
    else:
        output.write_text(json.dumps(build_output_filter_evidence(), ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"已导出模型输出过滤证据：{output}")


def cmd_assess(args: argparse.Namespace) -> None:
    if args.run_compare:
        for scenario in get_scenarios():
            compare_scenario(scenario["id"])
    data = build_attack_effectiveness(_competition_evidence_runs())
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    if args.format == "md":
        output.write_text(_attack_assessment_markdown(data), encoding="utf-8")
    else:
        output.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"已导出攻防有效性评测：{output}")


def cmd_attack_chains(args: argparse.Namespace) -> None:
    init_db()
    init_sandbox()
    output = Path(args.output)
    if args.write:
        result = write_attack_chain_report(output_root=output)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return

    if args.compare:
        data = compare_attack_chain(args.chain)
    elif args.run:
        data = run_attack_chain(args.chain, guard_enabled=args.guard == "on")
    else:
        data = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "chains": list_attack_chains(),
        }

    if output.suffix:
        output.parent.mkdir(parents=True, exist_ok=True)
        if args.format == "md":
            output.write_text(build_attack_chain_catalog_markdown(), encoding="utf-8")
        else:
            output.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"已导出组合攻击链评测：{output}")
        return

    output.mkdir(parents=True, exist_ok=True)
    if args.format == "md":
        path = output / "组合攻击链评测.md"
        path.write_text(build_attack_chain_catalog_markdown(), encoding="utf-8")
    else:
        path = output / "组合攻击链评测.json"
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"已导出组合攻击链评测：{path}")


def cmd_requirements(args: argparse.Namespace) -> None:
    data = build_attack_effectiveness(_competition_evidence_runs())["requirement_alignment"]
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    if args.format == "md":
        lines = [
            "# 功能验收对齐矩阵",
            "",
            "| 要求 | 状态 | 目标说明 | 当前证据 |",
            "|---|---|---|---|",
        ]
        for item in data:
            lines.append(f"| {item['requirement']} | {item['status']} | {item['expected']} | {item['evidence']} |")
        output.write_text("\n".join(lines), encoding="utf-8")
    else:
        output.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"已导出功能验收对齐矩阵：{output}")


def cmd_evaluate(args: argparse.Namespace) -> None:
    if args.input:
        event = json.loads(Path(args.input).read_text(encoding="utf-8"))
    elif args.json:
        event = json.loads(args.json)
    else:
        raise SystemExit("缺少事件输入，请使用 --input event.json 或 --json '{...}'")
    if isinstance(event, list):
        results = [
            evaluate_agent_event(
                item,
                guard_enabled=args.guard == "on",
                execute_in_sandbox=args.execute_in_sandbox,
            )
            for item in event
        ]
        controlled = [item for item in results if item["decision"] in {"拒绝", "询问", "隔离"}]
        result = {
            "total": len(results),
            "controlled": len(controlled),
            "control_rate": round((len(controlled) / len(results)) * 100) if results else 0,
            "results": results,
        }
    else:
        result = evaluate_agent_event(
            event,
            guard_enabled=args.guard == "on",
            execute_in_sandbox=args.execute_in_sandbox,
        )
    print(json.dumps(result, ensure_ascii=False, indent=2))


def cmd_demo_external(args: argparse.Namespace) -> None:
    input_path = Path(args.input)
    events = json.loads(input_path.read_text(encoding="utf-8"))
    if not isinstance(events, list):
        raise SystemExit("外部智能体演示文件必须是 JSON 数组。")
    results = [
        evaluate_agent_event(
            event,
            guard_enabled=args.guard == "on",
            execute_in_sandbox=args.execute_in_sandbox,
            review_scope="experiment",
        )
        for event in events
    ]
    controlled = [item for item in results if item["decision"] in {"拒绝", "询问", "隔离"}]
    result = {
        "source": str(input_path),
        "total": len(results),
        "controlled": len(controlled),
        "control_rate": round((len(controlled) / len(results)) * 100) if results else 0,
        "decisions": [
            {
                "tool": item["risk_evidence"]["tool"],
                "decision": item["decision"],
                "risk_score": item["risk_score"],
                "anomaly_score": item["anomaly_score"],
                "audit_hash": item["audit_log"].get("audit_hash"),
                "policy_id": item["policy_id"],
                "reason": item["reason"],
            }
            for item in results
        ],
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))


def cmd_external_agent_demo(args: argparse.Namespace) -> None:
    result = (
        run_managed_external_agent_demo(output_root=args.output)
        if args.managed_server
        else run_minimal_external_agent_demo(
            supervisor_url=args.supervisor_url,
            output_root=args.output,
            api_token=args.api_token,
        )
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))


def cmd_policy_ablation(args: argparse.Namespace) -> None:
    result = write_policy_ablation_report(output_root=args.output)
    print(json.dumps(result, ensure_ascii=False, indent=2))


def cmd_surface_pack(args: argparse.Namespace) -> None:
    result = write_surface_evidence_pack(surface_id=args.surface, output_root=args.output, runs=_competition_evidence_runs())
    print(json.dumps(result, ensure_ascii=False, indent=2))


def cmd_surface_packs(args: argparse.Namespace) -> None:
    result = write_all_surface_evidence_packs(output_root=args.output, runs=_competition_evidence_runs())
    print(json.dumps(result, ensure_ascii=False, indent=2))


def cmd_surface_brief(args: argparse.Namespace) -> None:
    result = write_surface_briefing_sheet(surface_id=args.surface, output_root=args.output, runs=_competition_evidence_runs())
    print(json.dumps(result, ensure_ascii=False, indent=2))


def cmd_surface_briefs(args: argparse.Namespace) -> None:
    result = write_all_surface_briefing_sheets(output_root=args.output, runs=_competition_evidence_runs())
    print(json.dumps(result, ensure_ascii=False, indent=2))


def cmd_roadmap(args: argparse.Namespace) -> None:
    result = write_project_roadmap(output_root=args.output, runs=_competition_evidence_runs())
    print(json.dumps(result, ensure_ascii=False, indent=2))


def cmd_anomaly_calibration(args: argparse.Namespace) -> None:
    result = write_anomaly_calibration_report(output_root=args.output, max_false_alarm_rate=args.max_false_alarm_rate)
    print(json.dumps(result, ensure_ascii=False, indent=2))


def cmd_real_model_eval(args: argparse.Namespace) -> None:
    result = write_real_model_evaluation_report(
        output_root=args.output,
        force_real=not args.local_only,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))


def cmd_competition_benchmark(args: argparse.Namespace) -> None:
    result = write_competition_benchmark_report(
        output_root=args.output,
        performance_repeats=args.repeats,
        concurrency=args.concurrency,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))


def cmd_repro_check(args: argparse.Namespace) -> None:
    result = write_reproducibility_report(
        output_root=args.output,
        trials=args.trials,
        operator=args.operator,
        operator_role=args.operator_role,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))


def cmd_http_e2e_benchmark(args: argparse.Namespace) -> None:
    result = write_http_e2e_benchmark_report(
        output_root=args.output,
        call_count=args.calls,
        concurrency=args.concurrency,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))


def cmd_openclaw_plugin(args: argparse.Namespace) -> None:
    result = write_openclaw_plugin_package(output_root=args.output, supervisor_url=args.supervisor_url)
    print(json.dumps(result, ensure_ascii=False, indent=2))


def cmd_openclaw_plugin_validate(args: argparse.Namespace) -> None:
    result = write_openclaw_plugin_validation_report(
        output_root=args.output,
        supervisor_url=args.supervisor_url,
        inspect_runtime=args.inspect_runtime,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))


def cmd_readiness(args: argparse.Namespace) -> None:
    if args.write:
        result = write_competition_readiness_report(output_root=args.output, runs=_competition_evidence_runs())
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return

    data = build_competition_readiness(_competition_evidence_runs())
    output = Path(args.output)
    if not output.suffix:
        output.mkdir(parents=True, exist_ok=True)
        output = output / ("赛前一键体检报告.md" if args.format == "md" else "赛前一键体检报告.json")
    output.parent.mkdir(parents=True, exist_ok=True)
    if args.format == "md":
        output.write_text(build_competition_readiness_markdown(data), encoding="utf-8")
    else:
        output.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"已导出赛前一键体检报告：{output}")


def cmd_approvals(args: argparse.Namespace) -> None:
    if args.write:
        result = write_approval_review_report(output_root=args.output)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return

    data = list_approval_reviews(status=args.status, limit=args.limit, scope=args.scope)
    output = Path(args.output)
    if output.suffix:
        output.parent.mkdir(parents=True, exist_ok=True)
        if args.format == "md":
            output.write_text(build_approval_review_markdown(data), encoding="utf-8")
        else:
            output.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"已导出人工复核队列报告：{output}")
        return

    output.mkdir(parents=True, exist_ok=True)
    if args.format == "md":
        path = output / "人工复核队列报告.md"
        path.write_text(build_approval_review_markdown(data), encoding="utf-8")
    else:
        path = output / "人工复核队列报告.json"
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"已导出人工复核队列报告：{path}")


def cmd_demo_drill(args: argparse.Namespace) -> None:
    data = run_judge_demo_drill(output_root=args.output) if args.run else load_judge_demo_drill_report(output_root=args.output)
    output = Path(args.output)
    if args.run:
        print(json.dumps(data, ensure_ascii=False, indent=2))
        return
    if output.suffix:
        output.parent.mkdir(parents=True, exist_ok=True)
        if args.format == "md":
            output.write_text(build_judge_demo_drill_markdown(data), encoding="utf-8")
        else:
            output.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"已导出答辩一键演示报告：{output}")
        return

    output.mkdir(parents=True, exist_ok=True)
    if args.format == "md":
        path = output / "答辩一键演示报告.md"
        path.write_text(build_judge_demo_drill_markdown(data), encoding="utf-8")
    else:
        path = output / "答辩一键演示报告.json"
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"已导出答辩一键演示报告：{path}")


def _brief(result: dict) -> dict:
    return {
        "run_id": result["run_id"],
        "scenario": result["scenario"]["id"],
        "guard_enabled": result["guard_enabled"],
        "attack_success": result["attack_success"],
        "metrics": result["metrics"],
        "decisions": [log["decision"] for log in result["audit_logs"]],
        "policies": [log["policy_id"] for log in result["audit_logs"]],
        "risk_scores": [log.get("risk_score") for log in result["audit_logs"]],
        "anomaly_scores": [log.get("anomaly_score") for log in result["audit_logs"]],
        "audit_hashes": [log.get("audit_hash") for log in result["audit_logs"]],
    }


def _attack_assessment_markdown(data: dict) -> str:
    summary = data["summary"]
    lines = [
        "# 攻防有效性评测",
        "",
        "该评测只基于真实运行记录统计，不把未运行脚本算作已验证。",
        "",
        "## 摘要",
        "",
        f"- 攻击脚本：{summary['scenario_count']}",
        f"- 无防护攻击复现率：{summary['attack_reproduced_rate']}%",
        f"- 有防护有效控制率：{summary['defense_effective_rate']}%",
        f"- 预期策略匹配率：{summary['expected_match_rate']}%",
        f"- 证据完整率：{summary['evidence_complete_rate']}%",
        "",
        "## 脚本矩阵",
        "",
        "| 脚本 | 攻击面 | 无防护复现 | 有防护控制 | 策略匹配 | 证据完整 | 缺口 |",
        "|---|---|---|---|---|---|---|",
    ]
    for case in data["cases"]:
        lines.append(
            "| {scenario} | {surface} | {attack} | {defense} | {match} | {complete} | {gaps} |".format(
                scenario=case["scenario_id"],
                surface=case["surface_name"],
                attack="是" if case["attack_reproduced_without_guard"] else "否",
                defense="是" if case["defense_effective_with_guard"] else "否",
                match="是" if case["expected_decision_match"] else "否",
                complete="是" if case["evidence_complete"] else "否",
                gaps="；".join(case["evidence_gaps"]) or "无",
            )
        )
    lines.extend(
        [
            "",
            "## 方向目标对齐",
            "",
            "| 要求 | 状态 | 当前证据 |",
            "|---|---|---|",
        ]
    )
    for item in data["requirement_alignment"]:
        lines.append(f"| {item['requirement']} | {item['status']} | {item['evidence']} |")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agent-supervisor", description="智安哨攻击脚本 CLI")
    sub = parser.add_subparsers(required=True)

    run = sub.add_parser("run", help="运行单个攻击脚本")
    run.add_argument("scenario_pos", nargs="?")
    run.add_argument("guard_pos", nargs="?", choices=["on", "off"])
    run.add_argument("--scenario")
    run.add_argument("--guard", choices=["on", "off"])
    run.set_defaults(func=cmd_run)

    batch = sub.add_parser("batch", help="批量运行攻击脚本")
    batch.add_argument("--guard", choices=["on", "off", "compare"], default="compare")
    batch.set_defaults(func=cmd_batch)

    export = sub.add_parser("export", help="导出实验报告素材")
    export.add_argument("--output", default="apps/api/sandbox/reports/实验结果.md")
    export.set_defaults(func=cmd_export)

    samples = sub.add_parser("samples", help="导出攻击样本、越狱用例和智能体脚本数据集")
    samples.add_argument("--output", default="apps/api/sandbox/reports/攻击样本与脚本数据集.json")
    samples.add_argument("--format", choices=["json", "md"], default="json")
    samples.add_argument("--surface", help="只导出指定攻击面，例如 prompt-injection、memory-poison")
    samples.set_defaults(func=cmd_samples)

    benign = sub.add_parser("benign", help="导出正常业务任务样本和误报率评测")
    benign.add_argument("--output", default="apps/api/sandbox/reports/正常业务任务误报评测.json")
    benign.add_argument("--format", choices=["json", "md"], default="json")
    benign.add_argument("--category", help="只评估指定正常业务任务类别，例如 API 调用、文件访问")
    benign.add_argument("--guard", choices=["on", "off"], default="on")
    benign.set_defaults(func=cmd_benign)

    benign_workflows = sub.add_parser("benign-workflows", help="导出连续正常业务任务流程误报评测")
    benign_workflows.add_argument("--output", default="apps/api/sandbox/reports/连续正常业务任务流程误报评测.json")
    benign_workflows.add_argument("--format", choices=["json", "md"], default="json")
    benign_workflows.add_argument("--guard", choices=["on", "off"], default="on")
    benign_workflows.set_defaults(func=cmd_benign_workflows)

    benign_workflows_write = sub.add_parser("benign-workflows-write", help="同时生成连续正常业务任务流程误报评测 JSON 和 Markdown")
    benign_workflows_write.add_argument("--output", default="apps/api/sandbox/reports")
    benign_workflows_write.set_defaults(func=cmd_benign_workflows_write)

    conclusions = sub.add_parser("conclusions", help="导出每类攻击面的实验结论")
    conclusions.add_argument("--output", default="apps/api/sandbox/reports/攻击面实验结论.md")
    conclusions.add_argument("--format", choices=["json", "md"], default="md")
    conclusions.set_defaults(func=cmd_conclusions)

    output_filter = sub.add_parser("output-filter", help="导出模型输出过滤前后对比证据")
    output_filter.add_argument("--output", default="apps/api/sandbox/reports/模型输出过滤证据.md")
    output_filter.add_argument("--format", choices=["json", "md"], default="md")
    output_filter.set_defaults(func=cmd_output_filter)

    assess = sub.add_parser("assess", help="导出攻防有效性评测矩阵")
    assess.add_argument("--output", default="apps/api/sandbox/reports/攻防有效性评测.md")
    assess.add_argument("--format", choices=["json", "md"], default="md")
    assess.add_argument("--run-compare", action="store_true", help="导出前先对全部脚本运行无防护/有防护对比")
    assess.set_defaults(func=cmd_assess)

    attack_chains = sub.add_parser("attack-chains", help="导出或运行多步组合攻击链")
    attack_chains.add_argument("--chain", default="multi-surface-exfiltration-chain", help="组合攻击链编号")
    attack_chains.add_argument("--guard", choices=["on", "off"], default="on")
    attack_chains.add_argument("--run", action="store_true", help="运行指定组合攻击链")
    attack_chains.add_argument("--compare", action="store_true", help="运行指定组合攻击链的无防护/有防护对比")
    attack_chains.add_argument("--write", action="store_true", help="同时生成组合攻击链 JSON 和 Markdown 目录报告")
    attack_chains.add_argument("--output", default="apps/api/sandbox/reports")
    attack_chains.add_argument("--format", choices=["json", "md"], default="json")
    attack_chains.set_defaults(func=cmd_attack_chains)

    requirements = sub.add_parser("requirements", help="导出功能验收对齐矩阵")
    requirements.add_argument("--output", default="apps/api/sandbox/reports/功能验收对齐矩阵.md")
    requirements.add_argument("--format", choices=["json", "md"], default="md")
    requirements.set_defaults(func=cmd_requirements)

    evaluate = sub.add_parser("evaluate", help="评估外部智能体工具调用事件")
    evaluate.add_argument("--input", help="事件 JSON 文件路径")
    evaluate.add_argument("--json", help="事件 JSON 字符串")
    evaluate.add_argument("--guard", choices=["on", "off"], default="on")
    evaluate.add_argument("--execute-in-sandbox", action="store_true", help="允许按监督决策在本地沙箱执行工具")
    evaluate.set_defaults(func=cmd_evaluate)

    demo_external = sub.add_parser("demo-external", help="运行 OpenClaw 兼容外部智能体事件演示")
    demo_external.add_argument("--input", default="apps/api/sandbox/examples/openclaw-like-events.json")
    demo_external.add_argument("--guard", choices=["on", "off"], default="on")
    demo_external.add_argument("--execute-in-sandbox", action="store_true", help="允许按监督决策在本地沙箱执行工具")
    demo_external.set_defaults(func=cmd_demo_external)

    external_agent_demo = sub.add_parser("external-agent-demo", help="运行最小外部 Agent 真实工具调度接入演示")
    external_agent_demo.add_argument("--supervisor-url", default="http://127.0.0.1:8012/api/runtime/evaluate")
    external_agent_demo.add_argument("--api-token", default="", help="监督接口 Bearer Token；本地免鉴权演示可留空")
    external_agent_demo.add_argument("--managed-server", action="store_true", help="自动启动隔离的Token/HMAC服务并在完成后关闭")
    external_agent_demo.add_argument("--output", default="apps/api/sandbox/reports")
    external_agent_demo.set_defaults(func=cmd_external_agent_demo)

    policy_ablation = sub.add_parser("policy-ablation", help="运行策略消融实验，验证关闭策略后的风险暴露和兜底控制")
    policy_ablation.add_argument("--output", default="apps/api/sandbox/reports")
    policy_ablation.set_defaults(func=cmd_policy_ablation)

    surface_pack = sub.add_parser("surface-pack", help="导出单个攻击面的证据包 JSON 与 Markdown")
    surface_pack.add_argument("--surface", required=True, help="攻击面编号，例如 prompt-injection、tool-hijack")
    surface_pack.add_argument("--output", default="apps/api/sandbox/reports")
    surface_pack.set_defaults(func=cmd_surface_pack)

    surface_packs = sub.add_parser("surface-packs", help="导出全部攻击面的证据包和索引")
    surface_packs.add_argument("--output", default="apps/api/sandbox/reports")
    surface_packs.set_defaults(func=cmd_surface_packs)

    surface_brief = sub.add_parser("surface-brief", help="导出单个攻击面的评测单页 HTML")
    surface_brief.add_argument("--surface", required=True, help="攻击面编号，例如 prompt-injection、tool-hijack")
    surface_brief.add_argument("--output", default="apps/api/sandbox/reports")
    surface_brief.set_defaults(func=cmd_surface_brief)

    surface_briefs = sub.add_parser("surface-briefs", help="导出全部攻击面的评测单页 HTML 和索引")
    surface_briefs.add_argument("--output", default="apps/api/sandbox/reports")
    surface_briefs.set_defaults(func=cmd_surface_briefs)

    roadmap = sub.add_parser("roadmap", help="导出项目成熟度与缺口路线图")
    roadmap.add_argument("--output", default="apps/api/sandbox/reports")
    roadmap.set_defaults(func=cmd_roadmap)

    anomaly_calibration = sub.add_parser("anomaly-calibration", help="导出异常检测阈值校准 JSON 与 Markdown")
    anomaly_calibration.add_argument("--output", default="apps/api/sandbox/reports")
    anomaly_calibration.add_argument("--max-false-alarm-rate", type=int, default=10, help="允许的正常业务任务误报率上限，默认 10%")
    anomaly_calibration.set_defaults(func=cmd_anomaly_calibration)

    real_model_eval = sub.add_parser("real-model-eval", help="运行真实模型结构化工具调用盲测并生成报告")
    real_model_eval.add_argument("--output", default="apps/api/sandbox/reports")
    real_model_eval.add_argument("--local-only", action="store_true", help="只运行本地模拟规划器，不调用已配置的真实模型")
    real_model_eval.set_defaults(func=cmd_real_model_eval)

    competition_benchmark = sub.add_parser("competition-benchmark", help="运行200条冻结集、四组基线与性能评测")
    competition_benchmark.add_argument("--output", default="apps/api/sandbox/reports")
    competition_benchmark.add_argument("--repeats", type=int, default=10, help="性能评测重复轮数，默认10")
    competition_benchmark.add_argument("--concurrency", type=int, default=20, help="并发工作线程，默认20")
    competition_benchmark.set_defaults(func=cmd_competition_benchmark)

    repro_check = sub.add_parser("repro-check", help="重复运行冻结评测与通用Agent链路，生成独立复现一致性报告")
    repro_check.add_argument("--output", default="apps/api/sandbox/reports")
    repro_check.add_argument("--trials", type=int, default=3, help="重复运行轮数，默认3")
    repro_check.add_argument("--operator", default="未填写", help="复现者姓名或标识")
    repro_check.add_argument("--operator-role", default="未填写", help="复现者身份，例如作者、同学或指导教师")
    repro_check.set_defaults(func=cmd_repro_check)

    http_e2e_benchmark = sub.add_parser("http-e2e-benchmark", help="运行 HTTP、Token、SQLite 与审计完整链路性能评测")
    http_e2e_benchmark.add_argument("--output", default="apps/api/sandbox/reports")
    http_e2e_benchmark.add_argument("--calls", type=int, default=200, help="请求数量，默认200")
    http_e2e_benchmark.add_argument("--concurrency", type=int, default=20, help="并发工作线程，默认20")
    http_e2e_benchmark.set_defaults(func=cmd_http_e2e_benchmark)

    openclaw_plugin = sub.add_parser("openclaw-plugin", help="生成可安装到 OpenClaw 的源码级 native plugin 包")
    openclaw_plugin.add_argument("--output", default="apps/api/sandbox/reports")
    openclaw_plugin.add_argument("--supervisor-url", default="http://127.0.0.1:8012/api/integrations/openclaw/events")
    openclaw_plugin.set_defaults(func=cmd_openclaw_plugin)

    openclaw_plugin_validate = sub.add_parser("openclaw-plugin-validate", help="生成 OpenClaw 插件包并执行静态/可选 runtime 验收")
    openclaw_plugin_validate.add_argument("--output", default="apps/api/sandbox/reports")
    openclaw_plugin_validate.add_argument("--supervisor-url", default="http://127.0.0.1:8012/api/integrations/openclaw/events")
    openclaw_plugin_validate.add_argument("--inspect-runtime", action="store_true", help="如果当前环境已安装 OpenClaw CLI，则执行 runtime inspect")
    openclaw_plugin_validate.set_defaults(func=cmd_openclaw_plugin_validate)

    readiness = sub.add_parser("readiness", help="运行赛前一键体检，检查攻击面、误报、OpenClaw、截图和提交包")
    readiness.add_argument("--output", default="apps/api/sandbox/reports/赛前一键体检报告.json")
    readiness.add_argument("--format", choices=["json", "md"], default="json")
    readiness.add_argument("--write", action="store_true", help="同时生成 JSON 和 Markdown 报告")
    readiness.set_defaults(func=cmd_readiness)

    approvals = sub.add_parser("approvals", help="导出人工复核队列与审批闭环报告")
    approvals.add_argument("--output", default="apps/api/sandbox/reports")
    approvals.add_argument("--format", choices=["json", "md"], default="json")
    approvals.add_argument("--status", default="全部", help="全部、待复核、已批准或已驳回")
    approvals.add_argument("--scope", default="全部", help="全部、operational、experiment 或 demo")
    approvals.add_argument("--limit", type=int, default=100)
    approvals.add_argument("--write", action="store_true", help="同时生成 JSON 和 Markdown 报告")
    approvals.set_defaults(func=cmd_approvals)

    demo_drill = sub.add_parser("demo-drill", help="运行或导出答辩一键演示报告")
    demo_drill.add_argument("--output", default="apps/api/sandbox/reports")
    demo_drill.add_argument("--format", choices=["json", "md"], default="json")
    demo_drill.add_argument("--run", action="store_true", help="实际运行四步答辩演示，并生成 JSON 与 Markdown 报告")
    demo_drill.set_defaults(func=cmd_demo_drill)
    return parser


def main() -> None:
    init_db()
    init_sandbox()
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
