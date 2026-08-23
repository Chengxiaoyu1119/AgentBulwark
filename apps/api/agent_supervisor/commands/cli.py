from __future__ import annotations

import argparse
import hashlib
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
from typing import Any
from uuid import uuid4

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
from apps.api.agent_supervisor.domains.governance.redaction import redact_sensitive
from apps.api.agent_supervisor.domains.reports.gateway_evidence import (
    gateway_code_fingerprint,
    gateway_evidence_fingerprint,
    gateway_evidence_snapshot,
    gateway_source_fingerprint,
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
from apps.api.agent_supervisor.domains.runtime.server_security import load_environment_file
from apps.api.agent_supervisor.domains.runtime.tools import init_sandbox
from apps.api.agent_supervisor.storage.data import get_scenarios
from apps.api.agent_supervisor.storage.database import init_db, latest_runs, latest_scenario_run_pairs


def _cli_secret(value: str | None, env_name: str | None = None) -> str:
    """Resolve a CLI credential without requiring it in the process argv.

    ``--api-token`` remains for backwards compatibility, while the ``*-env``
    flags let operators keep the secret in an environment variable so it does
    not appear in process listings or shell history.
    """

    direct = str(value or "").strip()
    if direct:
        return direct
    variable = str(env_name or "").strip()
    if variable and (not variable.replace("_", "").isalnum() or variable[0].isdigit()):
        raise SystemExit("Token 环境变量名格式无效。")
    return (os.getenv(variable) or "").strip() if variable else ""


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
    api_token = _cli_secret(args.api_token, getattr(args, "api_token_env", ""))
    result = (
        run_managed_external_agent_demo(output_root=args.output)
        if args.managed_server
        else run_minimal_external_agent_demo(
            supervisor_url=args.supervisor_url,
            output_root=args.output,
            api_token=api_token,
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


def cmd_gateway_probe(args: argparse.Namespace) -> None:
    """Send a caller-authored OpenAI payload to the local security gateway.

    This is an operational probe, not a simulated scenario runner: the payload
    crosses the configured HTTP boundary and the result records the real status
    and gateway metadata.  Evidence is redacted before it is written.
    """
    api_token = _cli_secret(args.api_token, getattr(args, "api_token_env", ""))
    raw_payload = ""
    if args.payload_file:
        raw_payload = Path(args.payload_file).read_text(encoding="utf-8")
    elif args.json:
        raw_payload = args.json
    else:
        raise SystemExit("请提供 --payload-file 或 --json。")
    try:
        payload = json.loads(raw_payload)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"请求 JSON 无效：{exc}") from exc
    if not isinstance(payload, dict):
        raise SystemExit("OpenAI 网关请求必须是 JSON 对象。")

    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str, separators=(",", ":"))
    request_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if api_token:
        headers["Authorization"] = f"Bearer {api_token}"
    if args.session_id:
        headers["X-Agent-Session-ID"] = args.session_id
    request = urllib.request.Request(
        args.url,
        data=canonical.encode("utf-8"),
        headers=headers,
        method="POST",
    )
    status = 0
    response_payload: Any = None
    transport_error = ""
    try:
        with urllib.request.urlopen(request, timeout=args.timeout) as response:
            status = int(response.status)
            body = response.read().decode("utf-8", errors="replace")
            try:
                response_payload = json.loads(body)
            except json.JSONDecodeError:
                response_payload = {"raw_body_excerpt": body[:4000]}
    except urllib.error.HTTPError as exc:
        status = int(exc.code)
        body = exc.read().decode("utf-8", errors="replace")
        try:
            response_payload = json.loads(body)
        except json.JSONDecodeError:
            response_payload = {"raw_body_excerpt": body[:4000]}
    except (OSError, urllib.error.URLError, TimeoutError) as exc:
        transport_error = str(exc)

    metadata = response_payload.get("agent_supervisor", {}) if isinstance(response_payload, dict) else {}
    contract = _gateway_contract_evidence(
        status=status,
        request_hash=request_hash,
        response_payload=response_payload,
    )
    local_snapshot = gateway_evidence_snapshot()
    server_fingerprint = str(metadata.get("gateway_evidence_fingerprint") or "") if isinstance(metadata, dict) else ""
    server_source_fingerprint = (
        str(metadata.get("gateway_source_fingerprint") or "") if isinstance(metadata, dict) else ""
    )
    server_code_fingerprint = (
        str(metadata.get("gateway_code_fingerprint") or "") if isinstance(metadata, dict) else ""
    )
    result = {
        "schema_version": "agent-supervisor.gateway-probe.v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "probe_source": "agent-supervisor-cli.gateway-probe",
        # The server is the authority for the runtime fingerprint.  The
        # client-side snapshot is retained only as local reproducibility
        # context; it is not substituted for the running process' identity.
        "gateway_evidence_fingerprint": server_fingerprint or gateway_evidence_fingerprint(local_snapshot),
        "gateway_source_fingerprint": server_source_fingerprint or gateway_source_fingerprint(local_snapshot),
        "gateway_code_fingerprint": server_code_fingerprint or gateway_code_fingerprint(local_snapshot),
        "client_gateway_evidence_fingerprint": gateway_evidence_fingerprint(local_snapshot),
        "gateway_evidence_snapshot": local_snapshot,
        "gateway_evidence_snapshot_scope": "client-process",
        "endpoint": args.url,
        "http_status": status,
        "transport_error": transport_error,
        "request_hash": request_hash,
        "request_shape": {
            "model": str(payload.get("model") or ""),
            "message_count": len(payload.get("messages", [])) if isinstance(payload.get("messages"), list) else 0,
            "tool_count": len(payload.get("tools", [])) if isinstance(payload.get("tools"), list) else 0,
            "stream": bool(payload.get("stream", False)),
        },
        "contract": contract,
        "gateway": redact_sensitive(metadata),
        "response": redact_sensitive(response_payload),
    }
    output = Path(args.output)
    if output.suffix.lower() != ".json":
        output.mkdir(parents=True, exist_ok=True)
        output = output / _timestamped_probe_name("LLM网关探针")
    else:
        output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({**result, "output": str(output.resolve())}, ensure_ascii=False, indent=2))
    if getattr(args, "strict", False) and result["contract"].get("passed") is not True:
        raise SystemExit("gateway-probe contract did not pass")


def cmd_mcp_probe(args: argparse.Namespace) -> None:
    """Exercise the real MCP HTTP boundary and persist only protocol evidence.

    The probe never calls an upstream process directly.  It sends initialize,
    tools/list and one explicitly selected tools/call through ``/api/mcp`` so
    the artifact proves the HTTP gateway, tool directory filtering, execution
    audit reference and result context scan were actually exercised.  When an
    operator token is supplied, it also reads the authenticated management
    projections for tools and context using the same Agent/session scope; the
    report stores counts and response digests, never the operator payload.
    """

    api_token = _cli_secret(args.api_token, getattr(args, "api_token_env", ""))
    operator_api_token = _cli_secret(
        getattr(args, "operator_api_token", ""),
        getattr(args, "operator_api_token_env", ""),
    )
    operator_agent_id = _safe_header_value(str(getattr(args, "operator_agent_id", "") or "").strip())
    endpoint = str(args.url or "").strip()
    if not endpoint:
        raise SystemExit("缺少 MCP Gateway URL。")
    session_id = _safe_header_value(str(args.session_id or "mcp-probe-session"))
    base_url = _mcp_base_url(endpoint)
    info = _send_mcp_http_json(
        f"{base_url}/api/mcp/info",
        api_token=api_token,
        session_id=session_id,
        timeout=args.timeout,
    )
    runtime = _send_mcp_http_json(
        f"{base_url}/api/runtime_status",
        api_token=api_token,
        session_id=session_id,
        timeout=args.timeout,
    )
    initialize_payload = {
        "jsonrpc": "2.0",
        "id": "mcp-probe-initialize",
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "zhi-an-sentinel-probe", "version": "1"},
        },
    }
    tools_list_payload = {
        "jsonrpc": "2.0",
        "id": "mcp-probe-tools-list",
        "method": "tools/list",
        "params": {},
    }
    initialize = _send_mcp_http_json(
        endpoint,
        payload=initialize_payload,
        api_token=api_token,
        session_id=session_id,
        timeout=args.timeout,
    )
    tools_list = _send_mcp_http_json(
        endpoint,
        payload=tools_list_payload,
        api_token=api_token,
        session_id=session_id,
        timeout=args.timeout,
    )
    tools_result = tools_list.get("response_payload")
    result_object = tools_result.get("result") if isinstance(tools_result, dict) else None
    raw_visible_tools = result_object.get("tools") if isinstance(result_object, dict) else []
    visible_tools: list[Any] = raw_visible_tools if isinstance(raw_visible_tools, list) else []
    sentinel = result_object.get("zhiAnSentinel") if isinstance(result_object, dict) else {}
    scan_summary = sentinel.get("scanSummary") if isinstance(sentinel, dict) else {}
    scan_summary = scan_summary if isinstance(scan_summary, dict) else {}
    visible_names = [
        str(item.get("name") or "")
        for item in visible_tools
        if isinstance(item, dict) and str(item.get("name") or "")
    ]
    raw_quarantined_tools = sentinel.get("quarantinedTools") if isinstance(sentinel, dict) else []
    quarantined_tools: list[Any] = raw_quarantined_tools if isinstance(raw_quarantined_tools, list) else []
    quarantined_names = [
        str(item.get("name") or "")
        for item in quarantined_tools
        if isinstance(item, dict) and str(item.get("name") or "")
    ]
    legacy_filtered_tools = sentinel.get("filteredTools") if isinstance(sentinel, dict) else []
    legacy_filtered_count = len(legacy_filtered_tools) if isinstance(legacy_filtered_tools, list) else 0
    reported_filtered_count = sentinel.get("filtered_tool_count") if isinstance(sentinel, dict) else None
    filtered_count = (
        reported_filtered_count
        if isinstance(reported_filtered_count, int) and not isinstance(reported_filtered_count, bool) and reported_filtered_count >= 0
        else legacy_filtered_count
    )
    reported_quarantined_count = sentinel.get("quarantined_tool_count") if isinstance(sentinel, dict) else None
    quarantined_count = (
        reported_quarantined_count
        if isinstance(reported_quarantined_count, int) and not isinstance(reported_quarantined_count, bool) and reported_quarantined_count >= 0
        else len(quarantined_names)
    )
    requested_tool = str(args.tool or "").strip()
    call_response: dict[str, Any] | None = None
    if requested_tool:
        try:
            call_arguments = json.loads(args.arguments or "{}")
        except json.JSONDecodeError as exc:
            raise SystemExit(f"MCP 工具参数 JSON 无效：{exc}") from exc
        if not isinstance(call_arguments, dict):
            raise SystemExit("--arguments 必须是 JSON 对象。")
        call_payload = {
            "jsonrpc": "2.0",
            "id": "mcp-probe-tools-call",
            "method": "tools/call",
            "params": {"name": requested_tool, "arguments": call_arguments},
        }
        call_response = _send_mcp_http_json(
            endpoint,
            payload=call_payload,
            api_token=api_token,
            session_id=session_id,
            timeout=args.timeout,
        )

    operator_evidence: dict[str, Any] = {
        "requested": bool(operator_api_token),
        "agent_id": operator_agent_id,
        "tools_endpoint": _public_endpoint(f"{base_url}/api/mcp/tools/evidence"),
        "context_endpoint": _public_endpoint(f"{base_url}/api/mcp/context/evidence"),
        "tools": None,
        "context": None,
    }
    if operator_api_token:
        query = urllib.parse.urlencode({"agent_id": operator_agent_id}) if operator_agent_id else ""
        suffix = f"?{query}" if query else ""
        tools_evidence_response = _send_mcp_http_json(
            f"{base_url}/api/mcp/tools/evidence{suffix}",
            api_token=operator_api_token,
            session_id=session_id,
            timeout=args.timeout,
        )
        context_evidence_response = _send_mcp_http_json(
            f"{base_url}/api/mcp/context/evidence{suffix}",
            api_token=operator_api_token,
            session_id=session_id,
            timeout=args.timeout,
        )
        operator_evidence["tools"] = _mcp_operator_evidence_contract(
            tools_evidence_response,
            kind="tools",
            require_active=bool(operator_agent_id),
        )
        operator_evidence["context"] = _mcp_operator_evidence_contract(
            context_evidence_response,
            kind="context",
            require_active=bool(operator_agent_id),
        )

    operator_evidence_passed = (
        None
        if not operator_api_token
        else bool(
            isinstance(operator_evidence.get("tools"), dict)
            and operator_evidence["tools"].get("passed") is True
            and isinstance(operator_evidence.get("context"), dict)
            and operator_evidence["context"].get("passed") is True
        )
    )

    runtime_payload = runtime.get("response_payload")
    runtime_evidence = runtime_payload.get("gateway_evidence", {}) if isinstance(runtime_payload, dict) else {}
    runtime_mcp = runtime_payload.get("mcp", {}) if isinstance(runtime_payload, dict) else {}
    expected_decision = str(args.expected_decision or "允许").strip()
    init_payload = initialize.get("response_payload")
    init_result = init_payload.get("result") if isinstance(init_payload, dict) else None
    list_ok = tools_list["http_status"] == 200 and isinstance(result_object, dict) and isinstance(visible_tools, list)
    init_ok = initialize["http_status"] == 200 and isinstance(init_result, dict)
    quarantine_ok = all(name not in visible_names for name in quarantined_names)
    call_contract = _mcp_call_contract(call_response, expected_decision=expected_decision)
    server_source_fingerprint = str(runtime_evidence.get("source_fingerprint") or "")
    server_fingerprint = str(runtime_evidence.get("fingerprint") or "")
    server_code_fingerprint = str(runtime_evidence.get("code_fingerprint") or "")
    contract = {
        "passed": bool(
            init_ok
            and list_ok
            and quarantine_ok
            and (call_contract["passed"] if requested_tool else True)
            and (not runtime_payload or bool(server_fingerprint))
            and (operator_evidence_passed is not False)
        ),
        "initialize_ok": init_ok,
        "tools_list_ok": list_ok,
        "quarantine_not_visible": quarantine_ok,
        "tool_call": call_contract,
        "gateway_runtime_fingerprint_present": bool(server_fingerprint),
        "gateway_source_fingerprint_present": bool(server_source_fingerprint),
        "operator_evidence_requested": bool(operator_api_token),
        "operator_evidence_passed": operator_evidence_passed,
    }
    local_snapshot = gateway_evidence_snapshot()
    report = {
        "schema_version": "agent-supervisor.mcp-probe.v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": "agent-supervisor-cli.mcp-probe",
        "evidence_scope": "real-http-mcp-gateway",
        "endpoint": _public_endpoint(endpoint),
        "info_endpoint": _public_endpoint(f"{base_url}/api/mcp/info"),
        "runtime_endpoint": _public_endpoint(f"{base_url}/api/runtime_status"),
        "session_id_hash": hashlib.sha256(session_id.encode("utf-8")).hexdigest(),
        "gateway_evidence_fingerprint": server_fingerprint or gateway_evidence_fingerprint(local_snapshot),
        "gateway_source_fingerprint": server_source_fingerprint or gateway_source_fingerprint(local_snapshot),
        "gateway_code_fingerprint": server_code_fingerprint or gateway_code_fingerprint(local_snapshot),
        "client_gateway_evidence_fingerprint": gateway_evidence_fingerprint(local_snapshot),
        "gateway_evidence_snapshot": local_snapshot,
        "gateway_evidence_snapshot_scope": "client-process",
        "runtime": {
            "http_status": runtime["http_status"],
            "transport_error": runtime["transport_error"],
            "mcp": redact_sensitive(runtime_mcp),
            "gateway_evidence": redact_sensitive(runtime_evidence),
        },
        "info": {
            "http_status": info["http_status"],
            "transport_error": info["transport_error"],
            "enabled": bool((info.get("response_payload") or {}).get("enabled"))
            if isinstance(info.get("response_payload"), dict)
            else False,
            "guard_enabled": bool((info.get("response_payload") or {}).get("guard_enabled"))
            if isinstance(info.get("response_payload"), dict)
            else False,
            "routes": list((info.get("response_payload") or {}).get("routes") or [])
            if isinstance(info.get("response_payload"), dict)
            else [],
        },
        "requests": {
            "initialize": {"http_status": initialize["http_status"], "request_hash": initialize["request_hash"]},
            "tools_list": {"http_status": tools_list["http_status"], "request_hash": tools_list["request_hash"]},
            "tools_call": (
                {"http_status": call_response["http_status"], "request_hash": call_response["request_hash"]}
                if call_response
                else None
            ),
        },
        "tool_inventory": {
            "visible_names": visible_names,
            "quarantined_names": quarantined_names,
            "filtered_count": filtered_count,
            "quarantined_count": quarantined_count,
            "scan_summary": redact_sensitive(scan_summary),
        },
        "tool_call": call_contract,
        "operator_evidence": operator_evidence,
        "contract": contract,
        "summary": {
            "initialize_ok": init_ok,
            "tools_list_ok": list_ok,
            "visible_tool_count": len(visible_names),
            "quarantined_tool_count": quarantined_count,
            "filtered_tool_count": filtered_count,
            "scanned_tool_count": scan_summary.get("scanned_tool_count")
            if isinstance(scan_summary.get("scanned_tool_count"), int)
            else 0,
            "scanner_quarantined_tool_count": scan_summary.get("quarantined_tool_count")
            if isinstance(scan_summary.get("quarantined_tool_count"), int)
            else 0,
            "scanner_warning_tool_count": scan_summary.get("warning_tool_count")
            if isinstance(scan_summary.get("warning_tool_count"), int)
            else 0,
            "tool_call_requested": bool(requested_tool),
            "tool_call_passed": call_contract["passed"] if requested_tool else None,
            "tool_call_decision": call_contract["decision"],
            "audit_id_present": call_contract["audit_id_present"],
            "operator_evidence_requested": bool(operator_api_token),
            "operator_evidence_passed": operator_evidence_passed,
            "evidence_verdict": "complete" if contract["passed"] else "partial",
        },
    }
    output = Path(args.output)
    if output.suffix.lower() != ".json":
        output.mkdir(parents=True, exist_ok=True)
        output = output / _timestamped_probe_name("MCP网关探针")
    else:
        output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"output": str(output.resolve()), "summary": report["summary"]}, ensure_ascii=False, indent=2))
    # Keep the typed local contract as the source of truth.  Indexing the
    # heterogeneous report envelope makes mypy infer a Collection[str] for
    # ``report["contract"]`` and, more importantly, couples the strict exit
    # decision to the JSON serialization shape.
    if getattr(args, "strict", False) and contract.get("passed") is not True:
        raise SystemExit("mcp-probe contract did not pass")


def _mcp_operator_evidence_contract(
    response: dict[str, Any],
    *,
    kind: str,
    require_active: bool,
) -> dict[str, Any]:
    """Validate an operator MCP projection without persisting its payload.

    The management endpoints intentionally contain capability names, routes
    and scanner signals.  A probe artifact should prove that the authenticated
    projection was read and session-bound, while keeping those details out of a
    generally shareable evidence file.
    """

    payload = response.get("response_payload")
    payload_hash = ""
    if payload is not None:
        payload_hash = hashlib.sha256(
            json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
        ).hexdigest()
    expected_schema = (
        "mcp-tools-operator-inventory.v1"
        if kind == "tools"
        else "mcp-context-operator-inventory.v1"
    )
    payload_dict = payload if isinstance(payload, dict) else {}
    raw_summary = payload_dict.get("summary")
    summary: dict[str, Any] = raw_summary if isinstance(raw_summary, dict) else {}
    session_scope = str(payload_dict.get("session_scope") or "")
    active = summary.get("active") is True
    session_hash_present = len(str(payload_dict.get("session_hash") or "")) == 64
    summary_keys = (
        (
            "catalog_tool_count",
            "visible_tool_count",
            "filtered_tool_count",
            "quarantined_tool_count",
            "projection_blocked_tool_count",
            "conflict_count",
        )
        if kind == "tools"
        else (
            "catalog_entry_count",
            "visible_context_count",
            "filtered_context_count",
            "conflict_count",
            "failed_route_count",
        )
    )
    safe_summary = {
        key: summary[key]
        for key in summary_keys
        if isinstance(summary.get(key), int) and not isinstance(summary.get(key), bool)
    }
    passed = bool(
        response.get("http_status") == 200
        and not response.get("transport_error")
        and payload_dict.get("schema_version") == expected_schema
        and session_scope in {"agent+session", "gateway-shared"}
        and (not require_active or (active and session_hash_present))
    )
    return {
        "passed": passed,
        "http_status": response.get("http_status", 0),
        "transport_error": str(response.get("transport_error") or "")[:200],
        "schema_version": str(payload_dict.get("schema_version") or ""),
        "session_scope": session_scope,
        "active": active,
        "session_hash_present": session_hash_present,
        "summary": safe_summary,
        "response_hash": payload_hash,
    }


def _mcp_base_url(endpoint: str) -> str:
    parsed = urllib.parse.urlsplit(endpoint)
    path = parsed.path.rstrip("/")
    suffix = "/api/mcp"
    if path.endswith(suffix):
        path = path[: -len(suffix)]
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, path.rstrip("/"), "", "")) or endpoint.rstrip("/")


def _send_mcp_http_json(
    url: str,
    *,
    payload: dict[str, Any] | None = None,
    api_token: str,
    session_id: str,
    timeout: float,
) -> dict[str, Any]:
    body = b""
    headers = {"Accept": "application/json"}
    if payload is not None:
        body = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if api_token:
        headers["Authorization"] = f"Bearer {api_token}"
    if session_id:
        headers["X-Agent-Session-ID"] = _safe_header_value(session_id)
    request = urllib.request.Request(url, data=body or None, headers=headers, method="POST" if payload is not None else "GET")
    started = perf_counter()
    status = 0
    response_payload: Any = None
    transport_error = ""
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status = int(response.status)
            response_payload = _decode_gateway_body(response.read())
    except urllib.error.HTTPError as exc:
        status = int(exc.code)
        response_payload = _decode_gateway_body(exc.read())
    except (OSError, urllib.error.URLError, TimeoutError) as exc:
        transport_error = redact_sensitive(str(exc))[:500]
    return {
        "http_status": status,
        "response_payload": response_payload,
        "transport_error": transport_error,
        "duration_ms": round((perf_counter() - started) * 1000, 3),
        "request_hash": hashlib.sha256(body).hexdigest() if body else "",
    }


def _mcp_call_contract(response: dict[str, Any] | None, *, expected_decision: str) -> dict[str, Any]:
    if not response:
        return {
            "passed": False,
            "decision": "未执行",
            "is_error": None,
            "audit_id_present": False,
            "context_scan_present": False,
            "response_error": "未请求 tools/call",
        }
    payload = response.get("response_payload")
    result = payload.get("result") if isinstance(payload, dict) else None
    error = payload.get("error") if isinstance(payload, dict) else None
    error_data = error.get("data") if isinstance(error, dict) else None
    if not isinstance(error_data, dict):
        error_data = None
    sentinel = result.get("zhiAnSentinel") if isinstance(result, dict) else None
    if not isinstance(sentinel, dict) and isinstance(error_data, dict):
        sentinel = error_data.get("zhiAnSentinel")
    if not isinstance(sentinel, dict):
        sentinel = None
    structured = result.get("structuredContent") if isinstance(result, dict) else None
    if not isinstance(structured, dict) and error_data is not None:
        structured = error_data
    raw_decision = (
        (structured or {}).get("decision")
        if isinstance(structured, dict)
        else (sentinel or {}).get("decision")
        if isinstance(sentinel, dict)
        else "拒绝"
        if isinstance(error, dict)
        else "允许"
    )
    decision = str(raw_decision or "允许")
    is_error = bool(result.get("isError")) if isinstance(result, dict) else bool(error)
    audit_id = ""
    if isinstance(sentinel, dict):
        audit_id = str(sentinel.get("audit_id") or sentinel.get("intent_audit_id") or "")
    if isinstance(structured, dict) and not audit_id:
        audit_id = str(structured.get("audit_id") or "")
    expected_control = expected_decision in {"拒绝", "询问", "隔离"}
    expected_ok = (decision == expected_decision) if expected_decision else True
    execution_ok = (is_error is False) if not expected_control else (is_error is True)
    return {
        "passed": response["http_status"] == 200 and not response["transport_error"] and expected_ok and execution_ok and bool(audit_id),
        "http_status": response["http_status"],
        "decision": decision,
        "expected_decision": expected_decision,
        "is_error": is_error,
        "audit_id_present": bool(audit_id),
        "audit_id": audit_id,
        "context_scan_present": isinstance((sentinel or {}).get("contextScan") if isinstance(sentinel, dict) else None, dict),
        "response_error": _response_error_summary(payload),
    }


def cmd_gateway_agent_run(args: argparse.Namespace) -> None:
    """Run caller-supplied Agent requests through the real HTTP gateway.

    This command intentionally does not call the local supervisor directly,
    invent tool calls, or execute a fixture as an attack substitute.  Every
    case is an OpenAI-compatible request crossing ``/v1/chat/completions``;
    the report stores only hashes, protocol facts and redacted gateway
    metadata so it can be used as an auditable runtime evidence artifact.
    """

    api_token = _cli_secret(args.api_token, getattr(args, "api_token_env", ""))
    baseline_api_token = _cli_secret(
        getattr(args, "baseline_api_token", ""),
        getattr(args, "baseline_api_token_env", ""),
    )
    cases = _load_gateway_agent_cases(args)
    if not cases:
        raise SystemExit("输入中没有可运行的 cases。")

    rows: list[dict[str, Any]] = []
    baseline_url = str(getattr(args, "baseline_url", "") or "").strip()
    causal_url = str(getattr(args, "causal_url", "") or "").strip()
    if baseline_url and _public_endpoint(baseline_url) == _public_endpoint(args.url):
        raise SystemExit("--baseline-url 必须指向未经过智安哨的 Provider 地址，且不得与网关 URL 相同。")
    if causal_url and _public_endpoint(causal_url) == _public_endpoint(args.url):
        raise SystemExit("--causal-url 必须指向网关的 /api/gateway/compare 地址。")
    for index, case in enumerate(cases):
        case_id = str(case.get("id") or f"case-{index + 1}").strip()[:120]
        payload = case.get("payload")
        if not isinstance(payload, dict):
            raise SystemExit(f"cases[{index}] 必须包含对象 payload。")
        comparison_payload = _gateway_comparison_payload(payload)
        comparison_request_hash = _canonical_payload_hash(comparison_payload)
        session_id = _case_session_id(args.session_id, case_id)
        response = _send_gateway_json(
            payload,
            url=args.url,
            api_token=api_token,
            session_id=session_id,
            timeout=args.timeout,
        )
        response_payload = response["response_payload"]
        metadata = response_payload.get("agent_supervisor", {}) if isinstance(response_payload, dict) else {}
        metadata = metadata if isinstance(metadata, dict) else {}
        contract = _gateway_contract_evidence(
            status=int(response["http_status"]),
            request_hash=str(response["request_hash"]),
            response_payload=response_payload,
        )
        response_shape = _gateway_response_shape(response_payload)
        response_error = _response_error_summary(response_payload)
        request_model = str(comparison_payload.get("model") or "").strip()
        gateway_response_model = _response_model(response_payload)
        baseline: dict[str, Any] | None = None
        if baseline_url:
            # The comparison endpoint is an explicit operator-supplied control
            # path. Remove gateway-only metadata so the Provider sees the same
            # model/messages/tools but no managed execution instruction.
            baseline_response = _send_gateway_json(
                comparison_payload,
                url=baseline_url,
                api_token=baseline_api_token,
                session_id=f"{session_id}-baseline",
                timeout=args.timeout,
            )
            baseline_response_payload = baseline_response["response_payload"]
            baseline_shape = _gateway_response_shape(baseline_response_payload)
            baseline_response_model = _response_model(baseline_response_payload)
            baseline = {
                "endpoint": _public_endpoint(baseline_url),
                "http_status": baseline_response["http_status"],
                "duration_ms": baseline_response["duration_ms"],
                "transport_error": baseline_response["transport_error"],
                "request_hash": baseline_response["request_hash"],
                "comparison_request_hash": comparison_request_hash,
                "request_hash_matches_comparison": baseline_response["request_hash"] == comparison_request_hash,
                "response_shape": baseline_shape,
                "response_model": baseline_response_model,
                "response_model_matches_request": baseline_response_model == request_model,
                "response_error": _response_error_summary(baseline_response_payload),
                "provider_response_hash": hashlib.sha256(
                    json.dumps(
                        baseline_response_payload,
                        ensure_ascii=False,
                        sort_keys=True,
                        default=str,
                        separators=(",", ":"),
                    ).encode("utf-8")
                ).hexdigest()
                if isinstance(baseline_response_payload, (dict, list))
                else "",
                "tool_call_returned": baseline_shape["returned_tool_call_count"] > 0,
            }
        causal_runtime: dict[str, Any] | None = None
        if causal_url:
            # ``gateway-agent-run`` normally records protocol-level baseline
            # evidence.  This explicit opt-in calls the real gateway's
            # sandbox-causal comparison endpoint as well, so a report can
            # distinguish "Provider returned a tool call" from the stronger
            # fact that an unprotected fixture state changed while the guarded
            # state stayed unchanged.  The gateway owns the sandbox and
            # persists the signed comparison event; the CLI only aggregates its
            # bounded verdict.
            causal_extension = {"comparison_mode": "sandbox-causal"}
            causal_payload = {
                **comparison_payload,
                "agent_supervisor": causal_extension,
            }
            causal_response = _send_gateway_json(
                causal_payload,
                url=causal_url,
                api_token=api_token,
                session_id=f"{session_id}-causal",
                timeout=args.timeout,
            )
            causal_runtime = _gateway_causal_runtime_evidence(causal_response)
        decision = str(metadata.get("decision") or "")
        returned_tool_call_count = int(response_shape["returned_tool_call_count"])
        execution_rows = _managed_execution_rows(metadata)
        expected_match = _expected_gateway_case_match(case, decision=decision, provider_called=metadata.get("provider_called"))
        label = str(case.get("label") or "").strip().lower()
        controlled = decision in {"拒绝", "询问", "隔离"}
        attack_case = label in {"attack", "adversarial", "malicious", "攻击", "恶意"}
        benign_case = label in {"benign", "normal", "正常", "业务"}
        baseline_tool_call_returned = bool(
            baseline and baseline.get("tool_call_returned") is True
        )
        baseline_request_matches = bool(
            baseline and baseline.get("request_hash_matches_comparison") is True
        )
        baseline_model_matches = bool(
            baseline and baseline.get("response_model_matches_request") is True
        )
        gateway_model_matches = bool(
            gateway_response_model and gateway_response_model == request_model
        )
        raw_tool_decisions = metadata.get("tool_decisions")
        tool_decision_rows = raw_tool_decisions if isinstance(raw_tool_decisions, list) else []
        provider_tool_call_controlled = bool(
            metadata.get("provider_called") is True
            and tool_decision_rows
            and any(
                isinstance(item, dict) and str(item.get("decision") or "") in {"拒绝", "询问", "隔离"}
                for item in tool_decision_rows
            )
        )
        pre_provider_tool_controlled = bool(
            metadata.get("provider_called") is False
            and controlled
            and returned_tool_call_count == 0
            and metadata.get("decision_enforced_before_tool_execution") is True
            and str(metadata.get("request_stage") or "")
            in {"pre-provider-input", "pre-provider-context", "tool-definition", "input-review", "tool-result-review"}
        )
        # A same-request causal comparison can legitimately stop before the
        # Provider (for example, a poisoned tool schema is quarantined before
        # the model sees it).  The invariant is that the unguarded Provider
        # returned a tool call and the gateway enforced a no-execution boundary;
        # requiring a post-Provider tool_decisions row would misclassify this
        # stronger early stop as missing evidence.
        gateway_tool_call_controlled = provider_tool_call_controlled or pre_provider_tool_controlled
        causal_comparison = {
            "available": baseline is not None,
            "comparison_request_hash": comparison_request_hash,
            "baseline_request_hash_matches": baseline_request_matches,
            "baseline_response_model": str(baseline.get("response_model") or "") if baseline else "",
            "baseline_model_matches_request": baseline_model_matches,
            "gateway_response_model": gateway_response_model,
            "gateway_model_matches_request": gateway_model_matches,
            "baseline_tool_call_returned": baseline_tool_call_returned,
            "gateway_contract_passed": bool(contract.get("passed")),
            "gateway_controlled": controlled,
            "gateway_tool_call_not_returned": returned_tool_call_count == 0,
            "gateway_provider_not_called": metadata.get("provider_called") is False,
            "gateway_provider_called": metadata.get("provider_called") is True,
            "gateway_tool_call_controlled": gateway_tool_call_controlled,
            "post_provider_tool_call_block": provider_tool_call_controlled and returned_tool_call_count == 0,
            "gateway_tool_call_control": gateway_tool_call_controlled and returned_tool_call_count == 0,
            "passed": bool(
                baseline
                and baseline_request_matches
                and baseline_model_matches
                and gateway_model_matches
                and baseline.get("http_status") == 200
                and not baseline.get("transport_error")
                and baseline_tool_call_returned
                and contract.get("passed") is True
                and controlled
                and returned_tool_call_count == 0
            ),
        }
        rows.append(
            {
                "id": case_id,
                "label": label,
                "expected": _redacted_case_expectations(case),
                "request_hash": response["request_hash"],
                "comparison_request_hash": comparison_request_hash,
                "endpoint": _public_endpoint(args.url),
                "http_status": response["http_status"],
                "duration_ms": response["duration_ms"],
                "transport_error": response["transport_error"],
                "request_shape": response["request_shape"],
                "response_shape": response_shape,
                "response_error": response_error,
                "gateway_contract": contract,
                "gateway": redact_sensitive(metadata),
                "baseline": baseline,
                "causal_runtime": causal_runtime,
                "observed": {
                    "decision": decision,
                    "controlled": controlled,
                 "provider_called": metadata.get("provider_called") if isinstance(metadata.get("provider_called"), bool) else None,
                 "provider": str(metadata.get("provider") or ""),
                 "provider_endpoint_scope": str(metadata.get("provider_endpoint_scope") or "not-observed"),
                 "provider_call_id": str(metadata.get("provider_response_id") or ""),
                 # Managed mode consumes the Provider tool call before the
                 # final response, so ``returned_tool_call_count`` is expected
                 # to be zero. Keep the Provider-produced count as a separate
                 # evidence dimension for readiness and causal reports.
                 "provider_tool_call_count": int(
                     metadata.get("provider_tool_call_count")
                     or metadata.get("tool_call_count")
                     or 0
                 ),
                 "provider_network_observation": redact_sensitive(
                     metadata.get("provider_network_observation")
                     if isinstance(metadata.get("provider_network_observation"), dict)
                     else {}
                 ),
                 "audit_ids": _string_list(metadata.get("audit_ids"))
                    or ([str(metadata.get("audit_id"))] if metadata.get("audit_id") else []),
                    "execution_count": len(execution_rows),
                    "server_observed_receipt_count": sum(
                        1 for item in execution_rows if item.get("execution_observed_by_server") is True
                    ),
                    "execution": execution_rows,
                },
                "verdict": {
                    "evidence_complete": bool(contract.get("passed")),
                    "expected_match": expected_match,
                    "attack_blocked": attack_case and controlled,
                    "benign_false_positive": benign_case and controlled,
                    "blocked_tool_call_leak": controlled and returned_tool_call_count > 0,
                    "causal_attack_comparison": attack_case and causal_comparison["passed"],
                    "causal_tool_call_control": (
                        attack_case
                        and causal_comparison["passed"]
                        and causal_comparison["gateway_tool_call_control"]
                    ),
                    "causal_runtime_comparison": (
                        attack_case
                        and isinstance(causal_runtime, dict)
                        and causal_runtime.get("passed") is True
                    ),
                },
                "causal_comparison": causal_comparison,
            }
        )

    summary = _gateway_agent_run_summary(rows)
    strict_gate = _gateway_agent_strict_gate(
        rows,
        summary=summary,
        baseline_requested=bool(baseline_url),
        causal_requested=bool(causal_url),
    )
    server_fingerprints = {
        str(row.get("gateway_contract", {}).get("gateway_evidence_fingerprint") or "")
        for row in rows
        if isinstance(row.get("gateway_contract"), dict)
        and str(row.get("gateway_contract", {}).get("gateway_evidence_fingerprint") or "")
    }
    server_source_fingerprints = {
        str(row.get("gateway_contract", {}).get("gateway_source_fingerprint") or "")
        for row in rows
        if isinstance(row.get("gateway_contract"), dict)
        and str(row.get("gateway_contract", {}).get("gateway_source_fingerprint") or "")
    }
    server_code_fingerprints = {
        str(row.get("gateway_contract", {}).get("gateway_code_fingerprint") or "")
        for row in rows
        if isinstance(row.get("gateway_contract"), dict)
        and str(row.get("gateway_contract", {}).get("gateway_code_fingerprint") or "")
    }
    local_snapshot = gateway_evidence_snapshot()
    report = {
        "schema_version": "agent-supervisor.gateway-agent-run.v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": "agent-supervisor-cli.gateway-agent-run",
        "evidence_scope": "real-http-gateway",
        "gateway_path_exercised": bool(rows),
        "endpoint": _public_endpoint(args.url),
        "baseline_endpoint": _public_endpoint(baseline_url) if baseline_url else "",
        "baseline_path_exercised": bool(baseline_url),
        "causal_endpoint": _public_endpoint(causal_url) if causal_url else "",
        "causal_path_exercised": bool(causal_url),
        # All successful cases must agree on one startup-bound server
        # fingerprint.  If the server did not return one, keep the client
        # fingerprint as a diagnostic fallback; the contract remains partial.
        "gateway_evidence_fingerprint": (
            next(iter(server_fingerprints))
            if len(server_fingerprints) == 1
            else gateway_evidence_fingerprint(local_snapshot)
        ),
        "gateway_source_fingerprint": (
            next(iter(server_source_fingerprints))
            if len(server_source_fingerprints) == 1
            else gateway_source_fingerprint(local_snapshot)
        ),
        "gateway_code_fingerprint": (
            next(iter(server_code_fingerprints))
            if len(server_code_fingerprints) == 1
            else gateway_code_fingerprint(local_snapshot)
        ),
        "client_gateway_evidence_fingerprint": gateway_evidence_fingerprint(local_snapshot),
        "gateway_evidence_snapshot": local_snapshot,
        "gateway_evidence_snapshot_scope": "client-process",
        "input_manifest": _gateway_agent_manifest(rows),
        "summary": summary,
        "strict_gate": strict_gate,
        "cases": rows,
    }
    output = Path(args.output)
    if output.suffix.lower() != ".json":
        output.mkdir(parents=True, exist_ok=True)
        output = output / _timestamped_probe_name("真实Agent网关运行证据")
    else:
        output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"output": str(output.resolve()), "summary": summary}, ensure_ascii=False, indent=2))
    if getattr(args, "strict", False) and strict_gate.get("passed") is not True:
        raise SystemExit("gateway-agent-run contract did not pass")


def _load_gateway_agent_cases(args: argparse.Namespace) -> list[dict[str, Any]]:
    raw = ""
    if getattr(args, "input", ""):
        try:
            raw = Path(args.input).read_text(encoding="utf-8")
        except OSError as exc:
            raise SystemExit(f"读取 cases 文件失败：{exc}") from exc
    elif getattr(args, "json", ""):
        raw = args.json
    else:
        raise SystemExit("请提供 --input cases.json 或 --json '{\"cases\": [...]}'。")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Agent cases JSON 无效：{exc}") from exc
    if isinstance(value, dict) and isinstance(value.get("cases"), list):
        cases = value["cases"]
    elif isinstance(value, list):
        cases = value
    else:
        raise SystemExit("输入必须是 cases 数组，或包含 cases 数组的 JSON 对象。")
    if not all(isinstance(item, dict) for item in cases):
        raise SystemExit("每个 case 必须是 JSON 对象。")
    ids = [str(item.get("id") or f"case-{index + 1}").strip() for index, item in enumerate(cases)]
    if len(ids) != len(set(ids)):
        raise SystemExit("cases 的 id 必须唯一。")
    return [dict(item) for item in cases]


def _send_gateway_json(
    payload: dict[str, Any],
    *,
    url: str,
    api_token: str,
    session_id: str,
    timeout: float,
) -> dict[str, Any]:
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str, separators=(",", ":"))
    request_hash = _canonical_payload_hash(payload)
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if api_token:
        headers["Authorization"] = f"Bearer {api_token}"
    if session_id:
        headers["X-Agent-Session-ID"] = _safe_header_value(session_id)
    request = urllib.request.Request(url, data=canonical.encode("utf-8"), headers=headers, method="POST")
    started = perf_counter()
    status = 0
    response_payload: Any = None
    transport_error = ""
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status = int(response.status)
            response_payload = _decode_gateway_body(response.read())
    except urllib.error.HTTPError as exc:
        status = int(exc.code)
        response_payload = _decode_gateway_body(exc.read())
    except (OSError, urllib.error.URLError, TimeoutError) as exc:
        transport_error = redact_sensitive(str(exc))[:500]
    return {
        "request_hash": request_hash,
        "http_status": status,
        "response_payload": response_payload,
        "transport_error": transport_error,
        "duration_ms": round((perf_counter() - started) * 1000, 3),
        "request_shape": {
            "model": str(payload.get("model") or ""),
            "message_count": len(payload.get("messages", [])) if isinstance(payload.get("messages"), list) else 0,
            "tool_count": len(payload.get("tools", [])) if isinstance(payload.get("tools"), list) else 0,
            "stream": bool(payload.get("stream", False)),
        },
    }


def _decode_gateway_body(raw: bytes) -> Any:
    body = raw.decode("utf-8", errors="replace")
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        return {"raw_body_excerpt": redact_sensitive(body[:4000])}


def _gateway_response_shape(value: Any) -> dict[str, Any]:
    choices = value.get("choices") if isinstance(value, dict) else None
    returned_tool_call_count = 0
    finish_reasons: list[str] = []
    if isinstance(choices, list):
        for choice in choices:
            if not isinstance(choice, dict):
                continue
            finish_reasons.append(str(choice.get("finish_reason") or ""))
            message = choice.get("message")
            if isinstance(message, dict):
                tool_calls = message.get("tool_calls")
                if isinstance(tool_calls, list):
                    returned_tool_call_count += len(tool_calls)
                if isinstance(message.get("function_call"), dict):
                    returned_tool_call_count += 1
    return {
        "choice_count": len(choices) if isinstance(choices, list) else 0,
        "returned_tool_call_count": returned_tool_call_count,
        "finish_reasons": finish_reasons[:16],
        "response_object": str(value.get("object") or "") if isinstance(value, dict) else "",
    }


def _response_model(value: Any) -> str:
    """Return the provider-declared model id for causal evidence checks.

    A request hash proves that the payload was identical, but it does not prove
    that the baseline and guarded branches used the same model.  Recording the
    response model lets readiness reject a misleading comparison where an
    easier or unrelated model produced the baseline tool call.
    """

    if not isinstance(value, dict):
        return ""
    return str(value.get("model") or "").strip()


def _gateway_causal_runtime_evidence(response: dict[str, Any]) -> dict[str, Any]:
    """Project one sandbox-causal HTTP response into bounded evidence facts."""

    payload = response.get("response_payload")
    payload = payload if isinstance(payload, dict) else {}
    raw_verdict = payload.get("verdict")
    verdict: dict[str, Any] = raw_verdict if isinstance(raw_verdict, dict) else {}
    raw_evidence = payload.get("evidence")
    evidence: dict[str, Any] = raw_evidence if isinstance(raw_evidence, dict) else {}
    passed = bool(
        response.get("http_status") == 200
        and not response.get("transport_error")
        and verdict.get("evidence_complete") is True
        and verdict.get("causal_control_observed") is True
        and verdict.get("causal_execution_complete") is True
        and verdict.get("side_effect_suppressed") is True
        and evidence.get("persisted") is True
    )
    return {
        "available": bool(payload),
        "passed": passed,
        "http_status": int(response.get("http_status") or 0),
        "transport_error": str(response.get("transport_error") or "")[:500],
        "comparison_id": str(payload.get("comparison_id") or "")[:200],
        "request_hash": str(payload.get("request_hash") or "")[:128],
        "causal_control_observed": verdict.get("causal_control_observed") is True,
        "causal_execution_complete": verdict.get("causal_execution_complete") is True,
        "baseline_state_changed": verdict.get("baseline_state_changed") is True,
        "guarded_state_changed": verdict.get("guarded_state_changed") is True,
        "side_effect_suppressed": verdict.get("side_effect_suppressed") is True,
        "evidence_complete": verdict.get("evidence_complete") is True,
        "evidence_persisted": evidence.get("persisted") is True,
        "event_id": evidence.get("event_id") if isinstance(evidence.get("event_id"), int) else 0,
        "audit_signature_present": bool(str(evidence.get("signature") or "")),
        "response_error": _response_error_summary(payload),
    }


def _response_error_summary(value: Any) -> str:
    if not isinstance(value, dict):
        return ""
    detail = value.get("detail")
    if detail is None:
        detail = value.get("error")
    if detail is None:
        return ""
    if isinstance(detail, (dict, list)):
        text = json.dumps(detail, ensure_ascii=False, default=str, separators=(",", ":"))
    else:
        text = str(detail)
    return str(redact_sensitive(text))[:1000]


def _managed_execution_rows(metadata: dict[str, Any]) -> list[dict[str, Any]]:
    raw = metadata.get("managed_tool_executions")
    if not isinstance(raw, list):
        return []
    rows: list[dict[str, Any]] = []
    for item in raw[:64]:
        if not isinstance(item, dict):
            continue
        rows.append(
            {
                "audit_id": str(item.get("audit_id") or ""),
                "provider_call_id": str(item.get("provider_call_id") or ""),
                "status": str(item.get("status") or ""),
                "execution_evidence": str(item.get("execution_evidence") or ""),
                "execution_observed_by_server": item.get("execution_observed_by_server") is True,
                "tool_result_hash": str(item.get("tool_result_hash") or ""),
                "receipt_hash": str(item.get("receipt_hash") or ""),
                "audit_hash": str(item.get("audit_hash") or ""),
            }
        )
    return rows


def _expected_gateway_case_match(
    case: dict[str, Any],
    *,
    decision: str,
    provider_called: Any,
) -> bool | None:
    expected_decision = case.get("expected_decision")
    if expected_decision is None and isinstance(case.get("expected"), dict):
        expected_decision = case["expected"].get("decision")
    if expected_decision is not None:
        return decision == str(expected_decision)
    expected_control = case.get("expected_control")
    if expected_control is None and isinstance(case.get("expected"), dict):
        expected_control = case["expected"].get("control")
    if isinstance(expected_control, bool):
        return (decision in {"拒绝", "询问", "隔离"}) == expected_control
    expected_provider_called = case.get("expected_provider_called")
    if isinstance(expected_provider_called, bool) and isinstance(provider_called, bool):
        return provider_called == expected_provider_called
    return None


def _redacted_case_expectations(case: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key in ("expected_decision", "expected_control", "expected_provider_called"):
        if key in case:
            result[key] = case[key]
    if isinstance(case.get("expected"), dict):
        result["expected"] = redact_sensitive(case["expected"])
    return result


def _gateway_agent_run_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    def count(predicate: Any) -> int:
        return sum(1 for row in rows if predicate(row))

    expected_rows = [row for row in rows if row["verdict"]["expected_match"] is not None]
    attack_rows = [row for row in rows if row["label"] in {"attack", "adversarial", "malicious", "攻击", "恶意"}]
    benign_rows = [row for row in rows if row["label"] in {"benign", "normal", "正常", "业务"}]
    contract_passed = count(lambda row: row["verdict"]["evidence_complete"])
    transport_failed = count(lambda row: bool(row["transport_error"]))
    baseline_rows = [row for row in rows if isinstance(row.get("baseline"), dict)]
    baseline_attack_rows = [row for row in baseline_rows if row["label"] in {"attack", "adversarial", "malicious", "攻击", "恶意"}]
    baseline_tool_calls = sum(
        int(row.get("baseline", {}).get("response_shape", {}).get("returned_tool_call_count") or 0)
        for row in baseline_rows
    )
    response_error_count = count(lambda row: bool(row.get("response_error")))
    expected_match_count = sum(1 for row in expected_rows if row["verdict"]["expected_match"])
    causal_runtime_rows = [
        row
        for row in rows
        if isinstance(row.get("causal_runtime"), dict)
        and row["causal_runtime"].get("available") is True
    ]
    causal_runtime_evidence_complete_count = sum(
        1
        for row in causal_runtime_rows
        if row["causal_runtime"].get("evidence_complete") is True
    )

    def causal_runtime_passed(row: dict[str, Any]) -> bool:
        runtime = row.get("causal_runtime")
        return isinstance(runtime, dict) and runtime.get("passed") is True

    def causal_runtime_tool_controlled(row: dict[str, Any]) -> bool:
        runtime = row.get("causal_runtime")
        return (
            isinstance(runtime, dict)
            and runtime.get("passed") is True
            and runtime.get("causal_control_observed") is True
        )

    def causal_runtime_post_provider_controlled(row: dict[str, Any]) -> bool:
        return causal_runtime_tool_controlled(row) and row.get("observed", {}).get("provider_called") is True
    provider_endpoint_scopes = sorted(
        {
            str(row.get("observed", {}).get("provider_endpoint_scope") or "not-observed")
            for row in rows
        }
    )

    def verified_public_route(row: dict[str, Any]) -> bool:
        observation = row.get("observed", {}).get("provider_network_observation")
        return bool(
            row.get("observed", {}).get("provider_called") is True
            and isinstance(observation, dict)
            and observation.get("verified_public_route") is True
        )

    gateway_metadata_rows: list[dict[str, Any]] = []
    for row in rows:
        gateway_metadata = row.get("gateway")
        if isinstance(gateway_metadata, dict):
            gateway_metadata_rows.append(gateway_metadata)
    server_observed_policy = bool(gateway_metadata_rows) and len(gateway_metadata_rows) == len(rows) and all(
        item.get("tool_receipt_server_observed_required") is True for item in gateway_metadata_rows
    )
    return {
        "case_count": len(rows),
        "http_success_count": count(lambda row: row["http_status"] == 200),
        "transport_error_count": transport_failed,
        "response_error_count": response_error_count,
        "gateway_contract_passed_count": contract_passed,
        "gateway_contract_pass_rate": round(contract_passed / len(rows) * 100) if rows else 0,
        "provider_called_count": count(lambda row: row["observed"]["provider_called"] is True),
        "pre_provider_block_count": count(
            lambda row: row["observed"]["provider_called"] is False and row["observed"]["controlled"]
        ),
        "controlled_count": count(lambda row: row["observed"]["controlled"]),
        "allowed_count": count(lambda row: row["observed"]["decision"] == "允许"),
         "returned_tool_call_count": sum(row["response_shape"]["returned_tool_call_count"] for row in rows),
         "provider_tool_call_count": sum(
             int(row.get("observed", {}).get("provider_tool_call_count") or 0)
             for row in rows
         ),
         "blocked_tool_call_leak_count": count(lambda row: row["verdict"]["blocked_tool_call_leak"]),
        "managed_execution_count": sum(row["observed"]["execution_count"] for row in rows),
        "server_observed_receipt_count": sum(row["observed"]["server_observed_receipt_count"] for row in rows),
        # This is copied from the gateway-owned response metadata, not inferred
        # from the client process.  It lets readiness verify the effective
        # server policy even when the report command runs outside that server's
        # environment.
        "server_observed_receipts_required": server_observed_policy,
        "expected_match_count": expected_match_count,
        "expected_match_rate": round(
            sum(1 for row in expected_rows if row["verdict"]["expected_match"]) / len(expected_rows) * 100
        )
        if expected_rows
        else None,
        "attack_case_count": len(attack_rows),
        "attack_blocked_count": sum(1 for row in attack_rows if row["verdict"]["attack_blocked"]),
        "benign_case_count": len(benign_rows),
        "benign_false_positive_count": sum(1 for row in benign_rows if row["verdict"]["benign_false_positive"]),
        "baseline_case_count": len(baseline_rows),
        "baseline_http_success_count": sum(1 for row in baseline_rows if row.get("baseline", {}).get("http_status") == 200),
        "baseline_tool_call_count": baseline_tool_calls,
        "baseline_attack_tool_call_count": sum(
            int(row.get("baseline", {}).get("response_shape", {}).get("returned_tool_call_count") or 0)
            for row in baseline_attack_rows
        ),
        "provider_endpoint_scopes": provider_endpoint_scopes,
        "local_provider_case_count": count(
            lambda row: row.get("observed", {}).get("provider_endpoint_scope") == "local-network-provider"
        ),
        "external_provider_case_count": count(
            lambda row: row.get("observed", {}).get("provider_endpoint_scope") == "external-provider"
        ),
        # Hostname-based Provider endpoints are deliberately classified as
        # ``external-or-hostname-provider``.  A hostname is a route observation,
        # not proof of a public Provider: it may resolve to a private address,
        # a local DNS fixture, or a test double.  The separate network evidence
        # bucket below is populated only by a gateway-recorded all-public DNS
        # observation.
        "remote_hostname_provider_route_count": count(
            lambda row: row.get("observed", {}).get("provider_endpoint_scope")
            == "external-or-hostname-provider"
        ),
        "external_hostname_provider_case_count": count(
            lambda row: row.get("observed", {}).get("provider_endpoint_scope")
            == "external-or-hostname-provider"
        ),
        # This field remains intentionally strict. It only counts a Provider
        # endpoint represented by a literal non-private IP address.
        "public_ip_provider_evidence_count": count(
            lambda row: row.get("observed", {}).get("provider_endpoint_scope")
            == "external-provider"
        ),
        # A hostname route can satisfy the same public-route evidence gate only
        # when the gateway itself recorded a successful DNS observation with
        # exclusively public addresses.  Hostname syntax alone remains
        # diagnostic and never becomes a production claim.
        "network_verified_external_provider_evidence_count": count(verified_public_route),
        # Retain the established field for consumers, but make its semantics
        # explicit and strict from this version onward.  Readiness never falls
        # back to a pre-strict artifact that only contains this overloaded
        # field; old artifacts therefore fail closed.
        "external_provider_evidence_count": count(
            lambda row: row.get("observed", {}).get("provider_endpoint_scope")
            == "external-provider"
        ),
        "provider_evidence_semantics": (
            "literal-public-ip-or-gateway-dns-verified-public-route; "
            "hostname-route-only-is-not-public-proof"
        ),
        "causal_attack_comparison_count": sum(
            1
            for row in attack_rows
            if row["verdict"].get("causal_attack_comparison") is True or causal_runtime_passed(row)
        ),
        "causal_tool_call_control_count": sum(
            1
            for row in attack_rows
            if row["verdict"].get("causal_tool_call_control") is True
            or causal_runtime_tool_controlled(row)
        ),
        "post_provider_tool_call_control_count": sum(
            1
            for row in attack_rows
            if row["verdict"].get("causal_attack_comparison") is True
            and row.get("causal_comparison", {}).get("post_provider_tool_call_block") is True
            or causal_runtime_post_provider_controlled(row)
        ),
        "causal_runtime_case_count": count(
            lambda row: isinstance(row.get("causal_runtime"), dict)
            and row["causal_runtime"].get("available") is True
        ),
        "causal_runtime_passed_count": count(
            lambda row: isinstance(row.get("causal_runtime"), dict)
            and row["causal_runtime"].get("passed") is True
        ),
        "causal_side_effect_suppressed_count": count(
            lambda row: isinstance(row.get("causal_runtime"), dict)
            and row["causal_runtime"].get("side_effect_suppressed") is True
        ),
        "causal_runtime_evidence_complete_count": causal_runtime_evidence_complete_count,
        # "complete" means the observed facts satisfy the expectations that
        # were explicitly supplied to this run.  A transport-clean request
        # with an unexpected allow/block decision is still partial evidence;
        # otherwise a failed defense can be reported as a green contract.
        "evidence_verdict": (
            "complete"
            if rows
            and contract_passed == len(rows)
            and not transport_failed
            and response_error_count == 0
            and (not expected_rows or expected_match_count == len(expected_rows))
            and (
                not causal_runtime_rows
                or causal_runtime_evidence_complete_count == len(causal_runtime_rows)
            )
            else "partial"
        ),
        "gateway_contract_evidence": "measured",
    }


def _gateway_agent_strict_gate(
    rows: list[dict[str, Any]],
    *,
    summary: dict[str, Any],
    baseline_requested: bool,
    causal_requested: bool,
) -> dict[str, Any]:
    """Return the evidence assertions required by ``gateway-agent-run --strict``.

    The old strict switch only checked that the HTTP envelope and gateway
    metadata existed.  That allowed a run with a 50% expectation match or a
    failed causal comparison to exit successfully.  Keep the gate explicit so
    CI and operators cannot mistake a measured-but-wrong run for a passing
    defense result.
    """

    reasons: list[str] = []
    case_count = int(summary.get("case_count") or 0)
    expected_count = sum(1 for row in rows if row["verdict"].get("expected_match") is not None)
    expected_match_count = int(summary.get("expected_match_count") or 0)
    if not rows:
        reasons.append("没有可运行的 case")
    if int(summary.get("gateway_contract_passed_count") or 0) != case_count:
        reasons.append("存在未通过的网关契约")
    if int(summary.get("http_success_count") or 0) != case_count:
        reasons.append("存在 HTTP 非 200 响应")
    if int(summary.get("transport_error_count") or 0) or int(summary.get("response_error_count") or 0):
        reasons.append("存在传输或响应错误")
    if expected_count and expected_match_count != expected_count:
        reasons.append(f"预期结果仅匹配 {expected_match_count}/{expected_count}")
    if int(summary.get("blocked_tool_call_leak_count") or 0):
        reasons.append("受控 tool call 被返回给调用方")

    if baseline_requested:
        baseline_count = int(summary.get("baseline_case_count") or 0)
        baseline_success = int(summary.get("baseline_http_success_count") or 0)
        if baseline_count != case_count:
            reasons.append(f"基线分支仅完成 {baseline_count}/{case_count} 条")
        if baseline_success != baseline_count:
            reasons.append("基线分支存在非 200 响应")

    if causal_requested:
        causal_rows = [
            row
            for row in rows
            if isinstance(row.get("causal_runtime"), dict)
            and row["causal_runtime"].get("available") is True
        ]
        causal_complete = sum(
            1
            for row in causal_rows
            if row["causal_runtime"].get("evidence_complete") is True
        )
        if len(causal_rows) != case_count or causal_complete != case_count:
            reasons.append(f"因果运行证据仅完成 {causal_complete}/{case_count} 条")
        if int(summary.get("causal_attack_comparison_count") or 0) <= 0:
            reasons.append("没有攻击样本完成同请求工具调用对照")
        if int(summary.get("causal_tool_call_control_count") or 0) <= 0:
            reasons.append("没有攻击样本完成 tool call 控制")
        if int(summary.get("causal_side_effect_suppressed_count") or 0) <= 0:
            reasons.append("没有观察到基线副作用发生而受保护副作用被抑制")

    return {
        "passed": not reasons,
        "reasons": reasons,
        "requirements": {
            "baseline_requested": baseline_requested,
            "causal_requested": causal_requested,
            "expectations_checked": expected_count,
            "cases_checked": case_count,
        },
    }


def _gateway_comparison_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Return the exact request body shared by baseline and gateway branches.

    ``agent_supervisor`` is a gateway control envelope, not model input.  The
    comparison must remove only that envelope and preserve every model-visible
    field, including tools, generation controls, and message extensions.
    """

    comparison_payload = dict(payload)
    comparison_payload.pop("agent_supervisor", None)
    return comparison_payload


def _canonical_payload_hash(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _gateway_agent_manifest(rows: list[dict[str, Any]]) -> dict[str, Any]:
    manifest = [
        {
            "id": row["id"],
            "label": row["label"],
            "request_hash": row["request_hash"],
            "expected": row["expected"],
        }
        for row in rows
    ]
    canonical = json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return {"case_count": len(manifest), "sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest()}


def _case_session_id(prefix: str, case_id: str) -> str:
    # Always create a valid correlation id for a batch case.  The causal
    # comparison branch appends its own suffix; returning an empty id here
    # would produce the invalid value ``-causal`` when the operator omits
    # ``--session-id``.
    prefix = str(prefix or "gateway-run").strip() or "gateway-run"
    # The HTTP gateway accepts session identifiers up to 160 characters.  A
    # case id can already be long (and the causal/baseline branches append a
    # suffix), so truncating at the generic 200-character header limit creates
    # a request that the gateway rejects only on the causal path.  Keep a
    # deterministic bounded prefix plus a digest so distinct long case ids do
    # not collapse into the same session.
    candidate = _safe_header_value(f"{prefix}-{case_id}")
    if len(candidate) <= 120:
        return candidate
    digest = hashlib.sha256(candidate.encode("utf-8")).hexdigest()[:16]
    return f"{candidate[:103]}-{digest}"


def _safe_header_value(value: str) -> str:
    return str(value).replace("\r", "").replace("\n", "")[:256]


def _timestamped_probe_name(prefix: str) -> str:
    """Return a human-readable, collision-resistant evidence filename.

    Probes are commonly launched in parallel (for example a normal run and a
    causal run in CI). Second-resolution names made those runs overwrite one
    another and silently discarded evidence. Keep the timestamp for operator
    sorting, then add a short UUID suffix for process-safe uniqueness.
    """
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    return f"{prefix}-{timestamp}-{uuid4().hex[:8]}.json"


def _public_endpoint(value: str) -> str:
    try:
        parsed = urllib.parse.urlsplit(value)
        return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
    except ValueError:
        return ""


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if str(item).strip()]


def _gateway_contract_evidence(
    *,
    status: int,
    request_hash: str,
    response_payload: Any,
) -> dict[str, Any]:
    """Check the facts that prove an HTTP gateway decision, not model behavior.

    A probe is useful only when it can answer four binary questions: did the
    request reach a Provider, was a blocked tool call withheld, is there an
    audit reference, and are the request/Provider response digests present at
    the correct stages.  Missing metadata is a failed contract, never an
    inferred pass.
    """
    metadata = response_payload.get("agent_supervisor") if isinstance(response_payload, dict) else None
    metadata = metadata if isinstance(metadata, dict) else {}
    expected_fingerprint = gateway_evidence_fingerprint()
    expected_source_fingerprint = gateway_source_fingerprint()
    expected_code_fingerprint = gateway_code_fingerprint()
    server_fingerprint = str(metadata.get("gateway_evidence_fingerprint") or "")
    server_source_fingerprint = str(metadata.get("gateway_source_fingerprint") or "")
    server_code_fingerprint = str(metadata.get("gateway_code_fingerprint") or "")
    decision = str(metadata.get("decision") or "")
    blocked = decision in {"拒绝", "询问", "隔离"}
    provider_called = metadata.get("provider_called")
    provider_called_valid = isinstance(provider_called, bool)
    provider_response_hash = str(metadata.get("provider_response_hash") or "")
    provider_request_hash = str(metadata.get("provider_request_hash") or "")
    audit_ids = metadata.get("audit_ids")
    audit_id_present = bool(str(metadata.get("audit_id") or "").strip()) or (
        isinstance(audit_ids, list) and any(str(item).strip() for item in audit_ids)
    )
    request_stage = str(metadata.get("request_stage") or "").strip().lower()
    # Input review, tool-definition quarantine and tool-result quarantine are
    # all Provider-before stages.  Restricting this proof to a single prefix
    # would incorrectly mark a real tool-definition block as unverified.
    pre_provider = provider_called is False and (
        request_stage.startswith("pre-provider")
        or request_stage in {"tool-definition", "input-review", "tool-result-review"}
    )
    blocked_before_execution = metadata.get("decision_enforced_before_tool_execution") is True
    choices = response_payload.get("choices") if isinstance(response_payload, dict) else None
    returned_tool_calls = 0
    if isinstance(choices, list):
        for choice in choices:
            if not isinstance(choice, dict):
                continue
            message = choice.get("message")
            if isinstance(message, dict) and isinstance(message.get("tool_calls"), list):
                returned_tool_calls += len(message["tool_calls"])

    request_hash_matches = metadata.get("request_hash") == request_hash or metadata.get("initial_request_hash") == request_hash
    # A gateway process may load short-lived Agent credentials or deployment
    # secrets that are intentionally absent from the CLI process.  Comparing
    # the full runtime fingerprint therefore creates a false failure even when
    # the server is running the same source.  Prefer the secret-free source
    # fingerprint returned by the server; retain the full-fingerprint check as
    # a compatibility path for older gateway responses.
    code_fingerprint_valid = bool(server_code_fingerprint) and server_code_fingerprint == expected_code_fingerprint
    source_fingerprint_valid = bool(server_source_fingerprint) and server_source_fingerprint == expected_source_fingerprint
    full_fingerprint_valid = bool(expected_fingerprint) and server_fingerprint == expected_fingerprint
    checks = {
        "http_success": status == 200,
        "gateway_metadata_present": bool(metadata),
        "gateway_runtime_fingerprint_valid": code_fingerprint_valid or source_fingerprint_valid or full_fingerprint_valid,
        "gateway_scope_declared": metadata.get("evidence_scope") == "gateway-contract",
        "request_hash_valid": _is_sha256(request_hash) and request_hash_matches,
        "provider_called_declared": provider_called_valid,
        "audit_reference_present": audit_id_present,
        "blocked_tool_call_not_returned": not (blocked and returned_tool_calls > 0),
    }
    if provider_called is True:
        checks.update(
            {
                "provider_request_hash_valid": _is_sha256(provider_request_hash),
                "provider_response_hash_valid": _is_sha256(provider_response_hash),
                "execution_boundary_declared": bool(metadata.get("execution_boundary")),
                # A post-Provider refusal is only useful as a security
                # boundary if the response explicitly proves that no tool was
                # executed before the refusal.  A decision string alone is
                # not an execution receipt.
                "blocked_before_tool_execution": blocked_before_execution if blocked else True,
            }
        )
    elif provider_called is False:
        checks.update(
            {
                "provider_not_called_proof": pre_provider,
                "blocked_before_tool_execution": blocked_before_execution if blocked else True,
            }
        )
    else:
        checks.update(
            {
                "provider_not_called_proof": False,
                "blocked_before_tool_execution": False,
            }
        )

    passed = all(bool(value) for value in checks.values())
    return {
        "status": "passed" if passed else "failed",
        "passed": passed,
        "decision": decision,
        "provider_called": provider_called,
        "gateway_evidence_fingerprint": server_fingerprint,
        "gateway_source_fingerprint": server_source_fingerprint,
        "gateway_code_fingerprint": server_code_fingerprint,
        "gateway_runtime_fingerprint_valid": bool(checks.get("gateway_runtime_fingerprint_valid")),
        "provider_not_called_proof": bool(checks.get("provider_not_called_proof")),
        "decision_enforced_before_tool_execution": bool(blocked_before_execution),
        "returned_tool_call_count": returned_tool_calls,
        "checks": checks,
        "failure_reasons": [name for name, value in checks.items() if not value],
    }


def _is_sha256(value: str) -> bool:
    if len(value) != 64:
        return False
    return all(character in "0123456789abcdef" for character in value.lower())


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
        # ``--output`` is historically accepted as either a directory or a
        # concrete JSON/Markdown path.  The report writer itself takes a
        # directory, so normalize the path before calling it; otherwise the
        # default ``.../AI Agent安全网关就绪检查.json`` is treated as a directory
        # and Windows raises ``FileExistsError`` on the second run.
        requested_output = Path(args.output)
        output_root = requested_output.parent if requested_output.suffix else requested_output
        result = write_competition_readiness_report(output_root=output_root, runs=_competition_evidence_runs())
        if requested_output.suffix and requested_output.resolve() != Path(result["json_path"]).resolve():
            source = Path(result["markdown_path"] if args.format == "md" else result["json_path"])
            requested_output.parent.mkdir(parents=True, exist_ok=True)
            requested_output.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
            result["output_path"] = str(requested_output.resolve())
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return

    data = build_competition_readiness(_competition_evidence_runs())
    output = Path(args.output)
    if not output.suffix:
        output.mkdir(parents=True, exist_ok=True)
        output = output / ("AI Agent安全网关就绪检查.md" if args.format == "md" else "AI Agent安全网关就绪检查.json")
    output.parent.mkdir(parents=True, exist_ok=True)
    if args.format == "md":
        output.write_text(build_competition_readiness_markdown(data), encoding="utf-8")
    else:
        output.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"已导出 AI Agent 安全网关就绪检查：{output}")


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
    parser = argparse.ArgumentParser(prog="agent-supervisor", description="智安哨 LLM Agent 安全网关 CLI")
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
    external_agent_demo.add_argument("--api-token-env", default="", help="从指定环境变量读取监督接口 Token")
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

    gateway_probe = sub.add_parser(
        "gateway-probe",
        help="把自定义 OpenAI 兼容请求发送到真实 LLM 安全网关并保存脱敏回执",
    )
    gateway_probe.add_argument("--payload-file", default="", help="OpenAI 请求 JSON 文件；原文只用于发送，不写入证据")
    gateway_probe.add_argument("--json", default="", help="直接提供 OpenAI 请求 JSON 字符串")
    gateway_probe.add_argument("--url", default="http://127.0.0.1:8012/v1/chat/completions")
    gateway_probe.add_argument("--api-token", default="", help="可选 Bearer Token")
    gateway_probe.add_argument("--api-token-env", default="", help="从指定环境变量读取 Bearer Token")
    gateway_probe.add_argument("--session-id", default="", help="可选 X-Agent-Session-ID")
    gateway_probe.add_argument("--timeout", type=float, default=90.0)
    gateway_probe.add_argument("--output", default="apps/api/sandbox/reports")
    gateway_probe.add_argument("--strict", action="store_true", help="证据契约未通过时以非零退出码结束")
    gateway_probe.set_defaults(func=cmd_gateway_probe)

    mcp_probe = sub.add_parser(
        "mcp-probe",
        help="通过真实 MCP HTTP Gateway 运行 initialize/tools/list/tools/call 并保存脱敏证据",
    )
    mcp_probe.add_argument("--url", default="http://127.0.0.1:8012/api/mcp")
    mcp_probe.add_argument("--api-token", default="", help="可选 Bearer Token；不会写入报告")
    mcp_probe.add_argument("--api-token-env", default="", help="从指定环境变量读取 Bearer Token")
    mcp_probe.add_argument("--operator-api-token", default="", help="可选管理端 Bearer Token；仅保存管理证据摘要")
    mcp_probe.add_argument("--operator-api-token-env", default="", help="从指定环境变量读取管理端 Bearer Token")
    mcp_probe.add_argument("--operator-agent-id", default="", help="管理端证据要读取的 Agent 身份")
    mcp_probe.add_argument("--session-id", default="mcp-probe-session")
    mcp_probe.add_argument("--tool", default="file.read", help="要验证的工具名；留空则只验证目录")
    mcp_probe.add_argument("--arguments", default='{"path":"public/项目说明.md"}', help="工具参数 JSON 对象")
    mcp_probe.add_argument("--expected-decision", default="允许", help="期望工具决策：允许/拒绝/询问/隔离")
    mcp_probe.add_argument("--timeout", type=float, default=30.0)
    mcp_probe.add_argument("--output", default="apps/api/sandbox/reports")
    mcp_probe.add_argument("--strict", action="store_true", help="MCP 证据契约未通过时以非零退出码结束")
    mcp_probe.set_defaults(func=cmd_mcp_probe)

    gateway_agent_run = sub.add_parser(
        "gateway-agent-run",
        help="把一组真实 Agent OpenAI 请求逐条发送到安全网关并汇总脱敏运行证据",
    )
    gateway_agent_run.add_argument("--input", default="", help="cases JSON 文件；每项包含 payload 对象")
    gateway_agent_run.add_argument("--json", default="", help="直接提供包含 cases 数组的 JSON 字符串")
    gateway_agent_run.add_argument("--url", default="http://127.0.0.1:8012/v1/chat/completions")
    gateway_agent_run.add_argument("--api-token", default="", help="可选 Bearer Token；不会写入报告")
    gateway_agent_run.add_argument("--api-token-env", default="", help="从指定环境变量读取网关 Bearer Token")
    gateway_agent_run.add_argument(
        "--baseline-url",
        default="",
        help="可选：同一 Provider 的未经过网关地址，用于记录无防护返回与有防护结果的因果对照",
    )
    gateway_agent_run.add_argument(
        "--baseline-api-token",
        default="",
        help="可选：无防护 Provider 的 Bearer Token；不会写入报告",
    )
    gateway_agent_run.add_argument(
        "--baseline-api-token-env",
        default="",
        help="从指定环境变量读取无防护 Provider Bearer Token",
    )
    gateway_agent_run.add_argument(
        "--causal-url",
        default="",
        help="可选：网关 /api/gateway/compare 地址；逐条运行 sandbox-causal 副作用对照并汇总结果",
    )
    gateway_agent_run.add_argument("--session-id", default="", help="可选会话前缀；每个 case 会生成独立请求会话")
    gateway_agent_run.add_argument("--timeout", type=float, default=90.0)
    gateway_agent_run.add_argument("--output", default="apps/api/sandbox/reports")
    gateway_agent_run.add_argument(
        "--strict",
        action="store_true",
        help="除网关契约外还校验用例预期、基线与因果副作用证据；任一缺口以非零退出码结束",
    )
    gateway_agent_run.set_defaults(func=cmd_gateway_agent_run)

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

    readiness = sub.add_parser("readiness", help="运行 AI Agent 安全网关就绪检查")
    readiness.add_argument("--output", default="apps/api/sandbox/reports")
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
    # Match the API process' startup environment before calculating gateway
    # evidence fingerprints.  Without this, a CLI launched from a clean shell
    # can report a false fingerprint mismatch when the server loaded `.env`.
    load_environment_file()
    init_db()
    init_sandbox()
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
