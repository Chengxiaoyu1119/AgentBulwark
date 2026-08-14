from __future__ import annotations

from datetime import datetime, timezone
from time import perf_counter
from uuid import uuid4

from apps.api.agent_supervisor.adapters.models.model_adapter import generate_model_response
from apps.api.agent_supervisor.domains.evaluations.outcomes import evaluate_attack_outcome
from apps.api.agent_supervisor.domains.governance.integrity import attach_audit_hashes
from apps.api.agent_supervisor.domains.governance.supervisor import decide
from apps.api.agent_supervisor.domains.governance.tool_contract import normalize_tool_call
from apps.api.agent_supervisor.domains.runtime.event_stream import publish_runtime_event
from apps.api.agent_supervisor.domains.runtime.tools import execute_tool
from apps.api.agent_supervisor.storage.data import find_scenario, get_scenarios
from apps.api.agent_supervisor.storage.database import write_run


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _trace(agent: str, role: str, message: str, status: str = "完成") -> dict:
    return {
        "id": str(uuid4()),
        "agent": agent,
        "role": role,
        "message": message,
        "status": status,
        "timestamp": _now(),
    }


def run_scenario(scenario_id: str, guard_enabled: bool = True, persist: bool = True) -> dict:
    scenario = find_scenario(scenario_id)
    run_id = str(uuid4())
    created_at = _now()
    model_result = generate_model_response(scenario["adversarial_prompt"], scenario_id)

    agent_trace = [
        _trace("规划 Agent", "red-team-planner", f"选择攻击面 `{scenario['surface_id']}`，目标工具 `{scenario['target']}`。"),
        _trace("样本生成 Agent", "sample-generator", f"生成对抗输入：{scenario['adversarial_prompt']}"),
        _trace("执行 Agent", "executor", "向目标智能体发送攻击任务，并等待工具调用意图。"),
        _trace("目标智能体", "target-agent", model_result["content"]),
    ]

    audit_logs = []
    alerts = []
    blocked_count = 0
    asked_count = 0
    isolated_count = 0
    decision_latencies: list[float] = []

    for index, raw_tool_call in enumerate(scenario["tool_calls"], start=1):
        tool_call = normalize_tool_call(raw_tool_call)
        decision_started = perf_counter()
        decision = decide(tool_call, guard_enabled, scenario["adversarial_prompt"])
        decision_latencies.append((perf_counter() - decision_started) * 1000)
        if decision.decision == "拒绝":
            blocked_count += 1
        if decision.decision == "询问":
            asked_count += 1
        if decision.decision == "隔离":
            isolated_count += 1

        tool_output = execute_tool(tool_call, decision.decision)
        log = {
            "id": str(uuid4()),
            "run_id": run_id,
            "step": index,
            "tool": tool_call["tool"],
            "arguments": tool_call.get("arguments", {}),
            "risk_hint": tool_call.get("risk_hint", ""),
            "decision": decision.decision,
            "risk_level": decision.risk_level,
            "policy_id": decision.policy_id,
            "reason": decision.reason,
            "recommendation": decision.recommendation,
            "risk_score": decision.risk_score,
            "risk_factors": decision.risk_factors,
            "anomaly_score": decision.anomaly_score,
            "anomaly_signals": decision.anomaly_signals,
            "tool_output": tool_output,
            "timestamp": _now(),
        }
        audit_logs.append(log)
        if decision.decision in {"拒绝", "询问", "隔离"}:
            alerts.append(
                {
                    "id": str(uuid4()),
                    "run_id": run_id,
                    "severity": decision.risk_level,
                    "title": f"{scenario['title']} - {decision.decision}",
                    "decision": decision.decision,
                    "evidence": decision.reason,
                    "risk_score": decision.risk_score,
                    "risk_factors": decision.risk_factors,
                    "anomaly_score": decision.anomaly_score,
                    "anomaly_signals": decision.anomaly_signals,
                    "created_at": _now(),
                }
            )
        agent_trace.append(
            _trace(
                "行为监督器",
                "guard",
                f"工具 `{tool_call['tool']}` 判定为 `{decision.decision}`：{decision.reason}",
            )
        )

    attack_outcome = evaluate_attack_outcome(scenario, audit_logs, model_output=str(model_result.get("content", "")))
    attack_success = bool(attack_outcome["attack_success"])

    detection_latency_ms = round(sum(decision_latencies), 3)
    metrics = {
        "attack_success_rate": 100 if attack_success else 0,
        "blocked_count": blocked_count,
        "asked_count": asked_count,
        "isolated_count": isolated_count,
        "detection_latency_ms": detection_latency_ms,
        "false_positive_rate": 0,
        "false_positive_applicable": False,
    }
    attach_audit_hashes(audit_logs, seed=f"{run_id}:{created_at}")
    agent_trace.append(
        _trace(
            "评测 Agent",
            "evaluator",
            f"攻击结果：{'成功复现风险' if attack_success else '已被监督器控制'}；检测延迟 {detection_latency_ms}ms。",
        )
    )

    result = {
        "run_id": run_id,
        "created_at": created_at,
        "scenario": scenario,
        "guard_enabled": guard_enabled,
        "model_result": model_result,
        "agent_trace": agent_trace,
        "audit_logs": audit_logs,
        "alerts": alerts,
        "attack_success": attack_success,
        "attack_outcome": attack_outcome,
        "metrics": metrics,
    }
    if persist:
        write_run(result)
        publish_runtime_event(
            "scenario-run",
            {
                "run_id": run_id,
                "scenario_id": scenario_id,
                "guard_enabled": guard_enabled,
                "attack_success": attack_success,
                "metrics": metrics,
                "alert_count": len(alerts),
            },
        )
    return result


def compare_scenario(scenario_id: str) -> dict:
    without_guard = run_scenario(scenario_id, guard_enabled=False)
    with_guard = run_scenario(scenario_id, guard_enabled=True)
    return {
        "scenario_id": scenario_id,
        "without_guard": without_guard,
        "with_guard": with_guard,
        "summary": {
            "attack_success_reduced": without_guard["attack_success"] and not with_guard["attack_success"],
            "blocked_or_controlled": bool(with_guard["metrics"]["blocked_count"] or with_guard["metrics"]["asked_count"] or with_guard["metrics"]["isolated_count"]),
        },
    }


def batch_compare_scenarios(scenario_ids: list[str] | None = None) -> dict:
    ids = scenario_ids or [scenario["id"] for scenario in get_scenarios()]
    comparisons = [compare_scenario(scenario_id) for scenario_id in ids]
    guarded_runs = [item["with_guard"] for item in comparisons]
    without_guard_runs = [item["without_guard"] for item in comparisons]
    total = len(comparisons)
    controlled = sum(1 for item in comparisons if item["summary"]["blocked_or_controlled"])
    attack_reduced = sum(1 for item in comparisons if item["summary"]["attack_success_reduced"])
    exposed_without_guard = sum(1 for run in without_guard_runs if run["attack_success"])
    total_latency = sum(run["metrics"]["detection_latency_ms"] for run in guarded_runs)
    return {
        "scenario_ids": ids,
        "comparisons": comparisons,
        "summary": {
            "total": total,
            "exposed_without_guard": exposed_without_guard,
            "controlled_with_guard": controlled,
            "attack_success_reduced": attack_reduced,
            "control_rate": round((controlled / total) * 100) if total else 0,
            "avg_latency_ms": round(total_latency / total) if total else 0,
            "blocked_count": sum(run["metrics"]["blocked_count"] for run in guarded_runs),
            "asked_count": sum(run["metrics"]["asked_count"] for run in guarded_runs),
            "isolated_count": sum(run["metrics"]["isolated_count"] for run in guarded_runs),
        },
    }
