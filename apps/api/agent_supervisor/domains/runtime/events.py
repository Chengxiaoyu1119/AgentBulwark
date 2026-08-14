from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from time import perf_counter
from typing import Any
from uuid import uuid4

from apps.api.agent_supervisor.domains.evaluations.outcomes import evaluate_tool_effect
from apps.api.agent_supervisor.domains.governance.approvals import create_approval_review
from apps.api.agent_supervisor.domains.governance.correlation import assess_cross_agent_chain
from apps.api.agent_supervisor.domains.governance.integrity import attach_audit_hashes
from apps.api.agent_supervisor.domains.governance.redaction import redact_sensitive
from apps.api.agent_supervisor.domains.governance.supervisor import decide
from apps.api.agent_supervisor.domains.governance.tool_contract import normalize_tool_call
from apps.api.agent_supervisor.domains.governance.tool_registry import resolve_tool_call
from apps.api.agent_supervisor.domains.runtime.event_stream import publish_runtime_event
from apps.api.agent_supervisor.domains.runtime.execution_receipts import tool_call_hash
from apps.api.agent_supervisor.domains.runtime.tools import SandboxPaths, execute_tool
from apps.api.agent_supervisor.storage.database import write_run

CONTROL_DECISIONS = {"拒绝", "询问", "隔离"}


def evaluate_agent_event(
    event: dict[str, Any],
    guard_enabled: bool = True,
    execute_in_sandbox: bool = False,
    review_scope: str = "operational",
    sandbox: SandboxPaths | None = None,
) -> dict[str, Any]:
    """Evaluate a real agent tool-call event and persist it as audit evidence."""
    raw_tool_call = event.get("tool_call") or {}
    if not isinstance(raw_tool_call, dict) or not raw_tool_call.get("tool"):
        raise ValueError("tool_call.tool 不能为空")
    agent_id = str(event.get("agent_id", "external-agent"))
    tool_resolution = resolve_tool_call(raw_tool_call, agent_id=agent_id)
    original_tool_call = tool_resolution.original_tool_call
    tool_call = normalize_tool_call(tool_resolution.effective_tool_call)

    run_id = str(uuid4())
    audit_id = str(uuid4())
    created_at = _now()
    model_input = str(event.get("model_input", ""))
    context_sources = event.get("context_sources", [])
    if not isinstance(context_sources, list):
        context_sources = []
    decision_started = perf_counter()
    decision = decide(
        raw_tool_call,
        guard_enabled=guard_enabled,
        prompt=model_input,
        context_sources=[str(item) for item in context_sources],
        agent_id=agent_id,
    )
    chain_assessment = assess_cross_agent_chain(event, tool_call)
    if guard_enabled and chain_assessment["escalated"]:
        chain_signals = [f"跨 Agent 关联：{item}" for item in chain_assessment["signals"]]
        decision.anomaly_signals = [*decision.anomaly_signals, *chain_signals]
        decision.risk_factors = [*decision.risk_factors, *chain_signals]
        decision.risk_score = max(decision.risk_score, 88)
        decision.anomaly_score = max(decision.anomaly_score, 72)
        if decision.decision == "允许":
            decision.decision = "询问"
            decision.risk_level = "high"
            decision.policy_id = "cross-agent-chain"
            decision.reason = "同一会话内出现敏感读取、批量导出或记忆访问后继续发送结果，疑似跨 Agent 分步外泄链。"
            decision.recommendation = "暂停自动执行，人工确认前序数据来源、当前收件人和业务授权。"
    detection_latency_ms = round((perf_counter() - decision_started) * 1000, 3)
    should_execute = execute_in_sandbox and decision.decision in {"允许", "隔离"}
    execution_started = perf_counter()
    tool_output = (
        execute_tool(tool_call, decision.decision, sandbox=sandbox)
        if should_execute
        else {
            "executed": False,
            "sandboxed": True,
            "output": (
                f"工具调用未执行，监督决策为：{decision.decision}。"
                if execute_in_sandbox
                else "监督已完成，等待外部 Agent 按决策执行并提交回执。"
            ),
        }
    )
    execution_duration_ms = round((perf_counter() - execution_started) * 1000, 3)
    raw_tool_output = tool_output
    executor_unavailable = str(raw_tool_output.get("executor", "")) == "unavailable"
    execution_completed = (
        should_execute
        and bool(raw_tool_output.get("executed"))
        and not bool(raw_tool_output.get("timed_out"))
        and raw_tool_output.get("exit_code") in {None, 0}
    )
    audit_tool_output = redact_sensitive(tool_output)
    audit_arguments = redact_sensitive(original_tool_call.get("arguments", {}))
    audit_standard_arguments = redact_sensitive(tool_call.get("arguments", {}))
    audit_model_input = str(redact_sensitive(model_input))
    audit_model_output = str(redact_sensitive(str(event.get("model_output", ""))))
    stage_context = redact_sensitive(event.get("stage_context", {}))

    surface_id = _surface_from_event(tool_call, decision.policy_id)
    audit_log = {
        "id": audit_id,
        "run_id": run_id,
        "step": 1,
        "tool": original_tool_call["tool"],
        "arguments": audit_arguments,
        "tool_call_hash": tool_call_hash(raw_tool_call),
        "standard_capability": tool_call["tool"],
        "standard_arguments": audit_standard_arguments,
        "tool_mapping": tool_resolution.mapping,
        "execution_receipt_expected": review_scope == "operational" or should_execute,
        "execution_status": (
            "completed"
            if execution_completed
            else "not_executed"
            if not should_execute or executor_unavailable
            else "failed"
        ),
        "execution_target": (
            str(raw_tool_output.get("execution_target") or "sandbox")
            if execution_completed or (should_execute and raw_tool_output.get("executed") and not executor_unavailable)
            else "none"
        ),
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
        "cross_agent_chain": chain_assessment,
        "tool_output": audit_tool_output,
        "execution_duration_ms": execution_duration_ms,
        "stage_context": stage_context if isinstance(stage_context, dict) else {},
        "timestamp": created_at,
        "source_app": event.get("source_app", "generic-agent"),
        "conversation_id": event.get("conversation_id", "external-conversation"),
        "agent_id": agent_id,
        "authenticated_role": event.get("authenticated_role", ""),
        "authenticated_agent_id": event.get("authenticated_agent_id", ""),
        "agent_identity_verified": bool(event.get("agent_identity_verified", False)),
        "agent_identity_admin_override": bool(event.get("agent_identity_admin_override", False)),
        "agent_identity_shared_compatibility": bool(event.get("agent_identity_shared_compatibility", False)),
    }
    attach_audit_hashes([audit_log], seed=f"{run_id}:{created_at}")
    alert = None
    if decision.decision in CONTROL_DECISIONS:
        alert = {
            "id": str(uuid4()),
            "run_id": run_id,
            "severity": decision.risk_level,
            "title": f"外部智能体事件 - {decision.decision}",
            "decision": decision.decision,
            "evidence": decision.reason,
            "risk_score": decision.risk_score,
            "risk_factors": decision.risk_factors,
            "anomaly_score": decision.anomaly_score,
            "anomaly_signals": decision.anomaly_signals,
            "created_at": created_at,
        }

    blocked_count = 1 if decision.decision == "拒绝" else 0
    asked_count = 1 if decision.decision == "询问" else 0
    isolated_count = 1 if decision.decision == "隔离" else 0
    observed_effect = evaluate_tool_effect(
        tool_call,
        decision.decision,
        raw_tool_output,
        model_output=str(event.get("model_output", "")),
    )
    attack_success = bool(observed_effect["observed"])

    scenario = {
        "id": f"EXTERNAL-{original_tool_call['tool'].upper().replace('.', '-')}",
        "surface_id": surface_id,
        "title": f"外部智能体工具调用：{original_tool_call['tool']}",
        "severity": decision.risk_level,
        "target": original_tool_call["tool"],
        "adversarial_prompt": audit_model_input,
        "jailbreak_case": "外部智能体运行时事件，由实际模型输入、输出、工具参数共同构成。",
        "expected_risk": decision.reason,
        "defense": decision.recommendation,
        "script_steps": [
            "外部智能体生成工具调用意图",
            "在执行工具前转发到智安哨监督接口",
            "监督器根据策略输出允许、拒绝、询问或隔离",
            "调用方按决策执行、阻断、人工确认或沙箱隔离",
        ],
        "attack_path": [
            "外部智能体上下文",
            "工具调用参数",
            "智安哨监督器",
            _execution_mode(decision.decision),
        ],
        "detection_points": _detection_points(event, tool_call, decision.policy_id)
        + ([f"工具映射：{original_tool_call['tool']} → {tool_call['tool']}"] if tool_resolution.mapped else []),
        "success_criteria": [
            "接口返回明确决策和策略命中原因",
            "审计日志可在监督端查询",
            "高风险工具调用不会被默认真实执行",
        ],
        "safety_boundary": "外部接入接口默认只判定和记录，不发送真实邮件、不读取真实文件、不替代真实外部系统执行工具。",
        "tags": ["external-agent-event", surface_id, decision.policy_id],
        "tool_calls": [
            {
                **original_tool_call,
                "arguments": audit_arguments,
                "standard_capability": tool_call["tool"],
                "standard_arguments": audit_standard_arguments,
            }
        ],
    }

    result = {
        "run_id": run_id,
        "created_at": created_at,
        "scenario": scenario,
        "guard_enabled": guard_enabled,
        "model_result": {
            "provider": "external-agent",
            "scenario_id": scenario["id"],
            "content": audit_model_output[:1200],
            "risk_observation": decision.reason,
        },
        "agent_trace": [
            _trace("外部智能体", event.get("agent_role", "agent"), "生成工具调用事件并提交监督器。"),
            _trace(
                "行为监督器",
                "guard",
                f"工具 `{original_tool_call['tool']}`"
                + (f"（标准能力 `{tool_call['tool']}`）" if tool_resolution.mapped else "")
                + f" 判定为 `{decision.decision}`：{decision.reason}",
            ),
            _trace("接入适配器", event.get("source_app", "generic-agent"), f"建议处置：{_execution_mode(decision.decision)}。"),
        ],
        "audit_logs": [audit_log],
        "alerts": [alert] if alert else [],
        "attack_success": attack_success,
        "attack_outcome": {
            "attack_success": attack_success,
            "source": "observed-sandbox-effect" if should_execute else "pre-execution-no-effect-observed",
            "assertions": [observed_effect],
        },
        "metrics": {
            "attack_success_rate": 100 if attack_success else 0,
            "blocked_count": blocked_count,
            "asked_count": asked_count,
            "isolated_count": isolated_count,
            "detection_latency_ms": detection_latency_ms,
            "false_positive_rate": 0,
            "false_positive_applicable": False,
        },
    }
    write_run(result)

    response = {
        "run_id": run_id,
        "audit_id": audit_id,
        "persisted": True,
        "decision": decision.decision,
        "risk_level": decision.risk_level,
        "risk_score": decision.risk_score,
        "risk_factors": decision.risk_factors,
        "anomaly_score": decision.anomaly_score,
        "anomaly_signals": decision.anomaly_signals,
        "policy_id": decision.policy_id,
        "reason": decision.reason,
        "recommendation": decision.recommendation,
        "execution_mode": _execution_mode(decision.decision),
        "execution_receipt_required": review_scope == "operational" and not should_execute,
        "execution_status": audit_log["execution_status"] if execute_in_sandbox else "awaiting_receipt",
        "execution_duration_ms": execution_duration_ms,
        "surface_id": surface_id,
        "risk_evidence": {
            "tool": original_tool_call["tool"],
            "standard_capability": tool_call["tool"],
            "standard_arguments": audit_standard_arguments,
            "tool_mapping": tool_resolution.mapping,
            "risk_hint": tool_call.get("risk_hint", ""),
            "arguments": audit_arguments,
            "context_sources": event.get("context_sources", []),
            "model_input_excerpt": audit_model_input[:240],
            "model_output_excerpt": audit_model_output[:240],
            "detection_points": scenario["detection_points"],
            "risk_score": decision.risk_score,
            "risk_factors": decision.risk_factors,
            "anomaly_score": decision.anomaly_score,
            "anomaly_signals": decision.anomaly_signals,
            "cross_agent_chain": chain_assessment,
            "stage_context": stage_context if isinstance(stage_context, dict) else {},
        },
        "audit_log": audit_log,
        "execution_result_hash": _payload_hash(raw_tool_output) if raw_tool_output.get("executed") else "",
        "alert": alert,
        "attack_success": attack_success,
        "attack_outcome": result["attack_outcome"],
    }
    response["approval_review"] = create_approval_review(event, response, review_scope=review_scope)
    publish_runtime_event(
        "supervisor-decision",
        {
            "run_id": run_id,
            "audit_id": audit_id,
            "decision": decision.decision,
            "risk_level": decision.risk_level,
            "risk_score": decision.risk_score,
            "anomaly_score": decision.anomaly_score,
            "policy_id": decision.policy_id,
            "tool": original_tool_call["tool"],
            "standard_capability": tool_call["tool"],
            "alert": alert,
            "approval_review": response["approval_review"],
        },
    )
    return response


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _payload_hash(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _trace(agent: str, role: str, message: str) -> dict[str, str]:
    return {
        "id": str(uuid4()),
        "agent": agent,
        "role": role,
        "message": message,
        "status": "完成",
        "timestamp": _now(),
    }


def _execution_mode(decision: str) -> str:
    return {
        "允许": "允许真实外部系统继续执行，但保留审计记录",
        "拒绝": "阻断工具调用",
        "询问": "暂停并等待人工确认",
        "隔离": "只允许在沙箱或低权限环境执行",
    }.get(decision, "记录后继续")


def _surface_from_event(tool_call: dict[str, Any], policy_id: str) -> str:
    risk_hint = str(tool_call.get("risk_hint", ""))
    tool = str(tool_call.get("tool", ""))
    if "prompt" in risk_hint or policy_id == "external-mail":
        return "prompt-injection"
    if "jailbreak" in risk_hint or "rewrite" in risk_hint or "refusal" in risk_hint or policy_id == "jailbreak-filter":
        return "jailbreak"
    if "training_data" in risk_hint or "sensitive" in risk_hint or "leak" in risk_hint:
        return "data-leakage"
    if "bulk" in risk_hint or policy_id == "bulk-action-review":
        return "abuse-risk"
    if "poison" in risk_hint or tool.startswith("memory."):
        return "memory-poison"
    if (
        "environment" in risk_hint
        or "pollution" in risk_hint
        or "untrusted_tool_return" in risk_hint
        or policy_id in {"environment-trust", "tool-return-trust"}
    ):
        return "environment-pollution"
    if tool in {"file.read", "api.call", "code.run", "mail.send"}:
        return "tool-hijack"
    return "tool-hijack"


def _detection_points(event: dict[str, Any], tool_call: dict[str, Any], policy_id: str) -> list[str]:
    points = [f"策略命中：{policy_id}", f"工具：{tool_call.get('tool', '')}"]
    risk_hint = tool_call.get("risk_hint")
    if risk_hint:
        points.append(f"风险提示：{risk_hint}")
    context_sources = event.get("context_sources") or []
    if context_sources:
        points.append(f"上下文来源：{', '.join(map(str, context_sources))}")
    return points
