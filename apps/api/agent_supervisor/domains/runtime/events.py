from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from time import perf_counter
from typing import Any
from uuid import uuid4

from apps.api.agent_supervisor.domains.governance.approvals import create_approval_review
from apps.api.agent_supervisor.domains.governance.correlation import assess_cross_agent_chain
from apps.api.agent_supervisor.domains.governance.effect import evaluate_tool_effect
from apps.api.agent_supervisor.domains.governance.integrity import attach_audit_hashes
from apps.api.agent_supervisor.domains.governance.redaction import redact_sensitive
from apps.api.agent_supervisor.domains.governance.supervisor import GuardDecision, decide
from apps.api.agent_supervisor.domains.governance.task_profiles import (
    evaluate_task_scope,
    resolve_task_profile,
    task_audit_context,
)
from apps.api.agent_supervisor.domains.governance.tool_contract import (
    normalize_tool_call,
    resolve_public_endpoint,
)
from apps.api.agent_supervisor.domains.governance.tool_registry import resolve_tool_call
from apps.api.agent_supervisor.domains.runtime.event_stream import publish_runtime_event
from apps.api.agent_supervisor.domains.runtime.execution_receipts import (
    complete_execution,
    tool_call_hash,
    tool_result_hash,
    verify_execution_receipt,
)
from apps.api.agent_supervisor.domains.runtime.tools import RuntimePaths, default_runtime_paths, execute_tool
from apps.api.agent_supervisor.storage.database import (
    append_runtime_event,
    claim_gateway_execution,
    complete_gateway_execution_claim,
    load_audit_log,
    load_execution_receipt,
    load_gateway_execution_claim,
    mark_gateway_execution_claim_unknown,
    write_run,
)

CONTROL_DECISIONS = {"拒绝", "询问", "隔离"}


class ServerExecutionUncertainError(ValueError):
    """Raised when a supervisor-owned side effect has no final durable state."""


def evaluate_agent_event(
    event: dict[str, Any],
    guard_enabled: bool = True,
    execute_managed: bool = False,
    receipt_required: bool = True,
    runtime: RuntimePaths | None = None,
) -> dict[str, Any]:
    """Evaluate a real agent tool-call event and persist it as audit evidence."""
    raw_tool_call = event.get("tool_call") or {}
    if not isinstance(raw_tool_call, dict) or not raw_tool_call.get("tool"):
        raise ValueError("tool_call.tool 不能为空")
    agent_id = str(event.get("agent_id", "external-agent"))
    server_owned_execution = bool(event.get("server_owned_execution"))
    server_execution_key = str(event.get("_server_execution_key") or "").strip()
    tool_resolution = resolve_tool_call(raw_tool_call, agent_id=agent_id)
    original_tool_call = tool_resolution.original_tool_call
    tool_call = normalize_tool_call(tool_resolution.effective_tool_call)
    raw_stage_context = event.get("stage_context")
    raw_stage_context = raw_stage_context if isinstance(raw_stage_context, dict) else {}
    task_binding = resolve_task_profile(agent_id, raw_stage_context.get("task_id"))
    task_scope = evaluate_task_scope(task_binding, raw_tool_call, agent_id=agent_id)

    # The supervisor-owned HTTP execution endpoint derives this key from the
    # complete request.  Reusing it makes an exact retry address the same
    # durable claim instead of creating a fresh audit row that could repeat a
    # side effect.  Other callers keep the historical random identifiers.
    run_id = f"runtime-run-{server_execution_key}" if server_execution_key else str(uuid4())
    audit_id = f"runtime-{server_execution_key}" if server_execution_key else str(uuid4())
    if server_execution_key:
        replay = _load_server_execution_replay(audit_id, agent_id=agent_id)
        if replay is not None:
            return replay
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
    network_addresses: list[str] | None = None
    if decision.decision in {"允许", "询问"} and tool_call["tool"] == "api.call":
        endpoint = str(tool_call.get("arguments", {}).get("endpoint", ""))
        if endpoint.lower().startswith(("http://", "https://")):
            try:
                # Resolve every absolute target even when the policy decision is
                # already ``询问``.  A review decision must not hide a private,
                # link-local, metadata, or DNS-rebinding destination.  The
                # allowlist is enforced in ``decide``; this phase proves the
                # network address is public before any caller-owned executor can
                # continue.
                network_addresses = resolve_public_endpoint(endpoint)
            except ValueError as exc:
                # An already-held allowlist review is non-executable, so an
                # unresolved documentation/fixture hostname remains in review.
                # A private/link-local/rebinding result is different: it is a
                # hard network-boundary failure even when the earlier decision
                # was only ``询问``.
                if decision.decision == "允许" or "非公网地址" in str(exc):
                    decision = GuardDecision(
                        decision="拒绝",
                        risk_level="critical",
                        policy_id="network-boundary",
                        reason=f"网络目标解析未通过：{exc}",
                        recommendation="仅允许解析到公网地址的 HTTP(S) 目标；连接器必须复用本次解析地址。",
                        risk_score=95,
                        risk_factors=["DNS rebinding / 非公网解析地址"],
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
    if task_binding.required:
        if not task_binding.valid:
            decision = GuardDecision(
                decision="拒绝",
                risk_level="high",
                policy_id="task-profile",
                reason=task_binding.reason or "任务授权无效。",
                recommendation="由宿主应用在模型上下文外传入当前 Agent 的有效 X-Agent-Task-ID。",
                risk_score=max(decision.risk_score, 88),
            )
        elif not task_scope.allowed:
            decision = GuardDecision(
                decision="拒绝",
                risk_level="high",
                policy_id="task-profile",
                reason=task_scope.reason,
                recommendation="将工具能力和目标收窄到已发布的任务授权范围内。",
                risk_score=max(decision.risk_score, 88),
            )
        elif task_binding.require_approval and tool_call["tool"] != "model.respond" and decision.decision == "允许":
            decision = GuardDecision(
                decision="询问",
                risk_level="medium",
                policy_id="task-profile-approval",
                reason="当前任务要求在执行已允许工具前完成人工复核。",
                recommendation="确认任务范围、目标和业务目的后，再由原始 Agent 领取一次审批调用。",
                risk_score=max(decision.risk_score, 55),
            )
    detection_latency_ms = round((perf_counter() - decision_started) * 1000, 3)
    should_execute = execute_managed and decision.decision in {"允许", "隔离"}
    external_receipt_required = receipt_required and decision.decision in {"允许", "隔离"}
    # This marker is written only by the authenticated supervisor-owned
    # The flag only requests local managed execution; durable server evidence
    # still comes from the authenticated server-owned route below.
    execution_pending = bool(server_owned_execution and should_execute)
    execution_started = perf_counter()
    # The authenticated server-owned route always derives its runtime from the
    # bound Agent identity so files and queued effects stay isolated.
    effective_runtime = runtime
    if effective_runtime is None and server_owned_execution:
        effective_runtime = default_runtime_paths(agent_id)

    tool_output = (
        {
            "executed": False,
            "pending": True,
            "execution_target": "none",
            "output": "服务端已建立执行意图，等待工具执行边界。",
        }
        if execution_pending
        else execute_tool(
            tool_call,
            decision.decision,
            runtime=effective_runtime,
            network_addresses=network_addresses,
            memory_namespace=agent_id,
        )
        if should_execute
        else {
            "executed": False,
            "output": (
                f"工具调用未执行，监督决策为：{decision.decision}。"
                if execute_managed
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
    # Supervisor explanations may interpolate caller/model text.  They are
    # durable evidence too, so redact them before logs, alerts, and responses.
    audit_reason = str(redact_sensitive(decision.reason))
    audit_recommendation = str(redact_sensitive(decision.recommendation))
    stage_context = redact_sensitive(event.get("stage_context", {}))
    if not isinstance(stage_context, dict):
        stage_context = {}
    stage_context.update(task_audit_context(task_binding, task_scope.scope))
    if network_addresses:
        stage_context["resolved_network_addresses"] = list(network_addresses)

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
        "execution_receipt_expected": external_receipt_required or should_execute,
        # ``execute_managed=True`` means this process owns the executor and
        # can observe the resulting tool output.  In the normal external-Agent
        # path the caller owns execution, so a later receipt is an attestation,
        # not server-observed evidence.
        "execution_evidence": "server-owned-pending"
        if execution_pending
        else "server-observed"
        if server_owned_execution or (should_execute and bool(raw_tool_output.get("executed")))
        else "caller-declared-required"
        if external_receipt_required and not should_execute
        else "not-executed-observed",
        # For a server-owned route, a controlled non-execution is also an
        # observed enforcement result.  It is distinct from a caller-declared
        # receipt, where the supervisor cannot know whether the tool ran.
        "execution_observed_by_server": bool(
            (server_owned_execution and not execution_pending)
            or (should_execute and raw_tool_output.get("executed"))
        ),
        "execution_status": (
            "pending"
            if execution_pending
            else
            "completed"
            if execution_completed
            else "not_executed"
            if not should_execute or executor_unavailable
            else "failed"
        ),
        "execution_target": (
            "none"
            if execution_pending
            else
            str(raw_tool_output.get("execution_target") or "local-runtime")
            if execution_completed or (should_execute and raw_tool_output.get("executed") and not executor_unavailable)
            else "none"
        ),
        "risk_hint": tool_call.get("risk_hint", ""),
        "original_risk_hint": raw_tool_call.get("risk_hint", ""),
        "risk_hint_trust": "caller-untrusted" if raw_tool_call.get("risk_hint") else "none",
        "decision": decision.decision,
        "risk_level": decision.risk_level,
        "policy_id": decision.policy_id,
        "reason": audit_reason,
        "recommendation": audit_recommendation,
        "risk_score": decision.risk_score,
        "risk_factors": decision.risk_factors,
        "anomaly_score": decision.anomaly_score,
        "anomaly_signals": decision.anomaly_signals,
        "model_confidence": decision.model_confidence,
        "model_latency_ms": decision.model_latency_ms,
        "model_version": decision.model_version,
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
            "evidence": audit_reason,
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
        "expected_risk": audit_reason,
        "defense": audit_recommendation,
        "script_steps": [
            "外部智能体生成工具调用意图",
            "在执行工具前转发到智垒监督接口",
            "监督器根据策略输出允许、拒绝、询问或隔离",
            "调用方按决策执行、阻断、人工确认或受限隔离",
        ],
        "attack_path": [
            "外部智能体上下文",
            "工具调用参数",
            "智垒监督器",
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
            "risk_observation": audit_reason,
        },
        "agent_trace": [
            _trace("外部智能体", event.get("agent_role", "agent"), "生成工具调用事件并提交监督器。"),
            _trace(
                "行为监督器",
                "guard",
                f"工具 `{original_tool_call['tool']}`"
                + (f"（标准能力 `{tool_call['tool']}`）" if tool_resolution.mapped else "")
                + f" 判定为 `{decision.decision}`：{audit_reason}",
            ),
            _trace("接入适配器", event.get("source_app", "generic-agent"), f"建议处置：{_execution_mode(decision.decision)}。"),
        ],
        "audit_logs": [audit_log],
        "alerts": [alert] if alert else [],
        "attack_success": attack_success,
        "attack_outcome": {
            "attack_success": attack_success,
            "source": "observed-local-runtime-effect" if should_execute else "pre-execution-no-effect-observed",
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
    execution_claim_id = ""
    if execution_pending:
        # Reserve the side-effect boundary before the first persistence write.
        # Two identical HTTP retries therefore contend for one durable claim;
        # only the winner can reach the executor.
        execution_claim_id = f"runtime-claim-{uuid4().hex}"
        try:
            claim = claim_gateway_execution(
                audit_id=audit_id,
                claim_id=execution_claim_id,
                agent_id=agent_id,
                session_id=str(event.get("conversation_id") or ""),
                tool_call_hash=str(audit_log.get("tool_call_hash") or ""),
                created_at=created_at,
            )
        except Exception:
            raise
        if claim.get("status") == "unknown":
            raise ServerExecutionUncertainError(
                "服务端工具执行状态不确定，已冻结执行占用，需先完成核查"
            )
        if claim.get("status") == "completed":
            replay = _load_server_execution_replay(audit_id, agent_id=agent_id)
            if replay is None:
                raise ServerExecutionUncertainError(
                    "服务端执行占用已完成但缺少有效回执，拒绝重放"
                )
            return replay
        try:
            # Persist the immutable intent before the side effect.  If this
            # fails, no tool execution has started and the claim is frozen.
            write_run(result, append_runtime_event=False)
        except Exception as exc:
            _freeze_server_execution_claim(
                audit_id=audit_id,
                claim_id=execution_claim_id,
                agent_id=agent_id,
                session_id=str(event.get("conversation_id") or ""),
                phase="intent-persistence",
                error=exc,
            )
            raise ServerExecutionUncertainError(
                "服务端执行意图落库失败，已冻结执行占用，未继续执行工具"
            ) from exc

        execution_started = perf_counter()
        try:
            raw_tool_output = execute_tool(
                tool_call,
                decision.decision,
                # Reuse the identity-bound path selected before the intent is
                # persisted.  Falling back to ``runtime=None`` here would
                # silently route the second phase to the process-wide runtime
                # workspace and break the Agent isolation invariant.
                runtime=effective_runtime,
                network_addresses=network_addresses,
                memory_namespace=agent_id,
            )
        except Exception as exc:
            _freeze_server_execution_claim(
                audit_id=audit_id,
                claim_id=execution_claim_id,
                agent_id=agent_id,
                session_id=str(event.get("conversation_id") or ""),
                phase="tool-execution",
                error=exc,
            )
            raise ServerExecutionUncertainError(
                "服务端工具执行状态不确定，已冻结执行占用，需先完成核查"
            ) from exc
        execution_duration_ms = round((perf_counter() - execution_started) * 1000, 3)
        if not isinstance(raw_tool_output, dict):
            raw_tool_output = {"executed": False, "output": "执行器返回了无效结果。"}
        executor_unavailable = str(raw_tool_output.get("executor", "")) == "unavailable"
        execution_completed = (
            bool(raw_tool_output.get("executed"))
            and not bool(raw_tool_output.get("timed_out"))
            and raw_tool_output.get("exit_code") in {None, 0}
        )
        audit_tool_output = redact_sensitive(raw_tool_output)
        audit_log.update(
            {
                "execution_evidence": "server-observed",
                "execution_observed_by_server": True,
                "execution_status": (
                    "completed"
                    if execution_completed
                    else "not_executed"
                    if executor_unavailable or not raw_tool_output.get("executed")
                    else "failed"
                ),
                "execution_target": (
                    str(raw_tool_output.get("execution_target") or "local-runtime")
                    if raw_tool_output.get("executed") and not executor_unavailable
                    else "none"
                ),
                "tool_output": audit_tool_output,
                "execution_duration_ms": execution_duration_ms,
            }
        )
        attach_audit_hashes([audit_log], seed=f"{run_id}:{created_at}")
        observed_effect = evaluate_tool_effect(
            tool_call,
            decision.decision,
            raw_tool_output,
            model_output=str(event.get("model_output", "")),
        )
        attack_success = bool(observed_effect["observed"])
        result["attack_success"] = attack_success
        result["attack_outcome"] = {
            "attack_success": attack_success,
            "source": "observed-local-runtime-effect",
            "assertions": [observed_effect],
        }
        existing_metrics = result.get("metrics")
        metrics: dict[str, Any] = existing_metrics if isinstance(existing_metrics, dict) else {}
        result["metrics"] = {
            **metrics,
            "attack_success_rate": 100 if attack_success else 0,
        }
        try:
            # The final snapshot is the only run event exposed as current
            # evidence.  The earlier intent remains in the audit row history
            # only through its claim and is never treated as a completed run.
            write_run(result, append_runtime_event=True)
        except Exception as exc:
            _freeze_server_execution_claim(
                audit_id=audit_id,
                claim_id=execution_claim_id,
                agent_id=agent_id,
                session_id=str(event.get("conversation_id") or ""),
                phase="result-persistence",
                error=exc,
            )
            raise ServerExecutionUncertainError(
                "工具已越过执行边界但最终审计落库失败，已冻结执行占用，需先完成核查"
            ) from exc
    else:
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
        "reason": audit_reason,
        "recommendation": audit_recommendation,
        "execution_mode": _execution_mode(decision.decision),
        "execution_receipt_required": external_receipt_required and not execute_managed,
        "execution_status": (
            audit_log["execution_status"]
            if execute_managed or not external_receipt_required
            else "awaiting_receipt"
        ),
        "execution_target": audit_log["execution_target"] if execute_managed else "none",
        "execution_evidence": audit_log["execution_evidence"],
        "execution_observed_by_server": audit_log["execution_observed_by_server"],
        "execution_duration_ms": execution_duration_ms,
        "surface_id": surface_id,
        "risk_evidence": {
            "tool": original_tool_call["tool"],
            "standard_capability": tool_call["tool"],
            "standard_arguments": audit_standard_arguments,
            "tool_mapping": tool_resolution.mapping,
            "risk_hint": tool_call.get("risk_hint", ""),
            "risk_hint_trust": "caller-untrusted" if raw_tool_call.get("risk_hint") else "none",
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
    if server_owned_execution:
        # The supervisor-owned route must leave the same signed receipt that an
        # external caller would otherwise have to submit.  This makes blocked
        # calls observable too: ``not_executed/none`` is a server fact, not a
        # promise from the Agent.  The original tool call is used so custom
        # tool mappings remain bound to their immutable audit hash.
        receipt_status = str(audit_log["execution_status"])
        receipt_target = str(audit_log["execution_target"])
        receipt_result_content = _tool_result_for_receipt(raw_tool_output)
        receipt_result_hash = tool_result_hash(receipt_result_content) if receipt_status in {"completed", "failed"} else ""
        try:
            receipt_result = complete_execution(
                audit_id,
                {
                    "receipt_id": f"server-{uuid4().hex}",
                    "agent_id": agent_id,
                    "tool_call": original_tool_call,
                    "status": receipt_status,
                    "execution_target": receipt_target,
                    "result_hash": receipt_result_hash,
                    "result_content": receipt_result_content,
                    "duration_ms": execution_duration_ms,
                    "error": "" if receipt_status == "completed" else str(raw_tool_output.get("error") or raw_tool_output.get("output") or ""),
                },
                server_observed=True,
            )
        except Exception as exc:
            if execution_pending:
                _freeze_server_execution_claim(
                    audit_id=audit_id,
                    claim_id=execution_claim_id,
                    agent_id=agent_id,
                    session_id=str(event.get("conversation_id") or ""),
                    phase="receipt-persistence",
                    error=exc,
                )
                raise ServerExecutionUncertainError(
                    "工具已执行但服务端回执落库失败，已冻结执行占用，需先完成核查"
                ) from exc
            raise
        response["execution_receipt"] = receipt_result.get("receipt")
        result["execution_receipt"] = receipt_result.get("receipt")
        if execution_pending:
            try:
                complete_gateway_execution_claim(
                    audit_id=audit_id,
                    claim_id=execution_claim_id,
                    receipt_id=str((receipt_result.get("receipt") or {}).get("receipt_id") or ""),
                    completed_at=_now(),
                )
            except Exception as exc:
                _freeze_server_execution_claim(
                    audit_id=audit_id,
                    claim_id=execution_claim_id,
                    agent_id=agent_id,
                    session_id=str(event.get("conversation_id") or ""),
                    phase="claim-completion",
                    error=exc,
                )
                raise ServerExecutionUncertainError(
                    "服务端回执已写入但执行占用状态不确定，已冻结执行占用，需先完成核查"
                ) from exc
    response["approval_review"] = create_approval_review(event, response)
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


def _tool_result_for_receipt(raw_tool_output: dict[str, Any]) -> Any:
    """Return the exact bounded value represented by a managed tool result."""
    redacted = redact_sensitive(raw_tool_output.get("output", ""))
    if isinstance(redacted, str):
        return redacted[:12_000]
    return json.dumps(redacted, ensure_ascii=False, sort_keys=True, default=str)[:12_000]


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
        "隔离": "只允许在受限权限边界内执行",
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
    if tool in {"file.read", "api.call", "mail.send"}:
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


def _load_server_execution_replay(audit_id: str, *, agent_id: str) -> dict[str, Any] | None:
    """Return an idempotent response for an already observed server execution."""

    claim = load_gateway_execution_claim(audit_id)
    if claim and str(claim.get("status") or "") == "unknown":
        raise ServerExecutionUncertainError(
            "服务端工具执行状态不确定，已冻结执行占用，需先完成核查"
        )
    audit_log = load_audit_log(audit_id)
    receipt = load_execution_receipt(audit_id)
    if audit_log is None and receipt is None:
        return None
    if audit_log is None or receipt is None:
        raise ServerExecutionUncertainError("服务端执行记录不完整，拒绝重放")
    if str(audit_log.get("agent_id") or "") != agent_id or str(receipt.get("agent_id") or "") != agent_id:
        raise ValueError("重放请求的 Agent 与原始服务端执行记录不一致")
    if receipt.get("execution_evidence") != "server-observed" or receipt.get("execution_observed_by_server") is not True:
        raise ValueError("已有回执不是服务端观察证据，拒绝重放")
    if not verify_execution_receipt(receipt):
        raise ServerExecutionUncertainError("已有服务端执行回执完整性校验失败，拒绝重放")
    if str(receipt.get("audit_hash") or "") != str(audit_log.get("audit_hash") or ""):
        raise ServerExecutionUncertainError("服务端执行回执与当前审计 Hash 不一致，拒绝重放")
    decision = str(audit_log.get("decision") or "未知")
    status = str(receipt.get("status") or "unknown")
    target = str(receipt.get("execution_target") or "none")
    return {
        "run_id": str(audit_log.get("run_id") or ""),
        "audit_id": audit_id,
        "persisted": True,
        "idempotent": True,
        "decision": decision,
        "risk_level": str(audit_log.get("risk_level") or "medium"),
        "risk_score": int(audit_log.get("risk_score") or 0),
        "risk_factors": audit_log.get("risk_factors") or [],
        "anomaly_score": int(audit_log.get("anomaly_score") or 0),
        "anomaly_signals": audit_log.get("anomaly_signals") or [],
        "policy_id": str(audit_log.get("policy_id") or ""),
        "reason": str(audit_log.get("reason") or ""),
        "recommendation": str(audit_log.get("recommendation") or ""),
        "execution_mode": _execution_mode(decision),
        "execution_receipt_required": False,
        "execution_status": status,
        "execution_target": target,
        "execution_evidence": "server-observed",
        "execution_observed_by_server": True,
        "execution_duration_ms": float(receipt.get("duration_ms") or 0),
        "surface_id": _surface_from_event(
            {"tool": audit_log.get("tool"), "risk_hint": audit_log.get("risk_hint")},
            str(audit_log.get("policy_id") or ""),
        ),
        "risk_evidence": {
            "tool": audit_log.get("tool", ""),
            "standard_capability": audit_log.get("standard_capability", ""),
            "standard_arguments": audit_log.get("standard_arguments", {}),
            "tool_mapping": audit_log.get("tool_mapping", {}),
            "risk_hint": audit_log.get("risk_hint", ""),
            "risk_hint_trust": audit_log.get("risk_hint_trust", "none"),
            "arguments": audit_log.get("arguments", {}),
            "context_sources": [],
            "model_input_excerpt": "",
            "model_output_excerpt": "",
            "detection_points": [],
            "risk_score": int(audit_log.get("risk_score") or 0),
            "risk_factors": audit_log.get("risk_factors") or [],
            "anomaly_score": int(audit_log.get("anomaly_score") or 0),
            "anomaly_signals": audit_log.get("anomaly_signals") or [],
            "cross_agent_chain": audit_log.get("cross_agent_chain") or {},
            "stage_context": audit_log.get("stage_context") or {},
        },
        "audit_log": audit_log,
        "execution_result_hash": str(receipt.get("result_hash") or ""),
        "execution_receipt": receipt,
        "alert": None,
        "attack_success": status == "completed",
        "attack_outcome": {
            "attack_success": status == "completed",
            "source": "server-observed-replay",
            "assertions": [{"status": status, "execution_target": target}],
        },
    }


def _freeze_server_execution_claim(
    *,
    audit_id: str,
    claim_id: str,
    agent_id: str,
    session_id: str,
    phase: str,
    error: Exception,
) -> None:
    """Freeze a generic server-owned claim after a side-effect boundary error."""

    created_at = _now()
    try:
        mark_gateway_execution_claim_unknown(
            audit_id=audit_id,
            claim_id=claim_id,
            completed_at=created_at,
        )
        append_runtime_event(
            "server-execution-uncertain",
            {
                "audit_id": audit_id,
                "claim_id": claim_id,
                "agent_id": agent_id,
                "session_id": session_id,
                "phase": phase,
                "status": "unknown",
                "error": str(redact_sensitive(str(error)))[:2000],
                "created_at": created_at,
            },
            created_at=created_at,
        )
    except Exception as exc:
        raise ServerExecutionUncertainError(
            "服务端工具执行状态不确定，未知状态冻结或事件记录失败，请检查审计存储"
        ) from exc
