from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
from typing import Any
from uuid import uuid4

from apps.api.agent_supervisor.adapters.models.model_adapter import (
    filter_model_output,
    generate_model_tool_followup,
    generate_model_tool_plan,
)
from apps.api.agent_supervisor.domains.governance.redaction import redact_sensitive
from apps.api.agent_supervisor.domains.runtime.events import evaluate_agent_event
from apps.api.agent_supervisor.domains.runtime.execution_receipts import complete_execution
from apps.api.agent_supervisor.domains.runtime.tools import execute_tool, init_sandbox
from apps.api.agent_supervisor.paths import SANDBOX_REPORTS_DIR

REPORT_DIR = SANDBOX_REPORTS_DIR


def run_model_driven_agent(
    task: str,
    *,
    force_real_model: bool = False,
    target_model: str = "",
    output_root: str | Path | None = None,
) -> dict[str, Any]:
    """Run model-generated tool calls through decision, execution, receipt, and model follow-up."""
    if not task.strip():
        raise ValueError("task 不能为空")
    init_sandbox()
    scenario_id = f"MODEL-AGENT-{uuid4()}"
    agent_id = "model-driven-agent"
    plan = generate_model_tool_plan(
        task,
        scenario_id,
        force_real=force_real_model,
        model_override=target_model,
        provider_profile="target",
    )
    raw_tool_calls = plan.get("tool_calls")
    tool_calls = raw_tool_calls if isinstance(raw_tool_calls, list) else []
    if not tool_calls or not isinstance(tool_calls[0], dict):
        raise ValueError("模型没有生成可执行的结构化工具调用")
    tool_call = dict(tool_calls[0])
    tool_call_id = str(tool_call.pop("id", "") or f"call-{uuid4()}")

    decision = evaluate_agent_event(
        {
            "conversation_id": scenario_id,
            "agent_id": agent_id,
            "agent_role": "model-tool-agent",
            "source_app": "ModelDrivenAgent",
            "model_input": task,
            "model_output": json.dumps({"tool_call_id": tool_call_id, "tool_call": tool_call}, ensure_ascii=False),
            "tool_call": tool_call,
            "context_sources": ["user", "model-tool-plan"],
        },
        guard_enabled=True,
        execute_in_sandbox=False,
        review_scope="demo",
    )

    started = perf_counter()
    status = "not_executed"
    execution_target = "none"
    execution_error = ""
    tool_output: dict[str, Any] = {
        "executed": False,
        "sandboxed": True,
        "status": "not_executed",
        "output": f"监督决策为 {decision['decision']}，工具没有进入执行器。",
    }
    if decision["decision"] in {"允许", "隔离"}:
        execution_target = "sandbox"
        try:
            tool_output = execute_tool(tool_call, decision["decision"])
            exit_code = tool_output.get("exit_code")
            execution_ok = bool(tool_output.get("executed")) and not tool_output.get("timed_out") and exit_code in {None, 0}
            status = "completed" if execution_ok else "failed"
            if status == "failed":
                execution_error = str(tool_output.get("output", "工具返回未执行状态"))
        except Exception as exc:  # noqa: BLE001 - the failure must become receipt evidence
            status = "failed"
            execution_error = str(exc)
            tool_output = {
                "executed": False,
                "sandboxed": True,
                "status": "failed",
                "output": f"受控执行器异常：{exc}",
            }
    duration_ms = round((perf_counter() - started) * 1000, 3)
    result_hash = _result_hash(tool_output) if status in {"completed", "failed"} else ""
    receipt_result = complete_execution(
        decision["audit_id"],
        {
            "receipt_id": str(uuid4()),
            "agent_id": agent_id,
            "tool_call": tool_call,
            "status": status,
            "execution_target": execution_target,
            "result_hash": result_hash,
            "duration_ms": duration_ms,
            "error": execution_error,
        },
    )
    receipt = receipt_result["receipt"]

    safe_tool_output = redact_sensitive(tool_output)
    followup = generate_model_tool_followup(
        task,
        scenario_id,
        plan,
        {"id": tool_call_id, **tool_call},
        safe_tool_output if isinstance(safe_tool_output, dict) else {"output": str(safe_tool_output)},
        force_real=force_real_model,
        provider_profile="target",
    )
    output_filter = filter_model_output(str(followup.get("content", "")))
    plan_content_hash = _result_hash(str(redact_sensitive(str(plan.get("content", "")))))
    followup_content_hash = _result_hash(output_filter["filtered"])
    plan_reasoning_hash = _optional_hash(plan.get("reasoning_content"))
    followup_reasoning_hash = _optional_hash(followup.get("reasoning_content"))
    plan_response_hash = _result_hash(
        {
            "provider": plan.get("provider"),
            "model": plan.get("model"),
            "mode": plan.get("mode"),
            "finish_reason": plan.get("finish_reason"),
            "content_hash": plan_content_hash,
            "reasoning_content_hash": plan_reasoning_hash,
            "request_hash": plan.get("request_hash", ""),
            "provider_response_hash": plan.get("provider_response_hash", ""),
            "tool_call": {"id": tool_call_id, **tool_call},
            "usage": plan.get("usage", {}),
        }
    )
    followup_response_hash = _result_hash(
        {
            "provider": followup.get("provider"),
            "model": followup.get("model"),
            "mode": followup.get("mode"),
            "finish_reason": followup.get("finish_reason", ""),
            "content_hash": followup_content_hash,
            "reasoning_content_hash": followup_reasoning_hash,
            "request_hash": followup.get("request_hash", ""),
            "provider_response_hash": followup.get("provider_response_hash", ""),
            "requires_additional_tool_call": bool(followup.get("requires_additional_tool_call")),
        }
    )
    protocol_evidence_complete = bool(
        decision["audit_log"].get("audit_hash")
        and receipt.get("receipt_hash")
        and receipt.get("tool_call_hash") == decision["audit_log"].get("tool_call_hash")
        and receipt.get("agent_followed_decision")
        and not followup.get("requires_additional_tool_call")
    )
    evidence_gaps = _real_model_evidence_gaps(plan, followup, protocol_evidence_complete)
    real_model_evidence_valid = not evidence_gaps
    evidence_chain_hash = _result_hash(
        {
            "plan_response_hash": plan_response_hash,
            "tool_call_hash": receipt.get("tool_call_hash"),
            "audit_hash": decision["audit_log"].get("audit_hash"),
            "result_hash": result_hash,
            "receipt_hash": receipt.get("receipt_hash"),
            "followup_response_hash": followup_response_hash,
        }
    )
    result = {
        "schema_version": "agent-supervisor.model-driven-agent.v2",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "task": task,
        "scenario_id": scenario_id,
        "agent_id": agent_id,
        "model_plan": {
            "provider": plan.get("provider"),
            "model": plan.get("model"),
            "mode": plan.get("mode"),
            "finish_reason": plan.get("finish_reason"),
            "usage": plan.get("usage", {}),
            "provider_failures": plan.get("provider_failures", []),
            "request_hash": plan.get("request_hash", ""),
            "provider_response_hash": plan.get("provider_response_hash", ""),
            "provider_response_id": plan.get("provider_response_id", ""),
            "provider_created": plan.get("provider_created"),
            "system_fingerprint": plan.get("system_fingerprint", ""),
            "tool_call_parse_issues": plan.get("tool_call_parse_issues", []),
            "content_hash": plan_content_hash,
            "reasoning_content_hash": plan_reasoning_hash,
            "response_hash": plan_response_hash,
        },
        "tool_call": {"id": tool_call_id, **tool_call},
        "supervision": {
            "run_id": decision["run_id"],
            "audit_id": decision["audit_id"],
            "audit_hash": decision["audit_log"].get("audit_hash"),
            "audit_signature": decision["audit_log"].get("audit_signature"),
            "decision": decision["decision"],
            "policy_id": decision["policy_id"],
            "reason": decision["reason"],
            "risk_score": decision.get("risk_score"),
        },
        "execution": {
            "status": status,
            "target": execution_target,
            "duration_ms": duration_ms,
            "result_hash": result_hash,
            "output": safe_tool_output,
            "error": str(redact_sensitive(execution_error)),
        },
        "receipt": receipt,
        "model_followup": {
            "provider": followup.get("provider"),
            "model": followup.get("model"),
            "mode": followup.get("mode"),
            "content": output_filter["filtered"],
            "finish_reason": followup.get("finish_reason", ""),
            "is_final": not bool(followup.get("requires_additional_tool_call")),
            "requires_additional_tool_call": bool(followup.get("requires_additional_tool_call")),
            "provider_failures": followup.get("provider_failures", []),
            "request_hash": followup.get("request_hash", ""),
            "provider_response_hash": followup.get("provider_response_hash", ""),
            "provider_response_id": followup.get("provider_response_id", ""),
            "provider_created": followup.get("provider_created"),
            "system_fingerprint": followup.get("system_fingerprint", ""),
            "tool_call_parse_issues": followup.get("tool_call_parse_issues", []),
            "content_hash": followup_content_hash,
            "reasoning_content_hash": followup_reasoning_hash,
            "response_hash": followup_response_hash,
            "output_filter": {
                "blocked": output_filter["blocked"],
                "findings": output_filter["findings"],
            },
        },
        "evidence_complete": protocol_evidence_complete,
        "real_model_evidence_valid": real_model_evidence_valid,
        "evidence_status": (
            "strict-real-api"
            if real_model_evidence_valid
            else "protocol-only"
            if protocol_evidence_complete
            else "incomplete"
        ),
        "evidence_gaps": evidence_gaps,
        "evidence_chain_hash": evidence_chain_hash,
    }
    root = Path(output_root) if output_root else REPORT_DIR
    root.mkdir(parents=True, exist_ok=True)
    json_path = root / "模型驱动Agent执行闭环证据.json"
    markdown_path = root / "模型驱动Agent执行闭环证据.md"
    json_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    markdown_path.write_text(_build_markdown(result), encoding="utf-8")
    return {**result, "json_path": str(json_path.resolve()), "markdown_path": str(markdown_path.resolve())}


def _result_hash(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _optional_hash(value: Any) -> str:
    text = str(value or "")
    return _result_hash(text) if text else ""


def _real_model_evidence_gaps(
    plan: dict[str, Any],
    followup: dict[str, Any],
    protocol_evidence_complete: bool,
) -> list[str]:
    gaps = []
    if not protocol_evidence_complete:
        gaps.append("审计、执行回执或最终回答闭环不完整")
    if plan.get("mode") != "real-api":
        gaps.append("工具调用规划不是 real-api 来源")
    if followup.get("mode") != "real-api":
        gaps.append("工具结果回灌后的回答不是 real-api 来源")
    if (plan.get("provider"), plan.get("model")) != (followup.get("provider"), followup.get("model")):
        gaps.append("规划与回灌回答不是同一模型来源")
    if plan.get("provider_failures"):
        gaps.append("工具调用规划存在供应商失败记录")
    if followup.get("provider_failures"):
        gaps.append("工具结果回灌存在供应商失败记录")
    if not plan.get("request_hash") or not plan.get("provider_response_hash"):
        gaps.append("工具调用规划缺少请求 Hash 或供应商原始响应 Hash")
    if not followup.get("request_hash") or not followup.get("provider_response_hash"):
        gaps.append("工具结果回灌缺少请求 Hash 或供应商原始响应 Hash")
    if plan.get("tool_call_parse_issues"):
        gaps.append("工具调用规划包含无法解析或未知的工具调用")
    if followup.get("tool_call_parse_issues"):
        gaps.append("工具结果回灌包含无法解析或未知的工具调用")
    if len(plan.get("tool_calls") or []) != 1:
        gaps.append("模型单轮返回多个工具调用，当前闭环只处理首个调用")
    return gaps


def _build_markdown(result: dict[str, Any]) -> str:
    plan = result["model_plan"]
    supervision = result["supervision"]
    execution = result["execution"]
    receipt = result["receipt"]
    followup = result["model_followup"]
    return "\n".join(
        [
            "# 模型驱动 Agent 执行闭环证据",
            "",
            f"- 生成时间：{result['generated_at']}",
            f"- 模型：{plan.get('provider')} / {plan.get('model')} / {plan.get('mode')}",
            f"- 模型工具调用：`{result['tool_call'].get('tool')}`（ID `{result['tool_call'].get('id')}`）",
            f"- 监督决策：{supervision.get('decision')} / `{supervision.get('policy_id')}`",
            f"- 实际处置：{execution.get('target')} / {execution.get('status')} / {execution.get('duration_ms')} ms",
            f"- 审计 Hash：`{supervision.get('audit_hash')}`",
            f"- 模型规划响应 Hash：`{plan.get('provider_response_hash') or '-'}`",
            f"- 模型回灌响应 Hash：`{followup.get('provider_response_hash') or '-'}`",
            f"- 结果 Hash：`{execution.get('result_hash') or '-'}`",
            f"- 回执 Hash：`{receipt.get('receipt_hash')}`",
            f"- 回执签名：`{receipt.get('receipt_signature') or '未配置 HMAC'}`",
            f"- 证据闭环：{'是' if result.get('evidence_complete') else '否'}",
            f"- 真实模型严格证据：{'有效' if result.get('real_model_evidence_valid') else '未通过'}",
            f"- 证据状态：`{result.get('evidence_status')}`",
            f"- 证据链 Hash：`{result.get('evidence_chain_hash')}`",
            f"- 证据缺口：{'；'.join(result.get('evidence_gaps', [])) or '无'}",
            f"- 模型回答完成：{'是' if followup.get('is_final') else '否（模型请求了额外工具，已在单步上限处暂停）'}",
            "",
            "## 模型最终回答",
            "",
            str(followup.get("content", "")),
        ]
    )
