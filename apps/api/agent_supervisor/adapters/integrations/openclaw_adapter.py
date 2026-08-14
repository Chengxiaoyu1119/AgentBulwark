from __future__ import annotations

import hashlib
import json
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from time import perf_counter
from typing import Any
from uuid import uuid4

from apps.api.agent_supervisor.adapters.integrations.openclaw_plugin_package import (
    build_openclaw_plugin_package_summary,
)
from apps.api.agent_supervisor.paths import SANDBOX_EXAMPLES_DIR


@dataclass
class GuardedToolResult:
    decision: str
    policy_id: str
    reason: str
    executed: bool
    execution_target: str = "none"
    execution_status: str = "not_executed"
    receipt_confirmed: bool = False
    receipt_error: str = ""
    tool_result: Any = None
    supervisor_result: dict[str, Any] | None = None


class AgentToolGuard:
    """Dependency-free guard that can be placed before any Agent tool executor.

    Any agent framework can call ``guarded_execute`` inside its tool-dispatch
    hook before running the real business tool. The OpenClaw-specific name is
    retained below as a compatibility alias.
    """

    def __init__(
        self,
        supervisor_url: str = "http://127.0.0.1:8012/api/runtime/evaluate",
        *,
        timeout: float = 5.0,
        default_on_error: str = "询问",
        api_token: str = "",
    ) -> None:
        if default_on_error not in {"询问", "拒绝", "隔离"}:
            raise ValueError("default_on_error 必须是询问、拒绝或隔离")
        self.supervisor_url = supervisor_url
        self.timeout = timeout
        self.default_on_error = default_on_error
        self.api_token = api_token

    def evaluate(
        self,
        *,
        conversation_id: str,
        agent_id: str,
        agent_role: str,
        source_app: str,
        model_input: str,
        model_output: str,
        tool_call: dict[str, Any],
        context_sources: list[str] | None = None,
        execute_in_sandbox: bool = False,
    ) -> dict[str, Any]:
        event = {
            "conversation_id": conversation_id,
            "agent_id": agent_id,
            "agent_role": agent_role,
            "source_app": source_app,
            "model_input": model_input,
            "model_output": model_output,
            "tool_call": tool_call,
            "context_sources": context_sources or [],
            "guard_enabled": True,
            "execute_in_sandbox": execute_in_sandbox,
        }
        body = json.dumps(event, ensure_ascii=False).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.api_token:
            headers["Authorization"] = f"Bearer {self.api_token}"
        request = urllib.request.Request(
            self.supervisor_url,
            data=body,
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            result = json.loads(response.read().decode("utf-8"))
        if not isinstance(result, dict):
            raise ValueError("监督器响应必须是 JSON 对象")
        decision = result.get("decision")
        if decision not in {"允许", "拒绝", "询问", "隔离"}:
            raise ValueError("监督器响应包含未知决策，已暂停工具执行")
        if not str(result.get("run_id", "")) or not str(result.get("audit_id", "")):
            raise ValueError("监督器响应缺少 run_id 或 audit_id，已暂停工具执行")
        # Internal marker distinguishes a real, schema-checked HTTP response
        # from a lightweight unit-test stub returned by a patched evaluate().
        result["_protocol_validated"] = True
        return result

    def resume_approved(
        self,
        *,
        review_id: str,
        agent_id: str,
        tool_call: dict[str, Any],
        executor: Callable[[dict[str, Any]], Any],
    ) -> GuardedToolResult:
        """Claim an approved call exactly once, execute it, and send the completion receipt."""
        claim = self._post_approval(review_id, "claim", {"agent_id": agent_id, "tool_call": tool_call})
        if not claim.get("granted"):
            review = claim.get("review") or {}
            return GuardedToolResult(
                decision=str(review.get("final_decision", "询问")),
                policy_id=str(review.get("policy_id", "approval-review")),
                reason=str(claim.get("reason", "审批调用尚未进入可恢复状态。")),
                executed=False,
                execution_target="none",
                execution_status="not_executed",
                supervisor_result={"approval_review": review},
            )

        claim_id = str(claim["claim_id"])
        review = claim.get("review") or {}
        try:
            tool_result = executor(tool_call)
        except Exception as exc:  # noqa: BLE001 - completion receipt must be persisted
            self._post_approval(
                review_id,
                "complete",
                {
                    "agent_id": agent_id,
                    "claim_id": claim_id,
                    "succeeded": False,
                    "result_hash": _result_hash({"error": str(exc)}),
                },
            )
            return GuardedToolResult(
                decision="允许",
                policy_id=str(review.get("policy_id", "approval-review")),
                reason=f"审批已通过，但恢复执行失败：{exc}",
                executed=False,
                execution_target="real",
                execution_status="failed",
                receipt_confirmed=True,
                supervisor_result={"approval_review": review, "claim_id": claim_id},
            )

        result_hash = _result_hash(tool_result)
        completion = self._post_approval(
            review_id,
            "complete",
            {"agent_id": agent_id, "claim_id": claim_id, "succeeded": True, "result_hash": result_hash},
        )
        return GuardedToolResult(
            decision="允许",
            policy_id=str(review.get("policy_id", "approval-review")),
            reason="人工审批通过，原始工具调用已恢复并完成，执行回执已写入审计链。",
            executed=True,
            execution_target="real",
            execution_status="completed",
            receipt_confirmed=True,
            tool_result=tool_result,
            supervisor_result={
                "approval_review": completion.get("review", review),
                "claim_id": claim_id,
                "result_hash": result_hash,
            },
        )

    def _post_approval(self, review_id: str, action: str, payload: dict[str, Any]) -> dict[str, Any]:
        parsed = urllib.parse.urlsplit(self.supervisor_url)
        path = f"/api/approvals/{urllib.parse.quote(review_id, safe='')}/{action}"
        url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.api_token:
            headers["Authorization"] = f"Bearer {self.api_token}"
        request = urllib.request.Request(url, data=body, headers=headers, method="POST")
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            return json.loads(response.read().decode("utf-8"))

    def _post_execution_receipt(
        self,
        *,
        supervisor_result: dict[str, Any],
        agent_id: str,
        tool_call: dict[str, Any],
        status: str,
        execution_target: str,
        result_hash: str = "",
        duration_ms: float = 0,
        error: str = "",
    ) -> dict[str, Any] | None:
        """Send a receipt for a schema-validated remote decision.

        A patched/local unit stub has no audit id and deliberately skips the
        network call; production responses always carry both ids.
        """
        if not supervisor_result.get("_protocol_validated"):
            return None
        audit_id = str(supervisor_result.get("audit_id", ""))
        if not audit_id:
            return None
        parsed = urllib.parse.urlsplit(self.supervisor_url)
        path = f"/api/runtime/executions/{urllib.parse.quote(audit_id, safe='')}/complete"
        url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))
        payload = {
            "receipt_id": str(uuid4()),
            "agent_id": agent_id,
            "tool_call": tool_call,
            "status": status,
            "execution_target": execution_target,
            "result_hash": result_hash,
            "duration_ms": round(max(0.0, duration_ms), 3),
            "error": error,
        }
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.api_token:
            headers["Authorization"] = f"Bearer {self.api_token}"
        request = urllib.request.Request(url, data=body, headers=headers, method="POST")
        last_error: Exception | None = None
        for _ in range(2):
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    receipt_response = json.loads(response.read().decode("utf-8"))
                if not isinstance(receipt_response, dict):
                    raise ValueError("执行回执接口响应必须是 JSON 对象")
                return receipt_response
            except urllib.error.HTTPError:
                raise
            except (OSError, TimeoutError, ValueError, json.JSONDecodeError) as exc:
                last_error = exc
        if last_error:
            raise last_error
        return None

    def guarded_execute(
        self,
        *,
        conversation_id: str,
        agent_id: str,
        agent_role: str,
        source_app: str,
        model_input: str,
        model_output: str,
        tool_call: dict[str, Any],
        executor: Callable[[dict[str, Any]], Any],
        sandbox_executor: Callable[[dict[str, Any]], Any] | None = None,
        context_sources: list[str] | None = None,
    ) -> GuardedToolResult:
        try:
            supervisor_result = self.evaluate(
                conversation_id=conversation_id,
                agent_id=agent_id,
                agent_role=agent_role,
                source_app=source_app,
                model_input=model_input,
                model_output=model_output,
                tool_call=tool_call,
                context_sources=context_sources,
            )
        except Exception as exc:  # noqa: BLE001 - fail closed to manual review
            return GuardedToolResult(
                decision=self.default_on_error,
                policy_id="supervisor-unavailable",
                reason=f"监督器不可用，按默认策略进入人工确认：{exc}",
                executed=False,
                execution_target="none",
            )

        decision = str(supervisor_result.get("decision", "询问"))
        if decision not in {"允许", "拒绝", "询问", "隔离"}:
            return GuardedToolResult(
                decision="询问",
                policy_id="invalid-supervisor-response",
                reason="监督器返回未知决策，已暂停工具执行。",
                executed=False,
                execution_target="none",
                supervisor_result=supervisor_result,
            )

        def receipt_for(
            status: str,
            target: str,
            *,
            result: Any = None,
            duration_ms: float = 0,
            error: str = "",
        ) -> tuple[bool, str]:
            try:
                receipt_response = self._post_execution_receipt(
                    supervisor_result=supervisor_result,
                    agent_id=agent_id,
                    tool_call=tool_call,
                    status=status,
                    execution_target=target,
                    result_hash=_result_hash(result) if status in {"completed", "failed"} else "",
                    duration_ms=duration_ms,
                    error=error,
                )
                if receipt_response is not None:
                    supervisor_result["execution_receipt"] = receipt_response.get("receipt")
                    return True, ""
                return False, ""
            except Exception as exc:  # noqa: BLE001 - execution already happened or was intentionally skipped
                return False, str(exc)

        if decision in {"拒绝", "询问"}:
            receipt_confirmed, receipt_error = receipt_for("not_executed", "none")
            return GuardedToolResult(
                decision=decision,
                policy_id=str(supervisor_result.get("policy_id", "unknown")),
                reason=str(supervisor_result.get("reason", "")),
                executed=False,
                execution_target="none",
                execution_status="not_executed",
                receipt_confirmed=receipt_confirmed,
                receipt_error=receipt_error,
                supervisor_result=supervisor_result,
            )

        if decision == "隔离":
            if sandbox_executor is None:
                receipt_confirmed, receipt_error = receipt_for("not_executed", "none")
                return GuardedToolResult(
                    decision=decision,
                    policy_id=str(supervisor_result.get("policy_id", "unknown")),
                    reason="监督器要求隔离执行，但调用方没有配置沙箱执行器，工具保持未执行。",
                    executed=False,
                    execution_target="none",
                    execution_status="not_executed",
                    receipt_confirmed=receipt_confirmed,
                    receipt_error=receipt_error,
                    supervisor_result=supervisor_result,
                )
            started = perf_counter()
            try:
                tool_result = sandbox_executor(tool_call)
            except Exception as exc:  # noqa: BLE001 - report the real executor outcome
                receipt_confirmed, receipt_error = receipt_for(
                    "failed", "sandbox", result={"error": str(exc)}, duration_ms=(perf_counter() - started) * 1000, error=str(exc)
                )
                return GuardedToolResult(
                    decision=decision,
                    policy_id=str(supervisor_result.get("policy_id", "unknown")),
                    reason=f"隔离执行失败：{exc}",
                    executed=False,
                    execution_target="sandbox",
                    execution_status="failed",
                    receipt_confirmed=receipt_confirmed,
                    receipt_error=receipt_error,
                    supervisor_result=supervisor_result,
                )
            execution_target = "sandbox"
        else:
            started = perf_counter()
            try:
                tool_result = executor(tool_call)
            except Exception as exc:  # noqa: BLE001 - report the real executor outcome
                receipt_confirmed, receipt_error = receipt_for(
                    "failed", "real", result={"error": str(exc)}, duration_ms=(perf_counter() - started) * 1000, error=str(exc)
                )
                return GuardedToolResult(
                    decision=decision,
                    policy_id=str(supervisor_result.get("policy_id", "unknown")),
                    reason=f"允许决策已下发，但真实工具执行失败：{exc}",
                    executed=False,
                    execution_target="real",
                    execution_status="failed",
                    receipt_confirmed=receipt_confirmed,
                    receipt_error=receipt_error,
                    supervisor_result=supervisor_result,
                )
            execution_target = "real"
        receipt_confirmed, receipt_error = receipt_for(
            "completed", execution_target, result=tool_result, duration_ms=(perf_counter() - started) * 1000
        )
        return GuardedToolResult(
            decision=decision,
            policy_id=str(supervisor_result.get("policy_id", "unknown")),
            reason=str(supervisor_result.get("reason", "")),
            executed=True,
            execution_target=execution_target,
            execution_status="completed",
            receipt_confirmed=receipt_confirmed,
            receipt_error=receipt_error,
            tool_result=tool_result,
            supervisor_result=supervisor_result,
        )


class OpenClawToolGuard(AgentToolGuard):
    """Backward-compatible OpenClaw adapter name."""


def _result_hash(value: Any) -> str:
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def build_openclaw_hook_example() -> str:
    return """
import os

from apps.api.agent_supervisor.adapters.integrations.openclaw_adapter import OpenClawToolGuard

guard = OpenClawToolGuard(
    "http://127.0.0.1:8012/api/integrations/openclaw/events",
    api_token=os.getenv("AGENT_SUPERVISOR_AGENT_TOKEN", ""),
)

def tool_dispatch_hook(tool_call, real_executor, model_input, model_output, conversation_id):
    result = guard.guarded_execute(
        conversation_id=conversation_id,
        agent_id="openclaw-agent-01",
        agent_role="executor",
        source_app="OpenClaw",
        model_input=model_input,
        model_output=model_output,
        tool_call=tool_call,
        context_sources=["user", "agent-plan"],
        executor=real_executor,
    )
    if not result.executed:
        return {"blocked": True, "decision": result.decision, "reason": result.reason}
    return result.tool_result
""".strip()

def build_openclaw_integration_bundle() -> dict[str, Any]:
    sample_events = _load_sample_events()
    plugin_summary = build_openclaw_plugin_package_summary()
    return {
        "name": "OpenClaw-compatible tool-call guard bundle",
        "version": "2026.06.08",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "purpose": "把外部智能体的工具调用前置到智安哨监督器，获得允许、拒绝、询问、隔离决策，并写入审计证据。",
        "endpoints": [
            {
                "name": "通用监督接口",
                "method": "POST",
                "path": "/api/runtime/evaluate",
                "description": "适合 LangChain、AutoGen、自研 Agent 等任意框架；服务端强制开启防护。",
            },
            {
                "name": "OpenClaw 兼容入口",
                "method": "POST",
                "path": "/api/integrations/openclaw/events",
                "description": "适合按 OpenClaw 风格工具调度钩子接入。",
            },
            {
                "name": "适配器代码",
                "method": "GET",
                "path": "/api/integrations/openclaw/adapter.py",
                "description": "可复制到外部智能体项目中的最小工具调用守卫。",
            },
            {
                "name": "外部执行回执",
                "method": "POST",
                "path": "/api/runtime/executions/{audit_id}/complete",
                "description": "原始 Agent 执行或阻断后回传实际目标、状态、耗时和结果 Hash，形成闭环证据。",
            },
            {
                "name": "最小真实接入演示",
                "method": "POST",
                "path": "/api/integrations/openclaw/minimal_agent_demo",
                "description": "从页面或接口运行最小外部 Agent 真实工具调度 demo，并生成审计证据文件。",
            },
            {
                "name": "OpenClaw 源码级插件包",
                "method": "POST",
                "path": "/api/integrations/openclaw/plugin_package/write",
                "description": "生成可安装到 OpenClaw 的 native plugin 包，使用 before_tool_call 作为工具调用前置闸门。",
            },
        ],
        "event_contract": {
            "required_fields": ["conversation_id", "agent_id", "source_app", "model_input", "model_output", "tool_call"],
            "tool_call": {
                "tool": "file.read | file.write | mail.send | api.call | code.run | memory.write | env.read | model.respond",
                "arguments": "工具参数对象",
                "risk_hint": "可选风险提示，例如 sensitive_file、external_mail、bulk_export",
            },
            "optional_fields": ["agent_role", "context_sources", "execute_in_sandbox"],
            "safe_default": "生产接口始终开启防护；execute_in_sandbox 默认为 false，只做判定和审计，不替代真实外部系统执行工具。",
            "execution_receipt": {
                "path": "/api/runtime/executions/{audit_id}/complete",
                "status": "completed | failed | not_executed",
                "execution_target": "real | sandbox | none",
                "required_hashes": ["tool_call_hash (由原始审计绑定)", "result_hash (执行时)", "receipt_hash"],
            },
            "identity_binding": "生产 Agent 使用独立 Bearer Token，服务端校验其绑定 agent_id。",
        },
        "adapter_code": build_openclaw_hook_example(),
        "openclaw_plugin_package": plugin_summary,
        "sample_events": sample_events,
        "validation": {
            "cli": "node scripts/agent-supervisor-cli.mjs demo-external",
            "real_agent_cli": "node scripts/agent-supervisor-cli.mjs external-agent-demo",
            "plugin_cli": "node scripts/agent-supervisor-cli.mjs openclaw-plugin --output apps/api/sandbox/reports",
            "plugin_validation_cli": "node scripts/agent-supervisor-cli.mjs openclaw-plugin-validate --output apps/api/sandbox/reports",
            "powershell": "Invoke-RestMethod -Method Post http://127.0.0.1:8012/api/runtime/batch_evaluate -Body (Get-Content apps/api/sandbox/examples/openclaw-like-events.json -Raw) -ContentType 'application/json'",
            "expected": {
                "event_count": len(sample_events),
                "controlled_min": 3,
                "allowed_normal_read": True,
                "execution_receipt_required": True,
            },
        },
        "acceptance_steps": [
            "在外部智能体项目的工具执行入口前调用 OpenClawToolGuard.guarded_execute。",
            "把模型输入、模型输出、工具名、工具参数和上下文来源封装成事件。",
            "先发送到 /api/integrations/openclaw/events。",
            "根据返回 decision 执行：允许继续、拒绝阻断、询问暂停、隔离到沙箱。",
            "执行器完成、失败或决定不执行后，向 /api/runtime/executions/{audit_id}/complete 回传一次性执行回执。",
            "在智安哨审计页和告警页查看 run_id、audit_id、policy_id、risk_score、audit_hash，以及实际执行目标、状态、结果 Hash 和回执签名。",
            "如使用 OpenClaw 原生接入，运行 `node scripts/agent-supervisor-cli.mjs openclaw-plugin --output apps/api/sandbox/reports` 生成插件包，再用 `openclaw plugins install -l apps/api/sandbox/reports/agent-supervisor-openclaw-guard` 安装。",
            "运行 `node scripts/agent-supervisor-cli.mjs openclaw-plugin-validate --output apps/api/sandbox/reports` 生成插件包验收报告；安装 OpenClaw 后可追加 `--inspect-runtime` 获取真实 runtime inspect 结果。",
        ],
        "safety_boundary": [
            "默认不发送真实邮件。",
            "默认不读取真实用户文件。",
            "默认不替代真实外部系统执行工具。",
            "如需执行，只允许在本项目沙箱和模拟业务工具中验证。",
        ],
    }


def build_openclaw_integration_markdown() -> str:
    bundle = build_openclaw_integration_bundle()
    lines = [
        "# OpenClaw 兼容接入包",
        "",
        f"生成时间：{bundle['generated_at']}",
        "",
        "## 接入目标",
        "",
        bundle["purpose"],
        "",
        "## 接口清单",
        "",
        "| 接口 | 方法 | 说明 |",
        "|---|---|---|",
    ]
    for endpoint in bundle["endpoints"]:
        lines.append(f"| `{endpoint['path']}` | {endpoint['method']} | {endpoint['description']} |")
    lines.extend(
        [
            "",
            "## 事件结构",
            "",
            f"- 必填字段：{', '.join(bundle['event_contract']['required_fields'])}",
            f"- 可选字段：{', '.join(bundle['event_contract']['optional_fields'])}",
            f"- 安全默认值：{bundle['event_contract']['safe_default']}",
            "",
            "## 验证命令",
            "",
            "```powershell",
            bundle["validation"]["cli"],
            "```",
            "",
            "运行最小外部 Agent 真实工具调度接入演示：",
            "",
            "```powershell",
            bundle["validation"]["real_agent_cli"],
            "```",
            "",
            "生成 OpenClaw native plugin 并做静态验收：",
            "",
            "```powershell",
            bundle["validation"]["plugin_validation_cli"],
            "```",
            "",
            "## 适配器代码",
            "",
            "```python",
            bundle["adapter_code"],
            "```",
            "",
            "## 验收步骤",
            "",
        ]
    )
    for index, step in enumerate(bundle["acceptance_steps"], start=1):
        lines.append(f"{index}. {step}")
    lines.extend(["", "## 安全边界", ""])
    for item in bundle["safety_boundary"]:
        lines.append(f"- {item}")
    return "\n".join(lines)

def _load_sample_events() -> list[dict[str, Any]]:
    sample_path = SANDBOX_EXAMPLES_DIR / "openclaw-like-events.json"
    try:
        data = json.loads(sample_path.read_text(encoding="utf-8"))
    except OSError:
        return []
    return data if isinstance(data, list) else []
