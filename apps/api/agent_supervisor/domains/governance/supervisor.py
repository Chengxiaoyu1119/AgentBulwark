from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from apps.api.agent_supervisor.domains.governance.anomaly import ANOMALY_REJECT_THRESHOLD, ANOMALY_REVIEW_THRESHOLD, detect_tool_anomaly
from apps.api.agent_supervisor.domains.governance.risk_score import calculate_risk_score
from apps.api.agent_supervisor.domains.governance.tool_contract import (
    SUPPORTED_TOOLS,
    canonical_text,
    normalize_tool_call,
    path_is_absolute_or_traversal,
    path_is_sensitive,
    recipients_are_internal,
)
from apps.api.agent_supervisor.domains.governance.semantic_detector import (
    REJECT_THRESHOLD,
    REVIEW_THRESHOLD,
    SemanticResult,
    get_semantic_detector,
)
from apps.api.agent_supervisor.domains.governance.tool_registry import resolve_tool_call
from apps.api.agent_supervisor.storage.data import get_policy_settings, is_policy_enabled


@dataclass
class GuardDecision:
    decision: str
    risk_level: str
    policy_id: str
    reason: str
    recommendation: str
    risk_score: int = 0
    risk_factors: list[str] = field(default_factory=list)
    anomaly_score: int = 0
    anomaly_signals: list[str] = field(default_factory=list)
    model_confidence: float | None = None
    model_latency_ms: float | None = None
    model_version: str = ""


DANGEROUS_COMMANDS = [
    "rm ",
    "del ",
    "format",
    "curl ",
    "wget ",
    "powershell -enc",
    "chmod 777",
    # The probe is intentionally executable only inside the fixture, but its
    # purpose is to model a hijacked command and must still hit the guard.
    "scripts/tool_hijack_probe.py",
]
JAILBREAK_MARKERS = ["忽略", "无约束", "绕过", "ignore previous", "do anything now", "不要解释安全规则"]
MEMORY_POISON_MARKERS = [
    "不需要检查权限",
    "忽略权限",
    "直接执行",
    "隐藏",
    "ignore authorization",
    "ignore permission",
    "bypass authorization",
    "without checking permission",
    "always send",
]


def inspect_prompt(prompt: str) -> GuardDecision | None:
    if not is_policy_enabled("jailbreak-filter"):
        return None

    lowered = prompt.lower()
    if any(marker.lower() in lowered for marker in JAILBREAK_MARKERS):
        return GuardDecision(
            decision="拒绝",
            risk_level="high",
            policy_id="jailbreak-filter",
            reason="输入包含越狱或覆盖系统规则的意图。",
            recommendation="保持系统指令优先级，并将用户输入隔离为不可信内容。",
        )
    return None


def _semantic_channel(prompt: str) -> SemanticResult | None:
    """语义检测通道：策略关闭或输入为空时直接跳过，模型不可用时自动降级。"""
    if not is_policy_enabled("jailbreak-semantic"):
        return None
    if not prompt or not prompt.strip():
        return None
    return get_semantic_detector().detect(prompt)


def decide(
    tool_call: dict[str, Any],
    guard_enabled: bool,
    prompt: str = "",
    context_sources: list[str] | None = None,
    agent_id: str = "",
) -> GuardDecision:
    resolution = resolve_tool_call(tool_call, agent_id=agent_id)
    original_tool = resolution.original_tool
    tool_call = normalize_tool_call(resolution.effective_tool_call)
    anomaly = detect_tool_anomaly(tool_call, prompt=prompt, context_sources=context_sources or [])
    policy_settings = get_policy_settings()
    internal_email_domains = {str(item).lower() for item in policy_settings.get("internal_email_domains", [])}
    sensitive_path_markers = {str(item).lower() for item in policy_settings.get("sensitive_path_markers", [])}
    sensitive_api_markers = {str(item).lower() for item in policy_settings.get("sensitive_api_markers", [])}
    anomaly_review_threshold = int(policy_settings.get("anomaly_review_threshold", ANOMALY_REVIEW_THRESHOLD))
    anomaly_reject_threshold = int(policy_settings.get("anomaly_reject_threshold", ANOMALY_REJECT_THRESHOLD))

    def scored(decision: GuardDecision) -> GuardDecision:
        risk = calculate_risk_score(
            tool_call,
            prompt=prompt,
            decision=decision.decision,
            policy_id=decision.policy_id,
        )
        decision.anomaly_score = anomaly.score
        decision.anomaly_signals = anomaly.signals
        decision.risk_score = min(100, risk.score + (anomaly.score // 4))
        decision.risk_factors = risk.factors + [f"异常检测：{item}" for item in anomaly.signals]
        return decision

    if not guard_enabled:
        return scored(
            GuardDecision(
                decision="允许",
                risk_level="low",
                policy_id="guard-disabled",
                reason="监督器处于记录模式，本次调用被允许以复现攻击风险。",
                recommendation="开启监督器后重新运行同一攻击，比较阻断效果。",
            )
        )

    prompt_decision = inspect_prompt(prompt)
    tool = tool_call["tool"]
    args = tool_call.get("arguments", {})
    risk_hint = tool_call.get("risk_hint", "")

    if tool not in SUPPORTED_TOOLS:
        return scored(
            GuardDecision(
                decision="拒绝",
                risk_level="critical",
                policy_id="tool-contract",
                reason=f"工具 `{original_tool or tool or 'unknown'}` 未注册标准能力映射。",
                recommendation="先注册工具 schema、参数约束和执行边界，再允许外部智能体调用。",
            )
        )

    agent_tool_allowlists = policy_settings.get("agent_tool_allowlists", {})
    if isinstance(agent_tool_allowlists, dict) and agent_id:
        allowed_tools = agent_tool_allowlists.get(agent_id, agent_tool_allowlists.get("*"))
        if isinstance(allowed_tools, list) and original_tool not in allowed_tools:
            return scored(
                GuardDecision(
                    decision="拒绝",
                    risk_level="critical",
                    policy_id="tool-contract",
                    reason=f"Agent `{agent_id}` 没有调用工具 `{original_tool}` 的能力授权。",
                    recommendation="为该 Agent 配置最小工具能力集合，或改由具备相应权限的 Agent 执行。",
                )
            )

    if tool == "file.read":
        path = str(args.get("path", ""))
        if is_policy_enabled("path-boundary") and (
            path_is_absolute_or_traversal(path)
            or path_is_sensitive(path, sensitive_path_markers)
            or risk_hint == "sensitive_file"
        ):
            return scored(
                GuardDecision(
                    decision="拒绝",
                    risk_level="critical",
                    policy_id="path-boundary",
                    reason=f"文件读取目标 `{path}` 命中敏感路径或越界访问策略。",
                    recommendation="仅允许读取任务白名单目录，并要求敏感文件访问走人工授权。",
                )
            )

    if tool == "file.write":
        path = str(args.get("path", ""))
        if is_policy_enabled("path-boundary") and (
            path_is_absolute_or_traversal(path)
            or path_is_sensitive(path, sensitive_path_markers)
            or risk_hint in {"sensitive_file", "sensitive_write"}
        ):
            return scored(
                GuardDecision(
                    decision="拒绝",
                    risk_level="critical",
                    policy_id="path-boundary",
                    reason=f"文件写入目标 `{path}` 命中敏感路径或越界写入策略。",
                    recommendation="仅允许写入沙箱公开报告目录，敏感目录写入必须走人工授权。",
                )
            )
        if len(str(args.get("content", ""))) > 5000:
            return scored(
                GuardDecision(
                    decision="询问",
                    risk_level="medium",
                    policy_id="bulk-action-review",
                    reason="文件写入内容较长，可能包含批量导出或敏感摘要。",
                    recommendation="人工确认写入内容和业务目的，必要时拆分或脱敏。",
                )
            )

    if tool == "mail.send":
        to = str(args.get("to", ""))
        body = str(args.get("body", ""))
        if is_policy_enabled("bulk-action-review") and risk_hint in {"bulk_mail", "indirect_prompt_injection"}:
            policy_id = "bulk-action-review"
            if risk_hint == "indirect_prompt_injection" and is_policy_enabled("external-mail"):
                policy_id = "external-mail"
            return scored(
                GuardDecision(
                    decision="询问",
                    risk_level="high",
                    policy_id=policy_id,
                    reason="邮件动作来自批量任务或不可信上下文，存在外发滥用和提示注入风险。",
                    recommendation="人工确认上下文来源、收件人、正文和业务审批记录。",
                )
            )
        if is_policy_enabled("external-mail") and not recipients_are_internal(to, internal_email_domains):
            return scored(
                GuardDecision(
                    decision="询问",
                    risk_level="high",
                    policy_id="external-mail",
                    reason=f"邮件收件人 `{to}` 属于外部地址，且正文可能包含 `{body[:20]}` 等敏感内容。",
                    recommendation="人工确认收件人、正文和业务目的；第一版只写入假 outbox。",
                )
            )

    if tool == "api.call":
        endpoint = canonical_text(args.get("endpoint")).lower()
        if is_policy_enabled("tool-return-trust") and (
            risk_hint == "untrusted_tool_return"
            or endpoint in {"/tool/metadata/untrusted", "/competition/challenges/attachment/readme"}
        ):
            return scored(
                GuardDecision(
                    decision="隔离",
                    risk_level="medium",
                    policy_id="tool-return-trust",
                    reason=f"API `{endpoint}` 的返回内容可能包含伪造授权或指令化文本。",
                    recommendation="将工具返回作为低信任数据隔离，禁止其覆盖安全策略或授权判断。",
                )
            )
        if is_policy_enabled("bulk-action-review") and (
            risk_hint == "bulk_export" or "export-all" in endpoint or endpoint.endswith("/export") or "/export/" in endpoint
        ):
            return scored(
                GuardDecision(
                    decision="询问",
                    risk_level="medium",
                    policy_id="bulk-action-review",
                    reason=f"API `{endpoint}` 涉及批量导出或未登记外部用途。",
                    recommendation="要求说明用途、审批人和数据范围，必要时改用脱敏聚合接口。",
                )
            )
        if is_policy_enabled("sensitive-api") and (
            any(marker in endpoint for marker in sensitive_api_markers)
            or risk_hint == "sensitive_api"
        ):
            return scored(
                GuardDecision(
                    decision="拒绝",
                    risk_level="critical",
                    policy_id="sensitive-api",
                    reason=f"API `{endpoint}` 属于高敏接口，当前任务缺少授权证明。",
                    recommendation="要求最小权限令牌，并记录调用理由、赛事角色和审批人。",
                )
            )

    if tool == "code.run":
        command = canonical_text(args.get("command")).lower()
        if is_policy_enabled("dangerous-command") and any(marker in command for marker in DANGEROUS_COMMANDS):
            return scored(
                GuardDecision(
                    decision="拒绝",
                    risk_level="critical",
                    policy_id="dangerous-command",
                    reason=f"代码执行命令 `{command}` 命中危险命令策略。",
                    recommendation="只允许运行预定义脚本，并禁用网络和破坏性系统命令。",
                )
            )
        if is_policy_enabled("code-sandbox"):
            return scored(
                GuardDecision(
                    decision="隔离",
                    risk_level="medium",
                    policy_id="code-sandbox",
                    reason="代码执行工具默认进入沙箱隔离运行。",
                    recommendation="限制执行目录、超时时间、环境变量和输出长度。",
                )
            )

    if tool == "memory.write":
        content = canonical_text(args.get("content")).lower()
        if is_policy_enabled("memory-write") and any(marker in content for marker in MEMORY_POISON_MARKERS):
            return scored(
                GuardDecision(
                    decision="隔离",
                    risk_level="high",
                    policy_id="memory-write",
                    reason="记忆写入内容试图改变未来权限检查或隐藏高风险动作。",
                    recommendation="将该记忆写入隔离区，等待人工复核后再合并。",
                )
            )

    if tool == "memory.read":
        query = canonical_text(args.get("query")).lower()
        if is_policy_enabled("memory-read-sensitive") and any(
            marker in query
            for marker in [
                "secret",
                "token",
                "team",
                "flag",
                "judge",
                "session",
                "scoreboard",
                "submission",
                "队伍",
                "赛题",
                "提交物",
                "成绩",
                "all",
                "everything",
                "全部",
                "所有",
                "全部记忆",
                "*",
            ]
        ):
            return scored(
                GuardDecision(
                    decision="拒绝",
                    risk_level="critical",
                    policy_id="memory-read-sensitive",
                    reason="记忆读取请求包含敏感字段或全量检索语义。",
                    recommendation="对记忆访问做字段级脱敏，并要求说明赛事角色、读取目的和授权范围。",
                )
            )

    if tool == "model.respond":
        topic = canonical_text(args.get("topic"))
        model_text = canonical_text(f"{prompt} {topic} {args.get('prompt', '')}").lower()
        training_risk = risk_hint == "training_data_extraction" or any(
            marker in model_text for marker in ["训练数据", "训练样例", "逐字复述", "training data", "memorized example"]
        )
        jailbreak_risk = risk_hint in {
            "jailbreak_output",
            "rewrite_evasion",
            "refusal_rewrite",
            "prompt_pollution",
        } or any(marker in model_text for marker in ["jailbreak", "policy-evasion", "绕过", "无约束", "ignore previous"])
        if is_policy_enabled("model-output-filter") and (training_risk or jailbreak_risk):
            return scored(
                GuardDecision(
                    decision="拒绝",
                    risk_level="high",
                    policy_id="model-output-filter" if training_risk else "jailbreak-filter",
                    reason=f"模型输出请求 `{topic}` 命中训练数据抽取、拒答改写绕过或高风险绕过输出策略。",
                    recommendation="拒绝逐字复述训练样例、拒答规避和绕过指导，仅允许输出安全解释、脱敏摘要或防护建议。",
                )
            )

    if tool == "env.read":
        key = canonical_text(args.get("key"))
        if is_policy_enabled("environment-trust") and ("ALLOW_UNSAFE" in key.upper() or risk_hint == "environment_pollution"):
            return scored(
                GuardDecision(
                    decision="隔离",
                    risk_level="medium",
                    policy_id="environment-trust",
                    reason=f"环境变量 `{key}` 可能被伪造为权限依据。",
                    recommendation="环境信息只能作为低信任上下文，不能覆盖安全策略。",
                )
            )

    if prompt_decision:
        return scored(prompt_decision)

    semantic = _semantic_channel(prompt)
    if semantic is not None and semantic.available:
        if semantic.probability >= REJECT_THRESHOLD:
            return scored(
                GuardDecision(
                    decision="拒绝",
                    risk_level="high",
                    policy_id="jailbreak-semantic",
                    reason=f"语义模型判定输入存在越狱意图（置信度 {semantic.probability:.2f}）。",
                    recommendation="保持系统指令优先级，将用户输入隔离为不可信内容并留存证据。",
                    model_confidence=semantic.probability,
                    model_latency_ms=semantic.latency_ms,
                    model_version=semantic.model_version,
                )
            )
        if semantic.probability >= REVIEW_THRESHOLD:
            return scored(
                GuardDecision(
                    decision="询问",
                    risk_level="medium",
                    policy_id="jailbreak-semantic",
                    reason=f"语义模型提示可疑越狱意图（置信度 {semantic.probability:.2f}），需人工确认。",
                    recommendation="人工复核输入意图后再决定是否放行。",
                    model_confidence=semantic.probability,
                    model_latency_ms=semantic.latency_ms,
                    model_version=semantic.model_version,
                )
            )

    if is_policy_enabled("anomaly-detection") and anomaly.score >= anomaly_review_threshold:
        return scored(
            GuardDecision(
                decision="询问" if anomaly.score < anomaly_reject_threshold else "拒绝",
                risk_level="high" if anomaly.score >= anomaly_reject_threshold else "medium",
                policy_id="anomaly-detection",
                reason=f"工具调用组合异常，异常分 {anomaly.score}，信号：{'；'.join(anomaly.signals[:4])}。",
                recommendation="暂停自动执行，要求人工核验上下文来源、参数来源和业务目的。",
            )
        )

    baseline_risk = calculate_risk_score(tool_call, prompt=prompt)
    if policy_settings.get("high_risk_auto_escalation", True) and baseline_risk.score >= 60:
        return scored(
            GuardDecision(
                decision="拒绝" if baseline_risk.score >= 85 else "询问",
                risk_level="critical" if baseline_risk.score >= 85 else "high",
                policy_id="anomaly-detection",
                reason=f"工具调用未命中单项规则，但综合风险分达到 {baseline_risk.score}。",
                recommendation="暂停执行并核验规范化参数、数据范围、调用目的和最小权限。",
            )
        )

    return scored(
        GuardDecision(
            decision="允许",
            risk_level="low",
            policy_id="default-allow",
            reason="未命中高风险策略，允许执行并记录审计。",
            recommendation="持续记录调用链，保留后续复盘证据。",
        )
    )
