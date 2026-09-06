from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from apps.api.agent_supervisor.domains.governance.anomaly import ANOMALY_REJECT_THRESHOLD, ANOMALY_REVIEW_THRESHOLD, detect_tool_anomaly
from apps.api.agent_supervisor.domains.governance.risk_score import calculate_risk_score
from apps.api.agent_supervisor.domains.governance.semantic_detector import (
    REJECT_THRESHOLD,
    REVIEW_THRESHOLD,
    SemanticResult,
    get_semantic_detector,
)
from apps.api.agent_supervisor.domains.governance.tool_contract import (
    ALLOWED_API_METHODS,
    SUPPORTED_TOOLS,
    canonical_text,
    canonical_text_variants,
    endpoint_allowlist_reason,
    endpoint_security_reason,
    get_agent_api_allowlist,
    get_agent_tool_allowlist,
    normalize_tool_call,
    path_is_absolute_or_traversal,
    path_is_sensitive,
    recipients_are_internal,
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


JAILBREAK_MARKERS = [
    # 保留明确的指令覆盖/越狱话术；普通技术名词放到下面的上下文规则，
    # 避免“目标路径”“系统配置”等合法业务词被单独拦截。
    "ignore previous",
    "do anything now",
    "不要解释安全规则",
    "无视规则",
    "没有安全限制",
]
JAILBREAK_EXPLICIT_PATTERNS = [
    re.compile(r"(?:忽略|无视|跳过)[^。\n]{0,24}(?:之前|以上|上文|前面|系统|安全|所有|原有)?[^。\n]{0,16}(?:指令|规则|提示词|约束|限制|审查|权限)"),
    re.compile(r"(?:绕过|规避|跳过)[^。\n]{0,20}(?:安全|审查|权限|验证|规则|防护|限制|系统检查|检查)"),
    re.compile(r"(?:ignore|disregard|forget|bypass)[^.!?\n]{0,60}(?:previous|prior|system|safety|security|instruction|rule|prompt|guard|policy)", re.IGNORECASE),
]
JAILBREAK_CONTEXT_PATTERNS = [
    # 指令覆盖：只有“优先级”与规则/权限改写动作同时出现才命中。
    re.compile(r"最高优先级[^。\n]{0,40}(?:规则|指令|权限|覆盖|执行)"),
    # 隐藏内容/触发器：技术讨论“隐藏字段”本身不构成攻击。
    re.compile(r"隐藏(?:指令|任务|记忆)[^。\n]{0,40}(?:执行|触发|放行|跳过|绕过|审查|外发)"),
    re.compile(r"(?:系统配置|系统提示词)[^。\n]{0,50}(?:完整|全部|隐藏|原始|原文|JSON|指令|提示|泄露|输出)"),
    re.compile(r"(?:上下文窗口|developer message|above this line)[^。\n]{0,60}(?:消息|指令|内容|原文|输出|显示|列出|verbatim)", re.IGNORECASE),
    re.compile(r"(?:工具|tool)[^。\n]{0,40}(?:完整定义|权限范围)[^。\n]{0,24}(?:隐藏|未展示|没展示)", re.IGNORECASE),
    # 任务拆解/密钥定位：要求同时出现敏感实体和“路径/自己猜”等外带意图。
    re.compile(r"(?:token|secret|密钥)[^。\n]{0,40}(?:路径|位置|存放|模式)[^。\n]{0,40}(?:自己猜|没有泄露|告诉我)", re.IGNORECASE),
    re.compile(r"(?:没有泄露任何)[^。\n]{0,30}(?:token|secret|密钥|机密)", re.IGNORECASE),
    # 权限伪造：管理员身份与敏感授权动作必须同时出现。
    re.compile(r"(?:超级管理员|管理员ID\s*[=:：]?\s*1|root)[^。\n]{0,60}(?:授权|读取|访问|永久|全部|机密|执行)", re.IGNORECASE),
    # 记忆投毒：置信度/二次验证在“记忆失效、永久放行”语境下才危险。
    re.compile(r"(?:记忆|规则)[^。\n]{0,40}(?:置信度)[^。\n]{0,24}(?:0|失效|不生效|禁用)", re.IGNORECASE),
    re.compile(r"(?:无需|不需要|跳过|豁免)[^。\n]{0,16}(?:二次验证|权限验证|审计)", re.IGNORECASE),
    # 工具劫持：目标路径结合改写、越界或敏感内容转写才命中。
    re.compile(r"目标路径[^。\n]{0,50}(?:改|调整|改为|\.\.|机密|摘要|file\.write)", re.IGNORECASE),
]
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
SENSITIVE_EGRESS_MARKERS = re.compile(
    r"(?i)(?<![a-z0-9])(?:api[_-]?key|access[_-]?token|token|secret|password|credential|private[_-]?key|flag|authorization|cookie|set-cookie|x-api-key|bearer|session)(?![a-z0-9])"
)


def inspect_prompt(prompt: str) -> GuardDecision | None:
    if not is_policy_enabled("jailbreak-filter"):
        return None

    lowered_variants = [variant.lower() for variant in canonical_text_variants(prompt)]
    explicit_marker_hit = any(
        marker.lower() in lowered
        for lowered in lowered_variants
        for marker in JAILBREAK_MARKERS
    )
    explicit_pattern_hit = any(
        pattern.search(lowered)
        for lowered in lowered_variants
        for pattern in JAILBREAK_EXPLICIT_PATTERNS
    )
    contextual_hit = any(
        pattern.search(lowered)
        for lowered in lowered_variants
        for pattern in JAILBREAK_CONTEXT_PATTERNS
    )
    if explicit_marker_hit or explicit_pattern_hit or contextual_hit:
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

    allowed_tools = get_agent_tool_allowlist(policy_settings, agent_id)
    # ``model.respond`` represents the Agent's primary model transaction, not
    # a tool capability exposed to the model. Its authority is governed by the
    # separate model allowlist at the API boundary; applying the tool allowlist
    # here would block every authenticated Agent before its first Provider call
    # unless operators redundantly registered ``model.respond`` as a tool.
    if tool != "model.respond" and agent_id and allowed_tools is not None:
        # Compare both the caller's framework-specific name and the resolved
        # canonical capability.  A registered alias such as ``file_read`` must
        # not be rejected merely because the policy is written in canonical
        # form as ``file.read``.
        normalized_allowed_tools = {canonical_text(item).lower() for item in allowed_tools if canonical_text(item)}
        if normalized_allowed_tools is not None and tool not in normalized_allowed_tools and original_tool not in normalized_allowed_tools:
            return scored(
                GuardDecision(
                    decision="拒绝",
                    risk_level="critical",
                    policy_id="tool-contract",
                    reason=f"Agent `{agent_id}` 没有调用工具 `{original_tool or tool}` 的能力授权。",
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
                    recommendation="仅允许写入已登记的公开目录，敏感目录写入必须走人工授权。",
                )
            )
        content = canonical_text(args.get("content"))
        persisted_prompt_decision = inspect_prompt(content)
        if persisted_prompt_decision:
            return scored(
                GuardDecision(
                    decision="隔离",
                    risk_level="high",
                    policy_id="jailbreak-filter",
                    reason="文件写入内容包含试图覆盖规则的指令，禁止把不可信指令持久化到 Agent 可读取的上下文。",
                    recommendation="将内容保留在隔离区，清除指令化文本后再写入共享工作区。",
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
        # Recipient classification alone is not an egress decision. An Agent
        # can place a credential-shaped value in an internal address and still
        # cause a real data disclosure. Treat destination and data class as
        # separate gates; the body remains redacted in audit output.
        if (
            is_policy_enabled("sensitive-egress")
            and recipients_are_internal(to, internal_email_domains)
            and _contains_sensitive_egress_value(
            {"subject": args.get("subject", ""), "body": body}
            )
        ):
            return scored(
                GuardDecision(
                    decision="询问",
                    risk_level="high",
                    policy_id="sensitive-egress",
                    reason="邮件正文或主题包含疑似凭据/敏感数据，必须在外发前完成人工复核。",
                    recommendation="确认数据分类、收件人范围、业务目的和审批记录；未经确认不得执行外发。",
                )
            )
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
        method = canonical_text(args.get("method") or "GET").upper()
        if method not in ALLOWED_API_METHODS:
            return scored(
                GuardDecision(
                    decision="拒绝",
                    risk_level="high",
                    policy_id="tool-contract",
                    reason=f"API endpoint 使用未注册的 HTTP 方法 `{method}`。",
                    recommendation="仅允许登记的 HTTP 方法，并为写操作配置独立权限和审计。",
                )
            )
        endpoint_boundary_reason = endpoint_security_reason(endpoint, sensitive_api_markers)
        if endpoint_boundary_reason:
            return scored(
                GuardDecision(
                    decision="拒绝",
                    risk_level="critical",
                    policy_id="sensitive-api",
                    reason=endpoint_boundary_reason,
                    recommendation="仅允许已登记的 HTTPS 公网目标或本地相对路由；拒绝回环、私网、链路本地、元数据和高敏路径。",
                )
            )
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
        # Public HTTP is a valid read-only integration, but a model-generated
        # write request carrying credentials or flags is an egress boundary.
        # The generic HTTP event contract cannot prove user intent, so pause it
        # for review instead of letting a caller-owned executor exfiltrate data.
        if (
            is_policy_enabled("bulk-action-review")
            and endpoint.startswith(("http://", "https://"))
            and method in {"POST", "PUT", "PATCH", "DELETE"}
            and _contains_sensitive_egress_value(args)
        ):
            return scored(
                GuardDecision(
                    decision="询问",
                    risk_level="high",
                    policy_id="bulk-action-review",
                    reason="外部 API 写请求携带疑似凭据或敏感数据，存在 Agent 数据外带风险。",
                    recommendation="人工确认目标主机、数据字段、授权范围和业务审批；未确认前不得执行。",
                )
            )
        if is_policy_enabled("external-api-allowlist") and endpoint.startswith(("http://", "https://")):
            allowlist_reason = endpoint_allowlist_reason(
                endpoint,
                get_agent_api_allowlist(policy_settings, agent_id),
            )
            if allowlist_reason:
                return scored(
                    GuardDecision(
                        decision="询问",
                        risk_level="high",
                        policy_id="external-api-allowlist",
                        reason=allowlist_reason,
                        recommendation="为当前 Agent 登记精确的 HTTPS API 主机（可含端口或单级子域通配符）；未登记目标不得自动外联。",
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
        if risk_hint == "resource_governance":
            return scored(
                GuardDecision(
                    decision="拒绝",
                    risk_level="high",
                    policy_id="resource-governance",
                    reason="Agent 请求超过并发、Token 或成本预算，Provider 尚未被调用。",
                    recommendation="降低单次生成上限、等待预算窗口刷新，或为该 Agent 配置明确的资源配额。",
                )
            )
        if risk_hint == "untrusted_tool_return" and is_policy_enabled("tool-return-trust"):
            return scored(
                GuardDecision(
                    decision="隔离",
                    risk_level="critical",
                    policy_id="tool-return-trust",
                    reason="工具返回内容包含指令化或敏感外传语义，不能作为可信模型上下文继续转发。",
                    recommendation="隔离原始工具结果，仅保留扫描信号和哈希；人工确认来源后再发布经过净化的内容。",
                )
            )
        training_risk = risk_hint == "training_data_extraction" or any(
            marker in model_text for marker in ["训练数据", "训练样例", "逐字复述", "training data", "memorized example"]
        )
        leak_risk = any(marker in model_text for marker in ["system prompt", "系统提示词", "developer message"])
        description_poison = risk_hint == "tool_description_poison"
        jailbreak_risk = risk_hint in {
            "jailbreak_output",
            "rewrite_evasion",
            "refusal_rewrite",
            "prompt_pollution",
            "tool_description_poison",
        } or any(marker in model_text for marker in ["jailbreak", "policy-evasion", "绕过", "无约束", "ignore previous"])
        output_policy_enabled = is_policy_enabled("tool-description-scan") if description_poison else is_policy_enabled("model-output-filter")
        if output_policy_enabled and (training_risk or jailbreak_risk or leak_risk):
            output_risk = risk_hint in {"jailbreak_output", "rewrite_evasion", "refusal_rewrite", "prompt_pollution"}
            return scored(
                GuardDecision(
                    decision="拒绝",
                    risk_level="high",
                    policy_id=(
                        "tool-description-scan"
                        if description_poison
                        else "model-output-filter"
                        if (training_risk or leak_risk or output_risk)
                        else "jailbreak-filter"
                    ),
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


def _contains_sensitive_egress_value(value: Any) -> bool:
    """Find credential-shaped values nested in an outbound API payload."""
    if isinstance(value, str):
        return any(SENSITIVE_EGRESS_MARKERS.search(variant) for variant in canonical_text_variants(value))
    if isinstance(value, dict):
        return any(_contains_sensitive_egress_value(key) or _contains_sensitive_egress_value(item) for key, item in value.items())
    if isinstance(value, (list, tuple, set)):
        return any(_contains_sensitive_egress_value(item) for item in value)
    return False
