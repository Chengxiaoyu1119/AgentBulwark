from __future__ import annotations

from dataclasses import dataclass
from math import log2
from typing import Any

from apps.api.agent_supervisor.domains.governance.tool_contract import (
    SUPPORTED_TOOLS,
    canonical_text,
    mail_recipient_addresses,
    normalize_tool_call,
    path_is_absolute_or_traversal,
    path_is_sensitive,
    recipients_are_internal,
)


@dataclass
class AnomalyResult:
    score: int
    signals: list[str]


ANOMALY_REVIEW_THRESHOLD = 55
ANOMALY_REJECT_THRESHOLD = 90
HIGH_IMPACT_TOOLS = {"code.run", "file.write", "mail.send", "api.call", "memory.write"}
KNOWN_TOOLS = SUPPORTED_TOOLS
UNTRUSTED_CONTEXT_MARKERS = ["网页", "公告", "工具返回", "外部", "摘要", "metadata", "retrieved", "browser", "赛题附件", "训练平台"]
SENSITIVE_MARKERS = [
    "secret",
    "token",
    "team",
    "flag",
    "scoreboard",
    "submission",
    "challenge",
    "judge",
    "portal",
    "campus",
    "队伍",
    "队员",
    "参赛",
    "赛题",
    "提交物",
    "成绩",
    "成绩榜",
    "受控实验环境",
    "密钥",
    "confidential",
]
OVERRIDE_MARKERS = ["忽略", "绕过", "不需要检查", "直接执行", "隐藏", "ignore previous", "do anything now"]
NETWORK_MARKERS = ["http://", "https://", "curl ", "wget ", "outside", "external"]


def detect_tool_anomaly(
    tool_call: dict[str, Any],
    *,
    prompt: str = "",
    context_sources: list[str] | None = None,
) -> AnomalyResult:
    tool_call = normalize_tool_call(tool_call)
    tool = str(tool_call.get("tool", ""))
    args = tool_call.get("arguments", {})
    if not isinstance(args, dict):
        args = {}

    signals: list[str] = []
    score = 0

    if tool not in KNOWN_TOOLS:
        score += 60
        signals.append("未知工具类型")

    if tool in HIGH_IMPACT_TOOLS:
        score += 16
        signals.append(f"高影响工具：{tool}")

    score += _prompt_score(prompt, signals)
    score += _argument_score(tool, args, signals)
    score += _context_score(context_sources or [], signals)

    return AnomalyResult(score=min(score, 100), signals=_dedupe(signals))


def _prompt_score(prompt: str, signals: list[str]) -> int:
    lowered = prompt.lower()
    score = 0
    if any(marker.lower() in lowered for marker in OVERRIDE_MARKERS):
        score += 25
        signals.append("输入包含覆盖规则或绕过语义")
    if any(marker.lower() in lowered for marker in SENSITIVE_MARKERS):
        score += 16
        signals.append("输入包含敏感资产语义")
    if any(marker.lower() in lowered for marker in UNTRUSTED_CONTEXT_MARKERS):
        score += 12
        signals.append("输入来源或内容疑似低信任上下文")
    if _entropy(prompt) >= 4.8 and len(prompt) >= 120:
        score += 10
        signals.append("输入文本复杂度较高，可能混入指令或编码片段")
    return score


def _argument_score(tool: str, args: dict[str, Any], signals: list[str]) -> int:
    serialized = " ".join(str(value) for value in args.values()).lower()
    score = 0
    if len(serialized) > 1500:
        score += 15
        signals.append("工具参数体积异常偏大")
    if any(marker in serialized for marker in SENSITIVE_MARKERS):
        score += 18
        signals.append("工具参数包含敏感资产标记")
    if any(marker in serialized for marker in NETWORK_MARKERS):
        score += 16
        signals.append("工具参数包含外部网络或外发目标")

    if tool in {"file.read", "file.write"}:
        path = str(args.get("path", ""))
        if path_is_absolute_or_traversal(path):
            score += 35
            signals.append("文件路径疑似越界")
        if path_is_sensitive(path):
            score += 28
            signals.append("文件路径指向敏感位置")

    if tool == "mail.send":
        to = str(args.get("to", "")).lower()
        if not mail_recipient_addresses(to) or not recipients_are_internal(to):
            score += 25
            signals.append("邮件收件人缺失、无效或包含外部地址")
        if len(str(args.get("body", ""))) > 1000:
            score += 12
            signals.append("邮件正文较长，需确认是否包含批量数据")

    if tool == "api.call":
        endpoint = canonical_text(args.get("endpoint")).lower()
        if any(marker in endpoint for marker in ["export", "all", "bulk"]):
            score += 24
            signals.append("API 调用疑似批量导出")
        if any(marker in endpoint for marker in ["admin", "scoreboard", "challenge", "seed", "judge", "session", "campus-net", "submissions/export", "teams/export"]):
            score += 30
            signals.append("API 调用指向高敏比赛或管理域")

    if tool == "code.run":
        command = canonical_text(args.get("command")).lower()
        if command and not command.startswith(("python --version", "python -v", "python scripts/")):
            score += 30
            signals.append("代码执行命令不在低风险白名单形态")
        if any(marker in command for marker in ["powershell", "cmd", "bash", "sh ", "rm ", "del ", "curl", "wget"]):
            score += 35
            signals.append("代码执行命令包含系统或网络动作")

    if tool == "memory.write":
        content = canonical_text(args.get("content")).lower()
        if any(
            marker in content
            for marker in [
                "以后",
                "隐藏",
                "直接执行",
                "不需要检查",
                "ignore authorization",
                "ignore permission",
                "bypass authorization",
                "always send",
            ]
        ):
            score += 30
            signals.append("长期记忆写入包含未来行为控制语义")

    return score


def _context_score(context_sources: list[str], signals: list[str]) -> int:
    if not context_sources:
        return 0
    lowered = {str(item).lower() for item in context_sources}
    score = 0
    if any(item in lowered for item in {"web", "browser", "tool", "retrieved", "external", "memory"}):
        score += 14
        signals.append("工具调用依赖低信任上下文来源")
    if len(lowered) >= 3:
        score += 8
        signals.append("上下文来源较多，存在污染传播风险")
    return score


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = {char: text.count(char) for char in set(text)}
    length = len(text)
    return -sum((count / length) * log2(count / length) for count in counts.values())

def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        result.append(item)
    return result
