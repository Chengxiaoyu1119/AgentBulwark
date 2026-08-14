from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from apps.api.agent_supervisor.domains.governance.tool_contract import (
    canonical_text,
    mail_recipient_addresses,
    normalize_tool_call,
    path_is_absolute_or_traversal,
    path_is_sensitive,
    recipients_are_internal,
)


@dataclass
class RiskScore:
    score: int
    factors: list[str]


TOOL_BASE_SCORES = {
    "file.read": 18,
    "file.write": 24,
    "mail.send": 20,
    "api.call": 20,
    "code.run": 45,
    "memory.write": 28,
    "memory.read": 24,
    "env.read": 18,
    "model.respond": 18,
}

RISK_HINT_SCORES = {
    "sensitive_file": (42, "风险提示标记敏感文件访问"),
    "sensitive_api": (42, "风险提示标记高敏 API"),
    "dangerous_command": (45, "风险提示标记危险代码执行"),
    "bulk_export": (28, "风险提示标记批量导出"),
    "bulk_mail": (28, "风险提示标记批量外发"),
    "external_mail": (24, "风险提示标记外部邮件"),
    "indirect_prompt_injection": (35, "风险提示标记间接提示注入"),
    "poison_memory": (34, "风险提示标记记忆污染"),
    "sensitive_memory": (40, "风险提示标记敏感记忆读取"),
    "training_data_extraction": (36, "风险提示标记训练数据抽取"),
    "jailbreak_output": (36, "风险提示标记越狱输出"),
    "rewrite_evasion": (38, "风险提示标记拒答改写绕过"),
    "refusal_rewrite": (34, "风险提示标记拒答后改写"),
    "prompt_pollution": (32, "风险提示标记提示污染"),
    "environment_pollution": (30, "风险提示标记环境感知污染"),
    "untrusted_tool_return": (26, "风险提示标记低信任工具返回"),
}

PROMPT_MARKERS = ["忽略", "无约束", "绕过", "ignore previous", "do anything now", "不要解释安全规则"]
DANGEROUS_COMMAND_MARKERS = ["rm ", "del ", "format", "curl ", "wget ", "powershell -enc", "chmod 777"]
SENSITIVE_WORDS = ["secret", "token", "team", "flag", "submission", "judge", "session", "队伍", "赛题", "提交物", "密钥", "confidential"]


def calculate_risk_score(
    tool_call: dict[str, Any],
    *,
    prompt: str = "",
    decision: str = "允许",
    policy_id: str = "default-allow",
) -> RiskScore:
    tool_call = normalize_tool_call(tool_call)
    tool = str(tool_call.get("tool", ""))
    args = tool_call.get("arguments", {})
    risk_hint = str(tool_call.get("risk_hint", ""))

    score = TOOL_BASE_SCORES.get(tool, 16)
    factors = [f"工具基础风险：{tool or 'unknown'}"]

    hint_score = RISK_HINT_SCORES.get(risk_hint)
    if hint_score:
        points, factor = hint_score
        score += points
        factors.append(factor)

    score += _argument_score(tool, args, factors)

    lowered_prompt = prompt.lower()
    if any(marker.lower() in lowered_prompt for marker in PROMPT_MARKERS):
        score += 22
        factors.append("输入包含越狱或覆盖规则语义")
    if any(word in lowered_prompt for word in SENSITIVE_WORDS):
        score += 12
        factors.append("输入包含敏感数据访问语义")

    return RiskScore(score=min(score, 100), factors=_dedupe(factors))


def _argument_score(tool: str, args: dict[str, Any], factors: list[str]) -> int:
    score = 0
    if tool in {"file.read", "file.write"}:
        path = str(args.get("path", ""))
        if path_is_absolute_or_traversal(path):
            score += 45
            factors.append("文件路径疑似越界")
        if path_is_sensitive(path):
            score += 34
            factors.append("文件路径指向敏感目录")
        if tool == "file.write" and len(str(args.get("content", ""))) > 5000:
            score += 28
            factors.append("文件写入内容体积较大")

    if tool == "mail.send":
        to = str(args.get("to", ""))
        body = str(args.get("body", ""))
        recipients = mail_recipient_addresses(to)
        if not recipients or not recipients_are_internal(to):
            score += 28
            factors.append("邮件收件人缺失、无效或包含外部地址")
        if any(word in body.lower() for word in SENSITIVE_WORDS):
            score += 18
            factors.append("邮件正文包含敏感词")

    if tool == "api.call":
        endpoint = canonical_text(args.get("endpoint")).lower()
        if any(marker in endpoint for marker in ["admin", "scoreboard", "challenge", "seed", "judge", "session", "campus-net", "submissions/export", "teams/export"]):
            score += 38
            factors.append("API endpoint 属于高敏接口")
        if any(marker in endpoint for marker in ["export", "all", "bulk"]):
            score += 24
            factors.append("API endpoint 涉及批量导出")

    if tool == "code.run":
        command = canonical_text(args.get("command")).lower()
        if any(marker in command for marker in DANGEROUS_COMMAND_MARKERS):
            score += 48
            factors.append("命令包含危险片段")
        if command and not command.startswith(("python --version", "python -v", "python scripts/")):
            score += 18
            factors.append("命令不在推荐白名单形态")

    if tool == "memory.write":
        content = canonical_text(args.get("content")).lower()
        if any(
            marker in content
            for marker in [
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
        ):
            score += 34
            factors.append("记忆内容试图改变未来权限检查")

    if tool == "memory.read":
        query = canonical_text(args.get("query")).lower()
        if any(
            marker in query
            for marker in [
                "secret",
                "token",
                "team",
                "flag",
                "submission",
                "队伍",
                "赛题",
                "提交物",
                "all",
                "everything",
                "全部",
                "所有",
                "*",
            ]
        ):
            score += 38
            factors.append("记忆检索包含敏感或全量关键词")

    if tool == "env.read":
        key = canonical_text(args.get("key"))
        if "ALLOW_UNSAFE" in key.upper():
            score += 30
            factors.append("环境变量可能伪造授权依据")

    return score

def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        result.append(item)
    return result
