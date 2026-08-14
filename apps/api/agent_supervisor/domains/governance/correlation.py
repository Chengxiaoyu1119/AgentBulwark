from __future__ import annotations

import json
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from threading import Lock
from typing import Any

from apps.api.agent_supervisor.domains.governance.tool_contract import normalize_tool_call, recipients_are_internal
from apps.api.agent_supervisor.storage.data import get_policy_settings

MAX_CHAIN_EVENTS = 20
CHAIN_WINDOW = timedelta(minutes=10)

SENSITIVE_MARKERS = (
    "confidential",
    "secret",
    "token",
    "flag",
    "scoreboard",
    "submission",
    "challenge",
    "seed",
    "session",
    "campus-net",
    "队伍",
    "提交物",
    "成绩",
    "赛题",
)

_LOCK = Lock()
_CHAINS: dict[str, deque[dict[str, Any]]] = defaultdict(lambda: deque(maxlen=MAX_CHAIN_EVENTS))


def assess_cross_agent_chain(event: dict[str, Any], tool_call: dict[str, Any]) -> dict[str, Any]:
    """Track recent conversation-level tool calls and detect multi-step exfiltration chains."""
    tool_call = normalize_tool_call(tool_call)
    conversation_id = str(event.get("conversation_id") or "external-conversation")
    agent_id = str(event.get("agent_id") or "external-agent")
    now = datetime.now(timezone.utc)
    profile = _profile_tool_call(tool_call, event)

    with _LOCK:
        history = _CHAINS[conversation_id]
        while history and now - history[0]["created_at"] > CHAIN_WINDOW:
            history.popleft()
        previous = list(history)
        history.append(
            {
                "created_at": now,
                "agent_id": agent_id,
                "tool": profile["tool"],
                "sensitive_access": profile["sensitive_access"],
                "bulk_export": profile["bulk_export"],
                "external_transfer": profile["external_transfer"],
                "memory_sensitive": profile["memory_sensitive"],
                "untrusted_context": profile["untrusted_context"],
            }
        )

    signals: list[str] = []
    if profile["external_transfer"] or profile["tool"] == "mail.send":
        sensitive_previous = [
            item
            for item in previous
            if item["sensitive_access"] or item["bulk_export"] or item["memory_sensitive"]
        ]
        if sensitive_previous:
            signals.append(
                "同一会话前序步骤出现敏感读取、批量导出或敏感记忆访问，当前步骤尝试发送或转移结果。"
            )
        if any(item["agent_id"] != agent_id for item in sensitive_previous):
            signals.append("敏感数据获取与发送动作由不同 Agent 完成，存在跨 Agent 拆分规避风险。")

    if profile["bulk_export"] and any(item["untrusted_context"] for item in previous):
        signals.append("不可信上下文后触发批量导出，疑似工具调用劫持链。")

    return {
        "conversation_id": conversation_id,
        "agent_id": agent_id,
        "escalated": bool(signals),
        "signals": signals,
        "history_event_count": len(previous),
        "previous_tools": [item["tool"] for item in previous[-5:]],
        "window_seconds": int(CHAIN_WINDOW.total_seconds()),
    }


def reset_correlation_state() -> None:
    with _LOCK:
        _CHAINS.clear()


def _profile_tool_call(tool_call: dict[str, Any], event: dict[str, Any]) -> dict[str, Any]:
    tool = str(tool_call.get("tool", ""))
    raw_args = tool_call.get("arguments")
    args: dict[str, Any] = raw_args if isinstance(raw_args, dict) else {}
    prompt = str(event.get("model_input", ""))
    sources = " ".join(str(item) for item in event.get("context_sources") or [])
    argument_text = json.dumps(args, ensure_ascii=False).lower()
    prompt_text = prompt.lower()
    combined = f"{argument_text} {prompt_text}"

    endpoint = str(args.get("endpoint", "")).lower()
    path = str(args.get("path", "")).lower()
    query = str(args.get("query", "")).lower()
    recipient = str(args.get("to", "")).lower()

    sensitive_access = (
        (tool == "file.read" and _contains_sensitive(path))
        or (tool == "api.call" and _contains_sensitive(endpoint))
        or (tool == "memory.read" and _contains_sensitive(query))
    )
    bulk_export = tool == "api.call" and any(marker in endpoint for marker in ("export", "dump", "all", "batch"))
    memory_sensitive = tool == "memory.read" and _contains_sensitive(query)
    internal_domains = {str(item).lower() for item in get_policy_settings().get("internal_email_domains", [])}
    external_transfer = tool == "mail.send" and not recipients_are_internal(recipient, internal_domains)
    untrusted_context = any(marker in prompt_text for marker in ("忽略", "绕过", "ignore previous", "trusted notice")) or any(
        marker in sources.lower() for marker in ("web", "browser", "retrieved", "tool")
    )

    return {
        "tool": tool,
        "sensitive_access": sensitive_access or _contains_sensitive(combined),
        "bulk_export": bulk_export,
        "memory_sensitive": memory_sensitive,
        "external_transfer": external_transfer,
        "untrusted_context": untrusted_context,
    }


def _contains_sensitive(text: str) -> bool:
    lowered = text.lower()
    return any(marker in lowered for marker in (*SENSITIVE_MARKERS, "all", "everything", "全部", "所有", "*"))
