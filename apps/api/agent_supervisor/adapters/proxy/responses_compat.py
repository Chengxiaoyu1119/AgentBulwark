"""Security-first translation for the OpenAI Responses API subset.

The runtime gateway's enforcement engine is built around the well-tested Chat
Completions contract.  Responses clients use a different envelope (`input`,
function-call items and `max_output_tokens`).  This module translates only the
small, typed subset that can be mapped without losing provenance.  Unknown
Response features are rejected at the boundary instead of silently being
discarded or forwarded to a Provider without the same checks.
"""

from __future__ import annotations

import json
import time
from typing import Any


class ResponsesCompatibilityError(ValueError):
    """A Responses request is outside the gateway's enforced compatibility subset."""


_ALLOWED_REQUEST_FIELDS = frozenset(
    {
        "model",
        "input",
        "instructions",
        "tools",
        "tool_choice",
        "max_output_tokens",
        "temperature",
        "top_p",
        "parallel_tool_calls",
        "metadata",
        "store",
        "agent_supervisor",
        "stream",
    }
)
_ALLOWED_ROLES = frozenset({"system", "developer", "user", "assistant"})
_TEXT_PART_TYPES = frozenset({"input_text", "output_text", "text"})
_MAX_INPUT_ITEMS = 64
_MAX_CONTENT_PARTS = 128
_MAX_TEXT_CHARS = 40_000
_MAX_TOOL_COUNT = 64


def responses_request_to_chat(payload: dict[str, Any]) -> dict[str, Any]:
    """Translate a bounded Responses request into the gateway's Chat contract.

    This is deliberately a fail-closed adapter.  It supports text messages,
    function tools and the function-call/function-call-output items needed for
    a receipt-bound follow-up.  Built-in tools, multimodal items, background
    jobs and ``previous_response_id`` require state or enforcement paths that
    are not represented by the Chat gateway and are rejected explicitly.
    """

    if not isinstance(payload, dict):
        raise ResponsesCompatibilityError("Responses 请求必须是 JSON 对象。")
    unknown = sorted(set(payload) - _ALLOWED_REQUEST_FIELDS)
    if unknown:
        raise ResponsesCompatibilityError(
            "Responses 兼容子集不支持字段：" + ", ".join(str(item)[:80] for item in unknown[:12])
        )
    if payload.get("stream") is True:
        raise ResponsesCompatibilityError("Responses 流式请求暂未纳入安全兼容子集，请使用非流式请求。")
    if "stream" in payload and payload.get("stream") is not False:
        raise ResponsesCompatibilityError("Responses.stream 必须是布尔值。")
    if not isinstance(payload.get("model"), str) or not payload["model"].strip():
        raise ResponsesCompatibilityError("Responses 请求必须包含非空 model。")
    if "input" not in payload:
        raise ResponsesCompatibilityError("Responses 请求必须包含 input。")

    messages: list[dict[str, Any]] = []
    instructions = payload.get("instructions")
    if instructions is not None:
        if not isinstance(instructions, str) or not instructions.strip():
            raise ResponsesCompatibilityError("Responses.instructions 只支持非空字符串。")
        messages.append({"role": "system", "content": instructions})
    messages.extend(_input_to_messages(payload["input"]))
    if not messages:
        raise ResponsesCompatibilityError("Responses input 未生成可检查的消息。")

    chat: dict[str, Any] = {
        "model": payload["model"].strip(),
        "messages": messages,
        "stream": False,
    }
    for field_name in ("temperature", "top_p", "parallel_tool_calls", "metadata", "store"):
        if field_name in payload:
            chat[field_name] = payload[field_name]
    if "agent_supervisor" in payload:
        chat["agent_supervisor"] = payload["agent_supervisor"]

    if "max_output_tokens" in payload:
        output_tokens = payload["max_output_tokens"]
        if isinstance(output_tokens, bool) or not isinstance(output_tokens, int) or output_tokens < 1:
            raise ResponsesCompatibilityError("Responses.max_output_tokens 必须是正整数。")
        chat["max_tokens"] = output_tokens

    if "tools" in payload:
        chat["tools"] = _responses_tools_to_chat(payload["tools"])
    if "tool_choice" in payload:
        chat["tool_choice"] = _responses_tool_choice_to_chat(payload["tool_choice"])
    return chat


def chat_response_to_responses(response: dict[str, Any], request: dict[str, Any]) -> dict[str, Any]:
    """Project a sanitized Chat response into a Responses-shaped envelope."""

    if not isinstance(response, dict):
        raise ResponsesCompatibilityError("Provider 响应不是 JSON 对象。")
    response_id = str(response.get("id") or f"resp-zhian-{int(time.time() * 1000)}")[:256]
    model = str(response.get("model") or request.get("model") or "")[:200]
    created = response.get("created")
    created_at = int(created) if isinstance(created, (int, float)) and not isinstance(created, bool) else int(time.time())
    output: list[dict[str, Any]] = []
    output_text_parts: list[str] = []
    choices = response.get("choices")
    if isinstance(choices, list):
        # The adapter rejects caller-side n; a Provider response with multiple
        # choices is still projected deterministically by keeping the first.
        choice = choices[0] if choices and isinstance(choices[0], dict) else {}
        message = choice.get("message") if isinstance(choice, dict) else {}
        message = message if isinstance(message, dict) else {}
        content = _content_to_text(message.get("content"))
        if content:
            output_text_parts.append(content)
            output.append(
                {
                    "id": f"{response_id}-message",
                    "type": "message",
                    "role": "assistant",
                    "status": "completed",
                    "content": [{"type": "output_text", "text": content, "annotations": []}],
                }
            )
        tool_calls = message.get("tool_calls")
        if isinstance(tool_calls, list):
            for index, raw_call in enumerate(tool_calls[:32]):
                if not isinstance(raw_call, dict) or not isinstance(raw_call.get("function"), dict):
                    continue
                function = raw_call["function"]
                call_id = str(raw_call.get("id") or f"{response_id}-call-{index}")[:256]
                output.append(
                    {
                        "id": call_id,
                        "type": "function_call",
                        "status": "completed",
                        "call_id": call_id,
                        "name": str(function.get("name") or "")[:160],
                        "arguments": str(function.get("arguments") or "")[:32_000],
                    }
                )

    usage = response.get("usage")
    response_usage: dict[str, int] = {}
    if isinstance(usage, dict):
        for source, target in (
            ("prompt_tokens", "input_tokens"),
            ("completion_tokens", "output_tokens"),
            ("total_tokens", "total_tokens"),
        ):
            value = usage.get(source)
            if isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0:
                response_usage[target] = int(value)

    result: dict[str, Any] = {
        "id": response_id,
        "object": "response",
        "created_at": created_at,
        "status": "completed",
        "model": model,
        "output": output,
        "output_text": "\n".join(output_text_parts),
        "parallel_tool_calls": bool(request.get("parallel_tool_calls", True)),
        "tool_choice": request.get("tool_choice", "auto"),
        "usage": response_usage,
    }
    metadata = response.get("agent_supervisor")
    if isinstance(metadata, dict):
        result["agent_supervisor"] = metadata
    return result


def _input_to_messages(raw_input: Any) -> list[dict[str, Any]]:
    if isinstance(raw_input, str):
        if not raw_input:
            return []
        return [{"role": "user", "content": raw_input}]
    if not isinstance(raw_input, list) or len(raw_input) > _MAX_INPUT_ITEMS:
        raise ResponsesCompatibilityError("Responses.input 必须是字符串或有限数组。")
    messages: list[dict[str, Any]] = []
    for index, item in enumerate(raw_input):
        path = f"input[{index}]"
        if isinstance(item, str):
            messages.append({"role": "user", "content": item})
            continue
        if not isinstance(item, dict):
            raise ResponsesCompatibilityError(f"{path} 必须是对象或字符串。")
        item_type = str(item.get("type") or "message").strip()
        if item_type == "function_call_output":
            call_id = _required_identifier(item.get("call_id") or item.get("id"), f"{path}.call_id")
            output = item.get("output")
            if output is None:
                raise ResponsesCompatibilityError(f"{path}.output 缺失。")
            messages.append({"role": "tool", "tool_call_id": call_id, "content": _stringify_output(output)})
            continue
        if item_type == "function_call":
            call_id = _required_identifier(item.get("call_id") or item.get("id"), f"{path}.call_id")
            name = _required_identifier(item.get("name"), f"{path}.name")
            arguments = item.get("arguments")
            if not isinstance(arguments, str):
                raise ResponsesCompatibilityError(f"{path}.arguments 必须是 JSON 字符串。")
            messages.append(
                {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": call_id,
                            "type": "function",
                            "function": {"name": name, "arguments": arguments},
                        }
                    ],
                }
            )
            continue
        if item_type != "message":
            raise ResponsesCompatibilityError(f"{path}.type `{item_type}` 未纳入安全兼容子集。")
        role = str(item.get("role") or "user").strip().lower()
        if role not in _ALLOWED_ROLES:
            raise ResponsesCompatibilityError(f"{path}.role `{role}` 不受支持。")
        messages.append({"role": role, "content": _content_to_chat(item.get("content"), path=f"{path}.content")})
    return messages


def _content_to_chat(value: Any, *, path: str) -> Any:
    if isinstance(value, str):
        return value
    if not isinstance(value, list) or len(value) > _MAX_CONTENT_PARTS:
        raise ResponsesCompatibilityError(f"{path} 只支持字符串或有限文本块数组。")
    parts: list[dict[str, str]] = []
    for index, part in enumerate(value):
        if isinstance(part, str):
            parts.append({"type": "text", "text": part})
            continue
        if not isinstance(part, dict) or str(part.get("type") or "") not in _TEXT_PART_TYPES:
            raise ResponsesCompatibilityError(f"{path}[{index}] 只支持 input_text/output_text 文本块。")
        text = part.get("text")
        if not isinstance(text, str):
            raise ResponsesCompatibilityError(f"{path}[{index}].text 必须是字符串。")
        parts.append({"type": "text", "text": text})
    return parts


def _responses_tools_to_chat(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > _MAX_TOOL_COUNT:
        raise ResponsesCompatibilityError("Responses.tools 必须是有限数组。")
    tools: list[dict[str, Any]] = []
    for index, raw_tool in enumerate(value):
        if not isinstance(raw_tool, dict) or raw_tool.get("type") != "function":
            raise ResponsesCompatibilityError(
                f"tools[{index}] 只支持 type=function；内置工具没有经过同一执行边界。"
            )
        name = _required_identifier(raw_tool.get("name"), f"tools[{index}].name")
        function: dict[str, Any] = {"name": name}
        for field_name in ("description", "parameters", "strict"):
            if field_name in raw_tool:
                function[field_name] = raw_tool[field_name]
        tools.append({"type": "function", "function": function})
    return tools


def _responses_tool_choice_to_chat(value: Any) -> Any:
    if isinstance(value, str):
        if value not in {"auto", "none", "required"}:
            raise ResponsesCompatibilityError("Responses.tool_choice 字符串值不受支持。")
        return value
    if not isinstance(value, dict) or value.get("type") != "function":
        raise ResponsesCompatibilityError("Responses.tool_choice 只支持 function 选择器。")
    name = value.get("name")
    if name is None and isinstance(value.get("function"), dict):
        name = value["function"].get("name")
    return {"type": "function", "function": {"name": _required_identifier(name, "tool_choice.name")}}


def _required_identifier(value: Any, path: str) -> str:
    text = str(value or "").strip()
    if not text or len(text) > 256 or any(ord(char) < 0x20 for char in text):
        raise ResponsesCompatibilityError(f"{path} 必须是有限的协议标识符。")
    return text


def _stringify_output(value: Any) -> str:
    if isinstance(value, str):
        return value[:_MAX_TEXT_CHARS]
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))[:_MAX_TEXT_CHARS]
    except (TypeError, ValueError, RecursionError) as exc:
        raise ResponsesCompatibilityError("function_call_output 无法安全序列化。") from exc


def _content_to_text(value: Any) -> str:
    if isinstance(value, str):
        return value[:_MAX_TEXT_CHARS]
    if isinstance(value, list):
        chunks: list[str] = []
        for item in value:
            if isinstance(item, str):
                chunks.append(item)
            elif isinstance(item, dict) and isinstance(item.get("text"), str):
                chunks.append(item["text"])
        return "".join(chunks)[:_MAX_TEXT_CHARS]
    return ""
