"""Bounded local tool adapters.

The runtime deliberately does not execute shell commands or arbitrary code.
External API/MCP side effects stay with the authenticated caller and must be
reported through the execution-receipt contract.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock
from typing import Any
from uuid import uuid4

from apps.api.agent_supervisor.domains.governance.tool_contract import (
    SUPPORTED_TOOLS,
    normalize_tool_call,
    resolve_public_endpoint,
)
from apps.api.agent_supervisor.paths import MEMORY_DIR, OUTBOX_DIR, RUNTIME_DIR, WORKSPACE_DIR

MAX_FILE_WRITE_CHARS = 20_000
MAX_FILE_READ_BYTES = 16 * 1024
MAX_MEMORY_FILE_BYTES = 2 * 1024 * 1024
MAX_MEMORY_ITEMS = 4_096
MAX_MEMORY_VISIBLE_ITEMS = 64
MAX_MEMORY_CONTENT_CHARS = 8_000
MAX_MEMORY_WRITE_CHARS = 8_000
MEMORY_LOCK = RLock()


@dataclass(frozen=True)
class RuntimePaths:
    workspace: Path
    outbox: Path
    memory: Path
    fixtures: Path | None = None
    seed_fixtures: bool = False


def _runtime_namespace(agent_id: str) -> str:
    normalized = str(agent_id or "").strip()
    return hashlib.sha256(normalized.encode("utf-8", errors="replace")).hexdigest()[:32] if normalized else "unbound"


def default_runtime_paths(agent_id: str | None = None) -> RuntimePaths:
    if agent_id:
        root = RUNTIME_DIR / "agents" / _runtime_namespace(agent_id)
        return RuntimePaths(root / "workspace", root / "outbox", root / "memory")
    return RuntimePaths(WORKSPACE_DIR, OUTBOX_DIR, MEMORY_DIR)


def init_runtime(paths: RuntimePaths | None = None) -> None:
    selected = paths or default_runtime_paths()
    selected.workspace.mkdir(parents=True, exist_ok=True)
    selected.outbox.mkdir(parents=True, exist_ok=True)
    selected.memory.mkdir(parents=True, exist_ok=True)
    memory_file = selected.memory / "memory.json"
    if not memory_file.exists():
        _atomic_write_json(memory_file, [])


def _safe_path(path: str, runtime: RuntimePaths | None = None) -> Path:
    selected = runtime or default_runtime_paths()
    root = selected.workspace.resolve()
    if not str(path).strip():
        raise ValueError("路径不能为空")
    target = (Path(path) if Path(path).is_absolute() else selected.workspace / path).resolve()
    try:
        target.relative_to(root)
    except ValueError as exc:
        raise ValueError("路径越出运行工作区") from exc
    return target


def execute_tool(
    tool_call: dict[str, Any],
    decision: str,
    runtime: RuntimePaths | None = None,
    network_addresses: list[str] | None = None,
    memory_namespace: str | None = None,
) -> dict[str, Any]:
    """Execute only bounded local operations; all network/code side effects stay external."""

    selected = runtime or default_runtime_paths(memory_namespace)
    init_runtime(selected)
    if decision in {"拒绝", "询问", "隔离"}:
        return _not_executed(f"工具调用未执行，监督决策为：{decision}")

    normalized = normalize_tool_call(tool_call)
    tool = normalized["tool"]
    args = normalized.get("arguments", {})
    if tool not in SUPPORTED_TOOLS:
        return _not_executed(f"未知工具已按默认拒绝处理：{tool or 'unknown'}")
    if tool == "api.call":
        endpoint = str(args.get("endpoint", ""))
        try:
            resolved = network_addresses or resolve_public_endpoint(endpoint) if endpoint.startswith(("http://", "https://")) else []
        except ValueError as exc:
            return _not_executed(f"外部 API 目标未通过固定出口校验：{exc}")
        return {
            "executed": False,
            "execution_target": "external",
            "executor": "caller",
            "network_addresses": list(resolved),
            "output": "外部 API 调用未在本地执行；请由已绑定出口的连接器执行并提交回执。",
        }
    if tool == "file.read":
        try:
            target = _safe_path(str(args.get("path", "")), selected)
        except ValueError as exc:
            return _not_executed(str(exc))
        if not target.exists():
            return {"executed": True, "execution_target": "local-runtime", "output": "运行工作区文件不存在。"}
        if not target.is_file():
            return _not_executed("运行工作区路径不是普通文件。")
        try:
            with target.open("rb") as handle:
                raw = handle.read(MAX_FILE_READ_BYTES + 1)
        except OSError as exc:
            return _not_executed(f"运行工作区文件读取失败：{exc}")
        return {
            "executed": True,
            "execution_target": "local-runtime",
            "resource_limited": len(raw) > MAX_FILE_READ_BYTES,
            "read_limit_bytes": MAX_FILE_READ_BYTES,
            "output": raw[:MAX_FILE_READ_BYTES].decode("utf-8", errors="replace")[:800],
        }
    if tool == "file.write":
        try:
            target = _safe_path(str(args.get("path", "")), selected)
        except ValueError as exc:
            return _not_executed(str(exc))
        content = str(args.get("content", ""))[:MAX_FILE_WRITE_CHARS]
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            target.write_text(content, encoding="utf-8")
        except OSError as exc:
            return _not_executed(f"运行工作区文件写入失败：{exc}")
        return {"executed": True, "execution_target": "local-runtime", "output": f"已写入运行工作区文件：{target.relative_to(selected.workspace)}"}
    if tool == "mail.send":
        outbox_entry = {
            "id": str(uuid4()),
            "to": str(args.get("to", "")),
            "subject": str(args.get("subject", ""))[:200],
            "body": str(args.get("body", ""))[:MAX_FILE_WRITE_CHARS],
            "created_at": _now(),
        }
        try:
            _append_jsonl(selected.outbox / "messages.jsonl", outbox_entry)
        except OSError as exc:
            return _not_executed(f"外发队列写入失败：{exc}")
        return {"executed": True, "execution_target": "local-runtime", "output": "邮件已写入本地外发队列，未直接发送。"}
    if tool == "memory.write":
        return _memory_write(selected, args, memory_namespace)
    if tool == "memory.read":
        return _memory_read(selected, args, memory_namespace)
    if tool == "env.read":
        key = str(args.get("key", "")).strip()
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,80}", key):
            return _not_executed("环境变量名格式无效。")
        if key.lower() in {"path", "home", "userprofile", "secret", "token", "api_key"} or any(
            marker in key.lower() for marker in ("secret", "token", "password", "credential", "key")
        ):
            return _not_executed("敏感环境变量禁止读取。")
        return {"executed": True, "execution_target": "local-runtime", "output": os.getenv(key, "")}
    if tool == "model.respond":
        return _not_executed("model.respond 由 Provider 网关处理，不在本地工具层执行。")
    return _not_executed(f"未知工具：{tool}")


def _memory_write(runtime: RuntimePaths, args: dict[str, Any], memory_namespace: str | None) -> dict[str, Any]:
    content = str(args.get("content", ""))
    if not content.strip():
        return _not_executed("记忆内容不能为空。")
    if len(content) > MAX_MEMORY_WRITE_CHARS:
        return _not_executed("记忆内容超过长度限制。")
    path = runtime.memory / "memory.json"
    with MEMORY_LOCK:
        items = _load_memory(path)
        items.append({"id": f"mem-{uuid4().hex[:12]}", "source": "agent", "scope": _memory_scope(memory_namespace), "content": content, "status": "active", "created_at": _now()})
        _atomic_write_json(path, items[-MAX_MEMORY_ITEMS:])
    return {"executed": True, "execution_target": "local-runtime", "output": "记忆已写入运行记忆库。"}


def _memory_read(runtime: RuntimePaths, args: dict[str, Any], memory_namespace: str | None) -> dict[str, Any]:
    query = str(args.get("query", "")).strip().lower()
    terms = [term for term in re.split(r"[\s,，、;；:：/]+", query) if term]
    with MEMORY_LOCK:
        items = _load_memory(runtime.memory / "memory.json")
    visible = []
    scope = _memory_scope(memory_namespace)
    for item in items:
        if item.get("status", "active") != "active" or item.get("scope", "global") not in {"global", scope}:
            continue
        content = str(item.get("content", ""))
        if terms and not any(term in content.lower() for term in terms):
            continue
        visible.append({"id": item.get("id", ""), "content": content[:MAX_MEMORY_CONTENT_CHARS], "source": item.get("source", "unknown"), "scope": item.get("scope", "global")})
    return {"executed": True, "execution_target": "local-runtime", "output": json.dumps(visible[:MAX_MEMORY_VISIBLE_ITEMS], ensure_ascii=False)}


def _load_memory(path: Path) -> list[dict[str, Any]]:
    try:
        if path.stat().st_size > MAX_MEMORY_FILE_BYTES:
            return []
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return []
    return [item for item in raw if isinstance(item, dict)] if isinstance(raw, list) else []


def _append_jsonl(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n")


def _atomic_write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    try:
        temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def _memory_scope(value: str | None) -> str:
    return str(value or "global").strip()[:160] or "global"


def _not_executed(reason: str) -> dict[str, Any]:
    return {"executed": False, "execution_target": "none", "executor": "unavailable", "output": reason}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
