from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from apps.api.agent_supervisor.domains.runtime.event_stream import publish_runtime_event
from apps.api.agent_supervisor.domains.runtime.tools import init_sandbox
from apps.api.agent_supervisor.paths import MEMORY_DIR
from apps.api.agent_supervisor.storage.database import append_runtime_event

MEMORY_FILE = MEMORY_DIR / "memory.json"
ACTIVE_STATUS = "active"
QUARANTINED_STATUS = "quarantined"
REMOVED_STATUS = "removed"


def memory_governance_snapshot(limit: int = 80) -> dict[str, Any]:
    items = _load_memory_items()
    safe_limit = max(1, min(limit, 500))
    status_counts: dict[str, int] = {}
    source_counts: dict[str, int] = {}
    for item in items:
        status = str(item.get("status", ACTIVE_STATUS))
        source = str(item.get("source", "unknown"))
        status_counts[status] = status_counts.get(status, 0) + 1
        source_counts[source] = source_counts.get(source, 0) + 1
    active = [item for item in items if item.get("status") == ACTIVE_STATUS]
    quarantined = [item for item in items if item.get("status") == QUARANTINED_STATUS]
    visible_items = _visible_memory_items(items, safe_limit)
    return {
        "generated_at": _now(),
        "summary": {
            "total": len(items),
            "active_count": len(active),
            "quarantined_count": len(quarantined),
            "removed_count": sum(1 for item in items if item.get("status") == REMOVED_STATUS),
            "avg_trust_score": round(sum(int(item.get("trust_score", 0)) for item in items) / len(items), 2)
            if items
            else 0,
        },
        "status_distribution": status_counts,
        "source_distribution": source_counts,
        "items_window": {
            "limit": safe_limit,
            "returned": len(visible_items),
            "total": len(items),
        },
        "items": visible_items,
    }


def update_memory_status(memory_id: str, status: str, operator: str = "security-analyst") -> dict[str, Any]:
    if status not in {ACTIVE_STATUS, QUARANTINED_STATUS, REMOVED_STATUS}:
        raise ValueError("status 必须是 active、quarantined 或 removed")
    items = _load_memory_items()
    for item in items:
        if item["id"] == memory_id:
            before = dict(item)
            item["status"] = status
            item["isolated"] = status == QUARANTINED_STATUS
            item["updated_at"] = _now()
            item["updated_by"] = operator or "security-analyst"
            item["trust_score"] = _trust_score(item)
            _save_memory_items(items)
            evidence = {
                "memory_id": memory_id,
                "operator": operator or "security-analyst",
                "before_status": str(before.get("status", "")),
                "after_status": status,
                "before_hash": _memory_hash(before),
                "after_hash": _memory_hash(item),
                "changed_at": str(item["updated_at"]),
            }
            journal_event = append_runtime_event("memory-governance-change", evidence, created_at=evidence["changed_at"])
            publish_runtime_event(
                "memory-governance-change",
                {**evidence, "event_id": journal_event["event_id"]},
            )
            return {
                "updated": True,
                "before": before,
                "after": item,
                "event_id": journal_event["event_id"],
                "evidence": evidence,
            }
    raise KeyError(memory_id)


def rollback_latest_memory(operator: str = "security-analyst") -> dict[str, Any]:
    items = _load_memory_items()
    candidates = [item for item in items if item.get("source") != "seed" and item.get("status") != REMOVED_STATUS]
    if not candidates:
        return {"updated": False, "reason": "没有可回滚的非种子记忆。"}
    target = sorted(candidates, key=lambda item: str(item.get("created_at", "")))[-1]
    return update_memory_status(str(target["id"]), REMOVED_STATUS, operator=operator)


def _load_memory_items() -> list[dict[str, Any]]:
    init_sandbox()
    try:
        raw = json.loads(MEMORY_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, FileNotFoundError):
        raw = []
    if not isinstance(raw, list):
        raw = []
    normalized: list[dict[str, Any]] = []
    changed = False
    for index, item in enumerate(raw, start=1):
        if not isinstance(item, dict):
            item = {"source": "legacy", "content": str(item)}
            changed = True
        normalized_item = _normalize_memory_item(item, index)
        if normalized_item != item:
            changed = True
        normalized.append(normalized_item)
    if changed:
        _save_memory_items(normalized)
    return normalized


def _normalize_memory_item(item: dict[str, Any], index: int) -> dict[str, Any]:
    status = str(item.get("status") or (QUARANTINED_STATUS if item.get("isolated") else ACTIVE_STATUS))
    if status not in {ACTIVE_STATUS, QUARANTINED_STATUS, REMOVED_STATUS}:
        status = ACTIVE_STATUS
    normalized = {
        **item,
        "id": str(item.get("id") or f"mem-{index}"),
        "source": str(item.get("source") or "legacy"),
        "content": str(item.get("content") or ""),
        "status": status,
        "isolated": status == QUARANTINED_STATUS,
        "created_at": str(item.get("created_at") or _now()),
    }
    normalized["trust_score"] = _trust_score(normalized)
    return normalized


def _visible_memory_items(items: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    return sorted(
        items,
        key=lambda item: (str(item.get("created_at", "")), str(item.get("id", ""))),
        reverse=True,
    )[:limit]


def _trust_score(item: dict[str, Any]) -> int:
    status = str(item.get("status", ACTIVE_STATUS))
    source = str(item.get("source", "unknown"))
    content = str(item.get("content", "")).lower()
    score = 85 if source == "seed" else 65
    if source in {"scenario", "external-agent", "legacy"}:
        score -= 10
    if any(token in content for token in ["忽略", "绕过", "secret", "token", "flag", "直接执行"]):
        score -= 35
    if status == QUARANTINED_STATUS:
        score = min(score, 30)
    if status == REMOVED_STATUS:
        score = 0
    return max(0, min(100, score))


def _save_memory_items(items: list[dict[str, Any]]) -> None:
    MEMORY_DIR.mkdir(parents=True, exist_ok=True)
    MEMORY_FILE.write_text(json.dumps(items, ensure_ascii=False, indent=2), encoding="utf-8")


def _memory_hash(item: dict[str, Any]) -> str:
    encoded = json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
