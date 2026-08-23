from __future__ import annotations

import json
import queue
import threading
from datetime import datetime, timezone
from typing import Any, Generator
from uuid import uuid4

SUBSCRIBERS: set[queue.Queue[dict[str, Any]]] = set()
SUBSCRIBERS_LOCK = threading.Lock()


_OBSERVER_EVENT_FIELDS = frozenset(
    {
        "run_id",
        "audit_id",
        "decision",
        "risk_level",
        "risk_score",
        "anomaly_score",
        "policy_id",
        "tool",
        "standard_capability",
        "status",
        "final_decision",
        "succeeded",
        "execution_outcome",
        "forwarded",
        "upstream_route",
        "event_id",
        "alert_count",
        "provider_called",
    }
)


def _event_for_role(event: dict[str, Any], role: str) -> dict[str, Any]:
    """Project live events before they cross the console role boundary.

    The event bus is process-wide and deliberately does not keep a separate
    queue for every Agent.  That is useful for low-latency operator updates, but
    it also means the projection must be performed before an observer receives
    an event.  Approval reviews and supervisor payloads can contain tool
    arguments, model excerpts, or other Agent context; those nested objects are
    never part of the observer contract.
    """

    if role in {"analyst", "admin"}:
        return event
    payload = event.get("payload")
    if not isinstance(payload, dict):
        return {key: event.get(key) for key in ("id", "type", "created_at")}
    safe_payload = {
        key: payload[key]
        for key in _OBSERVER_EVENT_FIELDS
        if key in payload and isinstance(payload[key], (str, int, float, bool))
    }
    safe_payload["access_scope"] = "summary-redacted"
    if "approval_review" in payload:
        safe_payload["approval_present"] = payload.get("approval_review") is not None
    return {
        "id": event.get("id", ""),
        "type": event.get("type", ""),
        "created_at": event.get("created_at", ""),
        "payload": safe_payload,
    }


def publish_runtime_event(event_type: str, payload: dict[str, Any]) -> None:
    event = {
        "id": str(uuid4()),
        "type": event_type,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "payload": payload,
    }
    with SUBSCRIBERS_LOCK:
        subscribers = list(SUBSCRIBERS)
    for subscriber in subscribers:
        try:
            subscriber.put_nowait(event)
        except queue.Full:
            continue


def stream_runtime_events(*, role: str = "observer") -> Generator[str, None, None]:
    """Stream role-projected events to the authenticated console caller."""

    subscriber: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=200)
    with SUBSCRIBERS_LOCK:
        SUBSCRIBERS.add(subscriber)
    try:
        yield "retry: 1500\n\n"
        while True:
            try:
                event = subscriber.get(timeout=15)
                payload = json.dumps(_event_for_role(event, role), ensure_ascii=False)
                yield f"id: {event['id']}\nevent: {event['type']}\ndata: {payload}\n\n"
            except queue.Empty:
                yield ": keepalive\n\n"
    finally:
        with SUBSCRIBERS_LOCK:
            SUBSCRIBERS.discard(subscriber)
