"""Operator-facing traces for the LLM API gateway.

The gateway response already carries a compact ``agent_supervisor`` envelope,
but a production operator also needs to find a request after the client has
closed its connection.  This module turns redacted audit rows into a bounded,
model/provider-neutral trace view.  It deliberately never returns messages,
tool arguments, provider error bodies or tool results.
"""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Iterable

CONTROLLED_DECISIONS = {"拒绝", "询问", "隔离"}
DECISION_PRIORITY = {"允许": 0, "询问": 1, "隔离": 2, "拒绝": 3}
SAFE_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$")


def build_gateway_trace_index(
    audit_rows: Iterable[dict[str, Any]],
    *,
    limit: int = 50,
) -> dict[str, Any]:
    """Build a bounded trace list from gateway audit records."""

    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in audit_rows:
        if not isinstance(row, dict):
            continue
        stage_context = row.get("stage_context")
        if not isinstance(stage_context, dict):
            continue
        request_id = str(stage_context.get("request_id") or "").strip()
        if request_id:
            groups[request_id].append(row)

    traces = [_build_trace(request_id, rows) for request_id, rows in groups.items()]
    traces.sort(key=lambda item: str(item.get("last_seen") or ""), reverse=True)
    bounded_limit = max(1, min(int(limit), 100))
    selected = traces[:bounded_limit]
    return {
        "schema_version": "agent-supervisor.gateway-trace.v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "count": len(selected),
        "total_available": len(traces),
        "raw_content_exposed": False,
        "traces": selected,
    }


def build_gateway_trace(
    request_id: str,
    audit_rows: Iterable[dict[str, Any]],
) -> dict[str, Any] | None:
    """Build one trace or return ``None`` when no matching audit exists."""

    rows = [
        row
        for row in audit_rows
        if isinstance(row, dict)
        and isinstance(row.get("stage_context"), dict)
        and str(row["stage_context"].get("request_id") or "") == str(request_id)
    ]
    if not rows:
        return None
    return _build_trace(str(request_id), rows)


def _build_trace(request_id: str, rows: list[dict[str, Any]]) -> dict[str, Any]:
    # Database queries normally return rowid order, but callers can provide
    # rows from a cache or a test fixture in either direction.  A trace is a
    # timeline, so sort it before deriving first/last facts and decision state.
    stages = [_safe_stage(row) for row in rows]
    stages.sort(key=_stage_sort_key)
    decisions = [str(stage.get("decision") or "") for stage in stages]
    decision = max(decisions or ["未知"], key=lambda value: DECISION_PRIORITY.get(value, -1))
    provider_called_values = [
        stage.get("provider_called")
        for stage in stages
        if isinstance(stage.get("provider_called"), bool)
    ]
    provider_called: bool | None
    if any(value is True for value in provider_called_values):
        provider_called = True
    elif provider_called_values and all(value is False for value in provider_called_values):
        provider_called = False
    else:
        provider_called = None

    first = stages[0] if stages else {}
    last = stages[-1] if stages else {}
    provider_stages = [stage for stage in stages if stage.get("provider_called") is True]
    provider_anchor = provider_stages[0] if provider_stages else {}
    request_hash = _first_non_empty(stages, "request_hash")
    provider_request_hash = _last_non_empty(stages, "provider_request_hash")
    provider_response_hash = _last_non_empty(stages, "provider_response_hash")
    provider_response_id = _last_non_empty(stages, "provider_response_id")
    session_id = _first_non_empty(stages, "session_id")
    agent_id = _first_non_empty(stages, "agent_id")
    provider = str(provider_anchor.get("provider") or first.get("provider") or "unknown")[:120]
    provider_profile = _first_non_empty(provider_stages or stages, "provider_profile")
    model = _first_non_empty(provider_stages or stages, "model")
    controlled_count = sum(1 for value in decisions if value in CONTROLLED_DECISIONS)
    tool_stage_count = sum(1 for stage in stages if stage.get("provider_call_id"))
    observed_count = sum(1 for stage in stages if stage.get("execution_observed_by_server") is True)
    receipt_count = sum(1 for stage in stages if stage.get("execution_receipt_present") is True)
    status = (
        "controlled"
        if controlled_count
        else "provider-failure"
        if any(stage.get("provider_failure") is True for stage in stages)
        else "allowed"
    )

    return {
        "trace_id": _safe_identifier(request_id),
        "request_id": _safe_identifier(request_id),
        "session_id": _safe_identifier(session_id),
        "agent_id": _safe_identifier(agent_id),
        "status": status,
        "decision": decision,
        "provider_called": provider_called,
        "provider": provider,
        "provider_profile": _safe_identifier(provider_profile),
        "model": _safe_identifier(model),
        "request_hash": _safe_hash(request_hash),
        "provider_request_hash": _safe_hash(provider_request_hash),
        "provider_response_hash": _safe_hash(provider_response_hash),
        "provider_response_id": _safe_identifier(provider_response_id),
        "controlled_stage_count": controlled_count,
        "tool_call_stage_count": tool_stage_count,
        "server_observed_execution_count": observed_count,
        "receipt_count": receipt_count,
        "first_seen": str(first.get("timestamp") or ""),
        "last_seen": str(last.get("timestamp") or ""),
        "stages": _bounded_stages(stages),
        "evidence": {
            "gateway_source": "openai-compatible-proxy",
            "raw_content_exposed": False,
            "request_hash_bound": bool(_safe_hash(request_hash)),
            "provider_hash_bound": bool(_safe_hash(provider_response_hash)),
            "execution_boundary": (
                "gateway-blocked-before-tool-execution"
                if decision in CONTROLLED_DECISIONS
                else "caller-or-managed-execution"
            ),
        },
    }


def _safe_stage(row: dict[str, Any]) -> dict[str, Any]:
    raw_context = row.get("stage_context")
    context: dict[str, Any] = raw_context if isinstance(raw_context, dict) else {}
    receipt = row.get("execution_receipt")
    return {
        "audit_id": _safe_identifier(str(row.get("id") or "")),
        "audit_hash": _safe_hash(row.get("audit_hash")),
        "timestamp": str(row.get("timestamp") or ""),
        "stage": _stage_name(row, context),
        "decision": str(row.get("decision") or "未知")[:16],
        "session_id": str(context.get("session_id") or row.get("conversation_id") or "")[:160],
        "agent_id": str(row.get("agent_id") or context.get("agent_id") or "")[:160],
        "policy_id": _safe_identifier(str(row.get("policy_id") or "")),
        "risk_score": _bounded_score(row.get("risk_score")),
        "tool": _safe_identifier(str(row.get("tool") or "")),
        "provider_called": context.get("provider_called") if isinstance(context.get("provider_called"), bool) else None,
        "provider_call_id": _safe_identifier(str(context.get("provider_call_id") or "")),
        "provider": str(context.get("provider") or "")[:120],
        "provider_profile": _safe_identifier(str(context.get("provider_profile") or "")),
        "model": _safe_identifier(str(context.get("provider_model") or "")),
        "provider_response_id": _safe_identifier(str(context.get("provider_response_id") or "")),
        "request_hash": _safe_hash(context.get("request_hash")),
        "provider_request_hash": _safe_hash(context.get("provider_request_hash")),
        "provider_response_hash": _safe_hash(context.get("provider_response_hash")),
        "execution_status": str(row.get("execution_status") or "")[:40],
        "execution_evidence": str(row.get("execution_evidence") or "")[:40],
        "execution_observed_by_server": row.get("execution_observed_by_server") is True,
        "execution_receipt_present": isinstance(receipt, dict) or bool(row.get("receipt_id")),
        "provider_failure": bool(context.get("provider_failure_kind") or context.get("provider_attempted")),
    }


def _stage_name(row: dict[str, Any], context: dict[str, Any]) -> str:
    if context.get("provider_failure_kind"):
        return "provider-failure"
    if context.get("provider_called") is False:
        return "pre-provider"
    if context.get("provider_call_id"):
        return "tool-call"
    if row.get("execution_status") or row.get("execution_receipt"):
        return "execution"
    return "provider-response"


def _stage_sort_key(stage: dict[str, Any]) -> tuple[str, str]:
    """Sort by the recorded timestamp, retaining deterministic tie order."""

    return (str(stage.get("timestamp") or ""), str(stage.get("audit_id") or ""))


def _first_non_empty(stages: list[dict[str, Any]], key: str) -> str:
    for stage in stages:
        value = str(stage.get(key) or "").strip()
        if value:
            return value
    return ""


def _last_non_empty(stages: list[dict[str, Any]], key: str) -> str:
    for stage in reversed(stages):
        value = str(stage.get(key) or "").strip()
        if value:
            return value
    return ""


def _bounded_stages(stages: list[dict[str, Any]], limit: int = 64) -> list[dict[str, Any]]:
    if len(stages) <= limit:
        return stages
    # Keep both ends of a long trace: the first pre-provider decision and the
    # latest execution/result stage are the two facts operators most often need.
    head = limit // 2
    tail = limit - head
    return [*stages[:head], *stages[-tail:]]


def _safe_identifier(value: str) -> str:
    candidate = str(value or "").strip()
    if not candidate:
        return ""
    if SAFE_IDENTIFIER_RE.fullmatch(candidate):
        return candidate
    return f"sha256:{hashlib.sha256(candidate.encode('utf-8', errors='replace')).hexdigest()[:16]}"


def _safe_hash(value: Any) -> str:
    candidate = str(value or "").strip()
    return candidate if re.fullmatch(r"[0-9a-fA-F]{64}", candidate) else ""


def _bounded_score(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return 0
    return max(0, min(100, int(value)))
