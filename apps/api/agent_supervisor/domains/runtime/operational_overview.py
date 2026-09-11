"""Build the operator-facing snapshot from live runtime evidence only."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any

from apps.api.agent_supervisor.domains.governance.approvals import list_approval_reviews
from apps.api.agent_supervisor.domains.runtime.execution_receipts import list_execution_receipts
from apps.api.agent_supervisor.domains.runtime.gateway_trace import build_gateway_trace_index
from apps.api.agent_supervisor.domains.runtime.runtime_status import build_runtime_status
from apps.api.agent_supervisor.storage.database import latest_operational_audit_logs

OPERATIONAL_SOURCES = {"openai-compatible-proxy", "mcp-gateway"}
CONTROLLED_DECISIONS = {"拒绝", "询问", "隔离"}
DECISION_PRIORITY = {"未知": -1, "允许": 0, "询问": 1, "隔离": 2, "拒绝": 3}
WINDOW_SECONDS = {"1h": 60 * 60, "6h": 6 * 60 * 60, "24h": 24 * 60 * 60, "7d": 7 * 24 * 60 * 60}


def build_operational_overview(window: str = "1h", role: str = "observer") -> dict[str, Any]:
    window_key = window if window in WINDOW_SECONDS else "1h"
    now = datetime.now(timezone.utc)
    start = now - timedelta(seconds=WINDOW_SECONDS[window_key])
    source_errors: list[dict[str, str]] = []

    try:
        audit_logs = latest_operational_audit_logs(2000)
    except Exception as exc:  # pragma: no cover - exercised through storage failure integration tests
        audit_logs = []
        source_errors.append({"source": "audit_logs", "error": type(exc).__name__})

    audit_source_failed = any(item["source"] == "audit_logs" for item in source_errors)
    window_logs = [row for row in audit_logs if _in_window(row.get("timestamp"), start, now)]
    records, audit_to_request = _request_records(window_logs)

    try:
        approval_inventory = list_approval_reviews(limit=500)
    except Exception as exc:  # pragma: no cover - exercised through storage failure integration tests
        approval_inventory = {"reviews": [], "summary": {}}
        source_errors.append({"source": "approval_reviews", "error": type(exc).__name__})

    approval_source_failed = any(item["source"] == "approval_reviews" for item in source_errors)
    operational_reviews = [
        item
        for item in approval_inventory.get("reviews", [])
        if isinstance(item, dict)
        and str(item.get("source_app") or "") in OPERATIONAL_SOURCES
        and _in_window(item.get("created_at"), start, now)
    ]
    pending_reviews = [item for item in operational_reviews if item.get("status") == "待复核"]

    try:
        execution_inventory = list_execution_receipts(limit=500)
    except Exception as exc:  # pragma: no cover - exercised through storage failure integration tests
        execution_inventory = {"receipts": [], "gateway_execution_claims": [], "summary": {}}
        source_errors.append({"source": "execution_receipts", "error": type(exc).__name__})

    receipt_source_failed = any(item["source"] == "execution_receipts" for item in source_errors)
    receipts = [
        item
        for item in execution_inventory.get("receipts", [])
        if isinstance(item, dict) and _in_window(item.get("created_at"), start, now)
    ]
    unknown_claims = [
        item
        for item in execution_inventory.get("gateway_execution_claims", [])
        if isinstance(item, dict) and item.get("status") == "unknown" and _in_window(item.get("created_at"), start, now)
    ]

    try:
        runtime_status = build_runtime_status(expose_provider_endpoints=role in {"analyst", "admin"})
    except Exception as exc:  # pragma: no cover - exercised through runtime failure integration tests
        runtime_status = {}
        source_errors.append({"source": "runtime_status", "error": type(exc).__name__})

    gateway_rows = [row for row in window_logs if row.get("source_app") == "openai-compatible-proxy"]
    try:
        trace_index = build_gateway_trace_index(gateway_rows, limit=12)
    except Exception as exc:  # pragma: no cover - exercised through gateway trace integration tests
        trace_index = {"traces": [], "summary": {}}
        source_errors.append({"source": "gateway_traces", "error": type(exc).__name__})
    activities = _activities(trace_index.get("traces", []), records)
    decisions = Counter(str(record.get("decision") or "未知") for record in records)
    controlled_count = sum(1 for record in records if record.get("decision") in CONTROLLED_DECISIONS)
    denied_count = decisions.get("拒绝", 0)
    asked_count = decisions.get("询问", 0)
    isolated_count = decisions.get("隔离", 0)
    unconfirmed_count = sum(
        1
        for record in records
        if (record.get("receipt_expected") and not record.get("receipt_present")) or record.get("execution_unconfirmed")
    ) + sum(1 for claim in unknown_claims if str(claim.get("audit_id") or "") not in audit_to_request)
    evidence_counts = Counter(str(record.get("evidence_status") or "unknown") for record in records)
    provider_failure_count = sum(1 for record in records if record.get("provider_failure"))
    provider_called_count = sum(1 for record in records if record.get("provider_called"))
    latency_values = [float(value) for value in (record.get("latency_ms") for record in records) if value is not None]

    runtime_source_failed = any(item["source"] == "runtime_status" for item in source_errors)
    readiness = _readiness(runtime_status, available=not runtime_source_failed)
    action_queue = _action_queue(
        pending_reviews,
        unknown_claims,
        records,
        audit_to_request,
        readiness,
    )
    if source_errors:
        action_queue.insert(
            0,
            {
                "id": "operational-source-errors",
                "kind": "data",
                "title": "运营数据源异常",
                "description": "部分实时来源不可用，受影响指标显示为未知，不按零值处理。",
                "count": len(source_errors),
                "tone": "danger",
                "audit_ids": [],
                "request_ids": [],
            },
        )
    has_runtime_activity = bool(records or pending_reviews or receipts or unknown_claims)
    data_status = "degraded" if source_errors else "live" if has_runtime_activity else "empty"
    request_count = len(records) if not audit_source_failed else None
    control_rate = round((controlled_count / request_count) * 100) if request_count else None
    models = runtime_status.get("models", {}).get("global", []) if isinstance(runtime_status, dict) else []

    summary = {
        "recent_run_count": request_count if request_count is not None else 0,
        "block_rate": control_rate,
        "avg_latency_ms": round(sum(latency_values) / len(latency_values), 2) if latency_values and not audit_source_failed else None,
        "request_count": request_count,
        "allowed_count": decisions.get("允许", 0) if not audit_source_failed else None,
        "controlled_count": controlled_count if not audit_source_failed else None,
        "denied_count": denied_count if not audit_source_failed else None,
        "approval_count": asked_count if not audit_source_failed else None,
        "isolated_count": isolated_count if not audit_source_failed else None,
        "control_rate": control_rate,
        "provider_failure_count": provider_failure_count if not audit_source_failed else None,
        "provider_called_count": provider_called_count if not audit_source_failed else None,
        "pending_review_count": len(pending_reviews) if not approval_source_failed else None,
        "execution_receipt_count": len(receipts) if not receipt_source_failed else None,
        "execution_completed_count": sum(1 for item in receipts if item.get("status") == "completed") if not receipt_source_failed else None,
        "execution_failed_count": sum(1 for item in receipts if item.get("status") == "failed") if not receipt_source_failed else None,
        "execution_not_executed_count": sum(1 for item in receipts if item.get("status") == "not_executed") if not receipt_source_failed else None,
        "execution_unconfirmed_count": unconfirmed_count if not receipt_source_failed else None,
        "evidence_verified_count": evidence_counts.get("verified", 0) if not audit_source_failed else None,
        "evidence_pending_count": evidence_counts.get("pending", 0) if not audit_source_failed else None,
        "evidence_invalid_count": evidence_counts.get("invalid", 0) if not audit_source_failed else None,
    }

    return {
        "schema_version": "agent-supervisor.operational-overview.v1",
        "generated_at": now.isoformat(),
        "updated_at": max(
            [str(record.get("last_seen") or "") for record in records]
            + [str(item.get("created_at") or "") for item in operational_reviews]
            + [str(item.get("created_at") or "") for item in receipts],
            default="",
        ),
        "data_status": data_status,
        "source_errors": source_errors,
        "sources": sorted(OPERATIONAL_SOURCES | {"approval_reviews", "execution_receipts"}),
        "window": {
            "key": window_key,
            "seconds": WINDOW_SECONDS[window_key],
            "start_at": start.isoformat(),
            "end_at": now.isoformat(),
            "sample_limit": 2000,
        },
        "summary": summary,
        "decision_distribution": dict(decisions),
        "trend": _trend(records, start, now, WINDOW_SECONDS[window_key]) if not audit_source_failed else [],
        "activity": activities,
        "action_queue": action_queue,
        "readiness": readiness,
        "models": models,
        "recent_runs": [],
        "alerts": [],
        "audit_logs": [],
        "access_scope": "summary-redacted" if role == "observer" else "operational",
    }


def _request_records(rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, str]]:
    records_by_key: dict[str, dict[str, Any]] = {}
    audit_to_request: dict[str, str] = {}
    evidence_priority = {"unknown": 0, "pending": 1, "verified": 2, "invalid": 3}
    for row in rows:
        source = str(row.get("source_app") or "")
        if source not in OPERATIONAL_SOURCES:
            continue
        raw_context = row.get("stage_context")
        context: dict[str, Any] = dict(raw_context) if isinstance(raw_context, dict) else {}
        request_id = str(context.get("request_id") or row.get("id") or "").strip()
        if not request_id:
            continue
        key = f"gateway:{request_id}" if source == "openai-compatible-proxy" else f"audit:{request_id}"
        timestamp = str(row.get("timestamp") or "")
        record = records_by_key.setdefault(
            key,
            {
                "request_id": request_id,
                "source_app": source,
                "first_seen": timestamp,
                "last_seen": timestamp,
                "decision": "未知",
                "decision_rank": -1,
                "provider_called": False,
                "provider_failure": False,
                "receipt_expected": False,
                "receipt_present": False,
                "evidence_status": "unknown",
                "policy_id": "",
                "tool": "",
                "risk_score": 0,
                "latency_ms": None,
                "execution_unconfirmed": False,
            },
        )
        if timestamp and timestamp < str(record.get("first_seen") or ""):
            record["first_seen"] = timestamp
        if timestamp > str(record.get("last_seen") or ""):
            record["last_seen"] = timestamp
        decision = str(row.get("decision") or "未知")
        if DECISION_PRIORITY.get(decision, -1) >= int(record.get("decision_rank") or -1):
            record["decision"] = decision
            record["decision_rank"] = DECISION_PRIORITY.get(decision, -1)
            record["policy_id"] = str(row.get("policy_id") or "")
            record["tool"] = str(row.get("tool") or "")
        record["provider_called"] = bool(record.get("provider_called") or context.get("provider_called") is True)
        record["provider_failure"] = bool(
            record.get("provider_failure")
            or context.get("provider_failure_kind")
            or context.get("provider_attempted")
        )
        record["receipt_expected"] = bool(record.get("receipt_expected") or row.get("execution_receipt_expected"))
        record["receipt_present"] = bool(
            record.get("receipt_present") or isinstance(row.get("execution_receipt"), dict) or row.get("receipt_id")
        )
        record["execution_unconfirmed"] = bool(
            record.get("execution_unconfirmed")
            or row.get("execution_status") == "unknown"
            or row.get("gateway_execution_claim_status") == "unknown"
        )
        evidence = str(row.get("evidence_status") or "unknown")
        if evidence_priority.get(evidence, 0) >= evidence_priority.get(str(record.get("evidence_status")), 0):
            record["evidence_status"] = evidence
        latency = row.get("execution_duration_ms") or row.get("detection_latency_ms")
        if isinstance(latency, (int, float)) and not isinstance(latency, bool):
            record["latency_ms"] = float(latency)
        audit_id = str(row.get("id") or "")
        if audit_id:
            audit_to_request[audit_id] = request_id
    return list(records_by_key.values()), audit_to_request


def _activities(traces: list[dict[str, Any]], records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    activities = [dict(item, source_app="openai-compatible-proxy") for item in traces if isinstance(item, dict)]
    gateway_request_ids = {str(item.get("request_id") or "") for item in activities}
    for record in records:
        if record.get("source_app") != "mcp-gateway" or record.get("request_id") in gateway_request_ids:
            continue
        activities.append(
            {
                "trace_id": str(record.get("request_id") or ""),
                "request_id": str(record.get("request_id") or ""),
                "source_app": "mcp-gateway",
                "status": "controlled" if record.get("decision") in CONTROLLED_DECISIONS else "allowed",
                "decision": record.get("decision", "未知"),
                "provider": "MCP Gateway",
                "model": "",
                "risk_score": record.get("risk_score", 0),
                "first_seen": record.get("first_seen", ""),
                "last_seen": record.get("last_seen", ""),
            }
        )
    return sorted(activities, key=lambda item: str(item.get("last_seen") or ""), reverse=True)[:12]


def _trend(records: list[dict[str, Any]], start: datetime, end: datetime, seconds: int) -> list[dict[str, Any]]:
    bucket_count = 12
    bucket_seconds = max(1, seconds // bucket_count)
    buckets: list[dict[str, Any]] = [
        {
            "bucket_start": (start + timedelta(seconds=index * bucket_seconds)).isoformat(),
            "request_count": 0,
            "allowed_count": 0,
            "controlled_count": 0,
            "denied_count": 0,
            "approval_count": 0,
            "isolated_count": 0,
        }
        for index in range(bucket_count)
    ]
    for record in records:
        timestamp = _parse_time(record.get("last_seen"))
        if timestamp is None:
            continue
        index = min(bucket_count - 1, max(0, int((timestamp - start).total_seconds() // bucket_seconds)))
        bucket = buckets[index]
        bucket["request_count"] += 1
        decision = str(record.get("decision") or "未知")
        bucket["allowed_count"] += int(decision == "允许")
        bucket["controlled_count"] += int(decision in CONTROLLED_DECISIONS)
        bucket["denied_count"] += int(decision == "拒绝")
        bucket["approval_count"] += int(decision == "询问")
        bucket["isolated_count"] += int(decision == "隔离")
    return buckets


def _action_queue(
    pending_reviews: list[dict[str, Any]],
    unknown_claims: list[dict[str, Any]],
    records: list[dict[str, Any]],
    audit_to_request: dict[str, str],
    readiness: dict[str, dict[str, str]],
) -> list[dict[str, Any]]:
    actions: list[dict[str, Any]] = []
    pending_audits = [str(item.get("audit_id") or "") for item in pending_reviews if item.get("audit_id")]
    pending_requests = [audit_to_request[audit_id] for audit_id in pending_audits if audit_id in audit_to_request]
    if pending_reviews:
        actions.append(
            {
                "id": "pending-approvals",
                "kind": "approval",
                "title": "待人工复核",
                "description": "高风险请求已暂停，等待操作员决定是否恢复。",
                "count": len(pending_reviews),
                "tone": "warning",
                "audit_ids": pending_audits[:8],
                "request_ids": pending_requests[:8],
            }
        )
    unknown_audits = [str(item.get("audit_id") or "") for item in unknown_claims if item.get("audit_id")]
    if unknown_claims:
        actions.append(
            {
                "id": "unknown-executions",
                "kind": "execution",
                "title": "执行状态不确定",
                "description": "可能已经产生副作用，必须先核查目标系统，禁止自动重试。",
                "count": len(unknown_claims),
                "tone": "danger",
                "audit_ids": unknown_audits[:8],
                "request_ids": [audit_to_request[item] for item in unknown_audits if item in audit_to_request][:8],
            }
        )
    invalid_records = [item for item in records if item.get("evidence_status") == "invalid"]
    if invalid_records:
        actions.append(
            {
                "id": "invalid-evidence",
                "kind": "evidence",
                "title": "证据核验失败",
                "description": "Hash、签名或回执绑定未形成可信证据。",
                "count": len(invalid_records),
                "tone": "danger",
                "audit_ids": [],
                "request_ids": [str(item.get("request_id") or "") for item in invalid_records[:8]],
            }
        )
    for key, item in readiness.items():
        if item.get("status") == "attention":
            actions.append(
                {
                    "id": f"readiness-{key}",
                    "kind": "readiness",
                    "title": item.get("label", "运行边界待处理"),
                    "description": item.get("description", "请在设置中完成运行边界配置。"),
                    "count": 1,
                    "tone": "warning",
                    "audit_ids": [],
                    "request_ids": [],
                }
            )
    return actions[:8]


def _readiness(status: dict[str, Any], *, available: bool = True) -> dict[str, dict[str, str]]:
    if not available:
        return {
            key: {
                "status": "unknown",
                "label": label,
                "description": "运行状态来源读取失败，当前无法确认。",
            }
            for key, label in (
                ("gateway", "网关边界"),
                ("provider", "Provider 接入"),
                ("mcp", "MCP 工具边界"),
                ("evidence", "证据链"),
            )
        }
    models = status.get("models", {}) if isinstance(status, dict) else {}
    target = models.get("target", []) if isinstance(models, dict) else []
    provider_ready = any(
        isinstance(item, dict) and item.get("configured") and item.get("mode") == "real-api" for item in target
    )
    proxy = status.get("proxy", {}) if isinstance(status, dict) else {}
    evidence = status.get("gateway_evidence", {}) if isinstance(status, dict) else {}
    gateway_ready = bool(
        isinstance(proxy, dict)
        and proxy.get("enabled")
        and isinstance(evidence, dict)
        and evidence.get("fingerprint")
        and proxy.get("tool_receipts_required")
        and proxy.get("server_observed_receipts_required")
    )
    mcp = status.get("mcp", {}) if isinstance(status, dict) else {}
    mcp_configured = isinstance(mcp, dict) and mcp.get("configured")
    mcp_ready = bool(mcp_configured and mcp.get("enabled") and mcp.get("guard_enabled"))
    return {
        "gateway": {
            "status": "ready" if gateway_ready else "attention",
            "label": "网关边界",
            "description": "请求策略、回执和服务端观察边界已闭合。" if gateway_ready else "网关回执信任边界尚未闭合。",
        },
        "provider": {
            "status": "ready" if provider_ready else "attention",
            "label": "Provider 接入",
            "description": "目标模型已配置真实 API。" if provider_ready else "目标 Provider 尚未配置真实 API。",
        },
        "mcp": {
            "status": "ready" if mcp_ready else "attention",
            "label": "MCP 工具边界",
            "description": "MCP 已启用并经过强制网关。" if mcp_ready else "MCP 尚未完成配置或强制边界。",
        },
        "evidence": {
            "status": "ready" if gateway_ready else "attention",
            "label": "证据链",
            "description": "网关运行指纹、Hash 与回执约束已登记。" if gateway_ready else "证据链运行指纹或回执约束尚未就绪。",
        },
    }


def _parse_time(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)


def _in_window(value: Any, start: datetime, end: datetime) -> bool:
    parsed = _parse_time(value)
    return parsed is not None and start <= parsed <= end
