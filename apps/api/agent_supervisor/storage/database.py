from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any

from apps.api.agent_supervisor.paths import RUNTIME_DIR

DB_PATH = RUNTIME_DIR / "agent_supervisor.sqlite3"


@contextmanager
def get_connection() -> Iterator[sqlite3.Connection]:
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.execute("PRAGMA busy_timeout = 10000")
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    with get_connection() as conn:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS experiment_runs (
                id TEXT PRIMARY KEY,
                scenario_id TEXT NOT NULL,
                guard_enabled INTEGER NOT NULL,
                attack_success INTEGER NOT NULL,
                blocked_count INTEGER NOT NULL,
                asked_count INTEGER NOT NULL,
                isolated_count INTEGER NOT NULL,
                detection_latency_ms INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                payload TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_logs (
                id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                tool TEXT NOT NULL,
                decision TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                reason TEXT NOT NULL,
                payload TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                decision TEXT NOT NULL,
                evidence TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS approval_reviews (
                id TEXT PRIMARY KEY,
                audit_id TEXT NOT NULL UNIQUE,
                run_id TEXT NOT NULL,
                status TEXT NOT NULL,
                final_decision TEXT NOT NULL,
                tool TEXT NOT NULL,
                policy_id TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                reason TEXT NOT NULL,
                operator TEXT NOT NULL,
                created_at TEXT NOT NULL,
                reviewed_at TEXT NOT NULL,
                payload TEXT NOT NULL
            )
            """
        )
        _ensure_governance_tables(conn)


def _ensure_governance_tables(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS policy_versions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            policy_id TEXT NOT NULL,
            operator TEXT NOT NULL,
            comment TEXT NOT NULL,
            created_at TEXT NOT NULL,
            before_payload TEXT NOT NULL,
            after_payload TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS runtime_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            created_at TEXT NOT NULL,
            payload TEXT NOT NULL
        )
        """
    )


def write_run(result: dict[str, Any]) -> None:
    with get_connection() as conn:
        _ensure_governance_tables(conn)
        conn.execute(
            """
            INSERT OR REPLACE INTO experiment_runs (
                id, scenario_id, guard_enabled, attack_success, blocked_count,
                asked_count, isolated_count, detection_latency_ms, created_at, payload
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                result["run_id"],
                result["scenario"]["id"],
                int(result["guard_enabled"]),
                int(result["attack_success"]),
                result["metrics"]["blocked_count"],
                result["metrics"]["asked_count"],
                result["metrics"]["isolated_count"],
                result["metrics"]["detection_latency_ms"],
                result["created_at"],
                json.dumps(result, ensure_ascii=False),
            ),
        )
        for log in result["audit_logs"]:
            conn.execute(
                """
                INSERT OR REPLACE INTO audit_logs (
                    id, run_id, tool, decision, risk_level, reason, payload
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    log["id"],
                    result["run_id"],
                    log["tool"],
                    log["decision"],
                    log["risk_level"],
                    log["reason"],
                    json.dumps(log, ensure_ascii=False),
                ),
            )
        for alert in result["alerts"]:
            conn.execute(
                """
                INSERT OR REPLACE INTO alerts (
                    id, run_id, severity, title, decision, evidence, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert["id"],
                    result["run_id"],
                    alert["severity"],
                    alert["title"],
                    alert["decision"],
                    alert["evidence"],
                    alert["created_at"],
                ),
            )
        conn.execute(
            """
            INSERT INTO runtime_events (event_type, created_at, payload)
            VALUES (?, ?, ?)
            """,
            (
                "run",
                result["created_at"],
                json.dumps(
                    {
                        "run_id": result["run_id"],
                        "scenario_id": result.get("scenario", {}).get("id", ""),
                        "guard_enabled": result.get("guard_enabled", False),
                        "attack_success": result.get("attack_success", False),
                        "metrics": result.get("metrics", {}),
                    },
                    ensure_ascii=False,
                ),
            ),
        )


def append_runtime_event(
    event_type: str,
    payload: dict[str, Any],
    *,
    created_at: str | None = None,
) -> dict[str, Any]:
    """Append an immutable runtime event to the existing event journal."""
    event_created_at = created_at or datetime.now(timezone.utc).isoformat()
    with get_connection() as conn:
        _ensure_governance_tables(conn)
        cursor = conn.execute(
            """
            INSERT INTO runtime_events (event_type, created_at, payload)
            VALUES (?, ?, ?)
            """,
            (event_type, event_created_at, json.dumps(payload, ensure_ascii=False, sort_keys=True)),
        )
        event_id = int(cursor.lastrowid or 0)
    return {
        "event_id": event_id,
        "event_type": event_type,
        "created_at": event_created_at,
        "payload": payload,
    }


def list_runtime_events(
    *,
    event_type: str | None = None,
    limit: int = 500,
) -> list[dict[str, Any]]:
    """Read the append-only runtime journal in newest-first order."""
    bounded_limit = max(1, min(int(limit), 5000))
    query = "SELECT id, event_type, created_at, payload FROM runtime_events"
    params: tuple[Any, ...]
    if event_type:
        query += " WHERE event_type = ?"
        params = (event_type, bounded_limit)
    else:
        params = (bounded_limit,)
    query += " ORDER BY id DESC LIMIT ?"
    with get_connection() as conn:
        _ensure_governance_tables(conn)
        rows = conn.execute(query, params).fetchall()
    events: list[dict[str, Any]] = []
    for row in rows:
        try:
            payload = json.loads(row["payload"])
        except (TypeError, json.JSONDecodeError):
            payload = {"raw_payload": str(row["payload"])}
        events.append(
            {
                "event_id": int(row["id"]),
                "event_type": row["event_type"],
                "created_at": row["created_at"],
                "payload": payload,
            }
        )
    return events


def load_runtime_event_by_payload_id(event_type: str, key: str, value: str) -> dict[str, Any] | None:
    """Load one immutable runtime event by an allowlisted top-level identifier."""
    if not event_type or key != "comparison_id" or not value:
        return None
    with get_connection() as conn:
        _ensure_governance_tables(conn)
        row = conn.execute(
            """
            SELECT id, created_at, payload
            FROM runtime_events
            WHERE event_type = ?
              AND json_extract(payload, '$.comparison_id') = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (event_type, value),
        ).fetchone()
    if row is None:
        return None
    try:
        payload = json.loads(row["payload"])
    except (TypeError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict) or str(payload.get("comparison_id", "")) != value:
        return None
    return {
        "event_id": int(row["id"]),
        "event_type": event_type,
        "created_at": row["created_at"],
        "payload": payload,
    }


def execution_receipts_for_audits(limit: int = 500) -> dict[str, dict[str, Any]]:
    """Return the newest execution receipt for each audit id."""
    receipts: dict[str, dict[str, Any]] = {}
    for event in list_runtime_events(event_type="execution-receipt", limit=limit):
        payload = event.get("payload")
        if not isinstance(payload, dict):
            continue
        audit_id = str(payload.get("audit_id", ""))
        if audit_id and audit_id not in receipts:
            receipts[audit_id] = {
                **payload,
                "event_id": event.get("event_id"),
                "journal_created_at": event.get("created_at"),
            }
    return receipts


def load_execution_receipt(audit_id: str) -> dict[str, Any] | None:
    """Load the persisted receipt for one audit without scanning a bounded list."""
    with get_connection() as conn:
        _ensure_governance_tables(conn)
        rows = conn.execute(
            """
            SELECT id, created_at, payload
            FROM runtime_events
            WHERE event_type = 'execution-receipt'
              AND json_extract(payload, '$.audit_id') = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (audit_id,),
        ).fetchall()
    for row in rows:
        try:
            payload = json.loads(row["payload"])
        except (TypeError, json.JSONDecodeError):
            continue
        if not isinstance(payload, dict) or str(payload.get("audit_id", "")) != audit_id:
            continue
        return {
            **payload,
            "event_id": int(row["id"]),
            "journal_created_at": row["created_at"],
        }
    return None


def persist_execution_receipt(payload: dict[str, Any]) -> dict[str, Any]:
    """Atomically append one receipt per audit and support exact idempotent retries."""
    with get_connection() as conn:
        _ensure_governance_tables(conn)
        conn.execute("BEGIN IMMEDIATE")
        rows = conn.execute(
            """
            SELECT id, created_at, payload
            FROM runtime_events
            WHERE event_type = 'execution-receipt'
            ORDER BY id DESC
            """
        ).fetchall()
        for row in rows:
            try:
                existing = json.loads(row["payload"])
            except (TypeError, json.JSONDecodeError):
                continue
            if not isinstance(existing, dict):
                continue
            same_receipt = existing.get("receipt_id") == payload.get("receipt_id")
            same_audit = existing.get("audit_id") == payload.get("audit_id")
            if not same_receipt and not same_audit:
                continue
            if (
                same_receipt
                and same_audit
                and existing.get("request_hash") == payload.get("request_hash")
            ):
                return {
                    "event_id": int(row["id"]),
                    "event_type": "execution-receipt",
                    "created_at": row["created_at"],
                    "payload": existing,
                    "idempotent": True,
                    "conflict": False,
                }
            return {
                "event_id": int(row["id"]),
                "event_type": "execution-receipt",
                "created_at": row["created_at"],
                "payload": existing,
                "idempotent": False,
                "conflict": True,
            }

        cursor = conn.execute(
            """
            INSERT INTO runtime_events (event_type, created_at, payload)
            VALUES ('execution-receipt', ?, ?)
            """,
            (
                str(payload["created_at"]),
                json.dumps(payload, ensure_ascii=False, sort_keys=True),
            ),
        )
        return {
            "event_id": int(cursor.lastrowid or 0),
            "event_type": "execution-receipt",
            "created_at": payload["created_at"],
            "payload": payload,
            "idempotent": False,
            "conflict": False,
        }


def enrich_audit_logs_with_execution_receipts(logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Add receipt state to response copies without mutating the hashed audit log."""
    receipts = execution_receipts_for_audits(limit=max(500, len(logs) * 3 or 500))
    enriched: list[dict[str, Any]] = []
    for log in logs:
        copy = dict(log)
        receipt = receipts.get(str(log.get("id", "")))
        copy["execution_receipt"] = receipt
        if receipt:
            copy["execution_status"] = str(receipt.get("status"))
            copy["execution_target"] = str(receipt.get("execution_target"))
        elif log.get("execution_receipt_expected"):
            copy["execution_status"] = "awaiting_receipt"
            copy["execution_target"] = "unknown"
        elif isinstance(log.get("tool_output"), dict) and log["tool_output"].get("executed"):
            copy["execution_status"] = "server_sandbox_completed"
            copy["execution_target"] = "sandbox"
        else:
            copy["execution_status"] = "not_applicable"
            copy["execution_target"] = "none"
        enriched.append(copy)
    return enriched


def latest_runs(limit: int = 20) -> list[dict[str, Any]]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT payload FROM experiment_runs ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [json.loads(row["payload"]) for row in rows]


def latest_scenario_run_pairs(scenario_ids: list[str]) -> list[dict[str, Any]]:
    """Return the newest guarded and unguarded run for each requested scenario.

    Evaluation evidence must not disappear when high-volume external runtime
    events push configured scenario runs outside a generic recent-run window.
    """
    requested_ids = list(dict.fromkeys(str(value) for value in scenario_ids if value))
    if not requested_ids:
        return []
    placeholders = ", ".join("?" for _ in requested_ids)
    query = f"""
        SELECT payload
        FROM (
            SELECT payload,
                   ROW_NUMBER() OVER (
                       PARTITION BY scenario_id, guard_enabled
                       ORDER BY created_at DESC, rowid DESC
                   ) AS evidence_rank
            FROM experiment_runs
            WHERE scenario_id IN ({placeholders})
        )
        WHERE evidence_rank = 1
    """
    with get_connection() as conn:
        rows = conn.execute(query, tuple(requested_ids)).fetchall()
    return [json.loads(row["payload"]) for row in rows]


def load_run(run_id: str) -> dict[str, Any] | None:
    with get_connection() as conn:
        row = conn.execute("SELECT payload FROM experiment_runs WHERE id = ?", (run_id,)).fetchone()
    return json.loads(row["payload"]) if row else None


def latest_audit_logs(limit: int = 100) -> list[dict[str, Any]]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT payload FROM audit_logs ORDER BY rowid DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return enrich_audit_logs_with_execution_receipts([json.loads(row["payload"]) for row in rows])


def load_audit_log(audit_id: str) -> dict[str, Any] | None:
    """Load the original immutable audit payload without response enrichment."""
    with get_connection() as conn:
        row = conn.execute("SELECT payload FROM audit_logs WHERE id = ?", (audit_id,)).fetchone()
    return json.loads(row["payload"]) if row else None


def load_audit_logs_by_conversation_ids(conversation_ids: set[str]) -> list[dict[str, Any]]:
    """Load exact comparison branches without relying on a recent-log window."""
    requested = sorted(value for value in conversation_ids if value)
    if not requested:
        return []
    placeholders = ", ".join("?" for _ in requested)
    with get_connection() as conn:
        rows = conn.execute(
            f"""
            SELECT payload
            FROM audit_logs
            WHERE json_extract(payload, '$.conversation_id') IN ({placeholders})
            """,
            tuple(requested),
        ).fetchall()
    return [json.loads(row["payload"]) for row in rows]


def record_policy_version(
    *,
    policy_id: str,
    before: dict[str, Any],
    after: dict[str, Any],
    operator: str = "security-admin",
    comment: str = "",
) -> dict[str, Any]:
    created_at = datetime.now(timezone.utc).isoformat()
    with get_connection() as conn:
        _ensure_governance_tables(conn)
        cursor = conn.execute(
            """
            INSERT INTO policy_versions (
                policy_id, operator, comment, created_at, before_payload, after_payload
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                policy_id,
                operator or "security-admin",
                comment,
                created_at,
                json.dumps(before, ensure_ascii=False),
                json.dumps(after, ensure_ascii=False),
            ),
        )
    return {
        "id": cursor.lastrowid,
        "policy_id": policy_id,
        "operator": operator or "security-admin",
        "comment": comment,
        "created_at": created_at,
        "before": before,
        "after": after,
    }


def list_policy_versions(policy_id: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
    query = """
        SELECT id, policy_id, operator, comment, created_at, before_payload, after_payload
        FROM policy_versions
    """
    params: tuple[Any, ...]
    if policy_id:
        query += " WHERE policy_id = ?"
        params = (policy_id, limit)
    else:
        params = (limit,)
    query += " ORDER BY id DESC LIMIT ?"
    with get_connection() as conn:
        _ensure_governance_tables(conn)
        rows = conn.execute(query, params).fetchall()
    return [
        {
            "id": row["id"],
            "policy_id": row["policy_id"],
            "operator": row["operator"],
            "comment": row["comment"],
            "created_at": row["created_at"],
            "before": json.loads(row["before_payload"]),
            "after": json.loads(row["after_payload"]),
        }
        for row in rows
    ]


def runtime_metrics_snapshot(limit: int = 500) -> dict[str, Any]:
    runs = latest_runs(limit)
    audit_logs = latest_audit_logs(limit)
    with get_connection() as conn:
        _ensure_governance_tables(conn)
        review_rows = conn.execute(
            "SELECT status, risk_level, reviewed_at FROM approval_reviews ORDER BY rowid DESC LIMIT ?",
            (limit,),
        ).fetchall()
        policy_version_count = conn.execute("SELECT COUNT(*) AS count FROM policy_versions").fetchone()["count"]
    receipt_map = execution_receipts_for_audits(limit=max(limit, 500))
    latencies = [
        float(run.get("metrics", {}).get("detection_latency_ms", 0))
        for run in runs
        if run.get("metrics", {}).get("detection_latency_ms") is not None
    ]
    controlled = [
        run
        for run in runs
        if run.get("metrics", {}).get("blocked_count", 0)
        or run.get("metrics", {}).get("asked_count", 0)
        or run.get("metrics", {}).get("isolated_count", 0)
    ]
    decisions: dict[str, int] = {}
    policies: dict[str, int] = {}
    tools: dict[str, int] = {}
    for log in audit_logs:
        decisions[str(log.get("decision", "unknown"))] = decisions.get(str(log.get("decision", "unknown")), 0) + 1
        policies[str(log.get("policy_id", "unknown"))] = policies.get(str(log.get("policy_id", "unknown")), 0) + 1
        tools[str(log.get("tool", "unknown"))] = tools.get(str(log.get("tool", "unknown")), 0) + 1
    pending_reviews = sum(1 for row in review_rows if row["status"] == "待复核")
    resolved_reviews = sum(1 for row in review_rows if row["status"] in {"已批准", "已驳回"})
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "window": {"run_limit": limit, "audit_limit": limit},
        "summary": {
            "run_count": len(runs),
            "controlled_count": len(controlled),
            "control_rate": round((len(controlled) / len(runs)) * 100) if runs else 0,
            "attack_success_count": sum(1 for run in runs if run.get("attack_success")),
            "avg_detection_latency_ms": round(sum(latencies) / len(latencies), 2) if latencies else 0,
            "max_detection_latency_ms": round(max(latencies), 2) if latencies else 0,
            "audit_log_count": len(audit_logs),
            "pending_review_count": pending_reviews,
            "resolved_review_count": resolved_reviews,
            "policy_version_count": int(policy_version_count),
            "execution_receipt_count": len(receipt_map),
            "execution_completed_count": sum(1 for item in receipt_map.values() if item.get("status") == "completed"),
            "execution_failed_count": sum(1 for item in receipt_map.values() if item.get("status") == "failed"),
            "execution_not_executed_count": sum(1 for item in receipt_map.values() if item.get("status") == "not_executed"),
            "execution_unconfirmed_count": sum(
                1
                for log in audit_logs
                if log.get("execution_receipt_expected") and not log.get("execution_receipt")
            ),
            "execution_control_verified_count": sum(1 for item in receipt_map.values() if item.get("control_verified")),
        },
        "decision_distribution": decisions,
        "policy_hit_distribution": policies,
        "tool_distribution": tools,
    }
