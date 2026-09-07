from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any

from apps.api.agent_supervisor.paths import RUNTIME_DIR
from apps.api.agent_supervisor.storage.json_store import decode_json_strict, encode_json_strict, exclusive_file_lock

DB_PATH = RUNTIME_DIR / "agent_supervisor.sqlite3"
MAX_QUERY_LIMIT = 5000


def _bounded_limit(value: Any, *, default: int, maximum: int = MAX_QUERY_LIMIT) -> int:
    try:
        normalized = int(value)
    except (TypeError, ValueError, OverflowError):
        normalized = default
    return max(1, min(normalized, maximum))


def _decode_json_object(raw: Any) -> dict[str, Any] | None:
    try:
        payload = decode_json_strict(raw)
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


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


def _init_db_unlocked() -> None:
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
    # Delayed import avoids the data -> database top-level dependency cycle.
    # A failed replay remains durable in the outbox and must not stop startup.
    from apps.api.agent_supervisor.storage.data import recover_policy_audit_outbox

    recover_policy_audit_outbox()


def init_db() -> None:
    # SQLite busy_timeout does not reliably serialize simultaneous WAL setup
    # or check-then-ALTER migrations across API worker processes.
    with exclusive_file_lock(DB_PATH, timeout_seconds=30.0):
        _init_db_unlocked()


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
            after_payload TEXT NOT NULL,
            operation_id TEXT NOT NULL DEFAULT ''
        )
        """
    )
    policy_version_columns = {row["name"] for row in conn.execute("PRAGMA table_info(policy_versions)").fetchall()}
    if "operation_id" not in policy_version_columns:
        conn.execute("ALTER TABLE policy_versions ADD COLUMN operation_id TEXT NOT NULL DEFAULT ''")
    conn.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS idx_policy_versions_operation_id
        ON policy_versions (operation_id)
        WHERE operation_id <> ''
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
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS gateway_execution_claims (
            audit_id TEXT PRIMARY KEY,
            claim_id TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            session_id TEXT NOT NULL,
            tool_call_hash TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            completed_at TEXT NOT NULL DEFAULT '',
            receipt_id TEXT NOT NULL DEFAULT ''
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS gateway_resource_buckets (
            agent_id TEXT PRIMARY KEY,
            window_started REAL NOT NULL,
            consumed_tokens INTEGER NOT NULL DEFAULT 0,
            reserved_tokens INTEGER NOT NULL DEFAULT 0,
            consumed_cost_usd REAL NOT NULL DEFAULT 0,
            reserved_cost_usd REAL NOT NULL DEFAULT 0,
            in_flight INTEGER NOT NULL DEFAULT 0,
            last_seen REAL NOT NULL,
            updated_at REAL NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS gateway_resource_leases (
            lease_id TEXT PRIMARY KEY,
            agent_id TEXT NOT NULL,
            mode TEXT NOT NULL,
            provider_calls INTEGER NOT NULL,
            estimated_tokens INTEGER NOT NULL,
            estimated_cost_usd REAL NOT NULL,
            acquired_at REAL NOT NULL,
            expires_at REAL NOT NULL,
            status TEXT NOT NULL,
            provider_called INTEGER NOT NULL DEFAULT 0,
            charged_tokens INTEGER NOT NULL DEFAULT 0,
            charged_cost_usd REAL NOT NULL DEFAULT 0,
            settled_at REAL NOT NULL DEFAULT 0
        )
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_gateway_resource_leases_agent_status
        ON gateway_resource_leases (agent_id, status, expires_at)
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS gateway_rate_limit_buckets (
            key_hash TEXT PRIMARY KEY,
            window_started REAL NOT NULL,
            request_count INTEGER NOT NULL DEFAULT 0,
            last_seen REAL NOT NULL,
            updated_at REAL NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_gateway_rate_limit_buckets_last_seen
        ON gateway_rate_limit_buckets (last_seen)
        """
    )


def write_run(result: dict[str, Any], *, append_runtime_event: bool = True) -> None:
    """Persist one run snapshot and its audit rows.

    Server-owned execution uses this function twice.  The pre-execution intent
    persists its audit row and execution claim, but deliberately does not enter
    ``experiment_runs`` or publish a completed ``run`` event.  That table is
    the completed-run source for product metrics; exposing a pending intent
    there would turn an unobserved side effect into a false successful run.
    The final observed result uses the default flag and replaces the same
    durable audit/run identifiers before publishing one ``run`` event.
    """
    # Encode every JSON column before opening the transaction.  This prevents a
    # deep NaN/Infinity in a later audit row from leaving an earlier run row
    # committed when serialization fails.
    serialized_result = encode_json_strict(result, ensure_ascii=False)
    serialized_logs = [encode_json_strict(log, ensure_ascii=False) for log in result["audit_logs"]]
    serialized_runtime_event = encode_json_strict(
        {
            "run_id": result["run_id"],
            "scenario_id": result.get("scenario", {}).get("id", ""),
            "guard_enabled": result.get("guard_enabled", False),
            "attack_success": result.get("attack_success", False),
            "metrics": result.get("metrics", {}),
        },
        ensure_ascii=False,
    )
    with get_connection() as conn:
        _ensure_governance_tables(conn)
        if append_runtime_event:
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
                    serialized_result,
                ),
            )
        for log, serialized_log in zip(result["audit_logs"], serialized_logs, strict=True):
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
                    serialized_log,
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
        if append_runtime_event:
            conn.execute(
                """
                INSERT INTO runtime_events (event_type, created_at, payload)
                VALUES (?, ?, ?)
                """,
                (
                    "run",
                    result["created_at"],
                    serialized_runtime_event,
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
    serialized_payload = encode_json_strict(payload, ensure_ascii=False, sort_keys=True)
    with get_connection() as conn:
        _ensure_governance_tables(conn)
        cursor = conn.execute(
            """
            INSERT INTO runtime_events (event_type, created_at, payload)
            VALUES (?, ?, ?)
            """,
            (event_type, event_created_at, serialized_payload),
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
    bounded_limit = _bounded_limit(limit, default=500)
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
            payload = decode_json_strict(row["payload"])
        except (TypeError, ValueError, json.JSONDecodeError):
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
              AND json_valid(payload)
              AND json_extract(payload, '$.comparison_id') = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (event_type, value),
        ).fetchone()
    if row is None:
        return None
    try:
        payload = decode_json_strict(row["payload"])
    except (TypeError, ValueError, json.JSONDecodeError):
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


def execution_receipts_for_audit_ids(audit_ids: set[str]) -> dict[str, dict[str, Any]]:
    """Load newest receipts for exactly the displayed audit identifiers.

    The generic recent-event window is useful for aggregate metrics, but it is
    not an evidence lookup: unrelated traffic can evict an older receipt from
    that window.  This query follows the audit IDs currently being rendered and
    is split into conservative batches for SQLite's host-parameter limit.
    """
    requested = sorted({str(value) for value in audit_ids if str(value)})
    if not requested:
        return {}
    receipts: dict[str, dict[str, Any]] = {}
    for start in range(0, len(requested), 500):
        batch = requested[start : start + 500]
        placeholders = ", ".join("?" for _ in batch)
        with get_connection() as conn:
            _ensure_governance_tables(conn)
            rows = conn.execute(
                f"""
                SELECT id, created_at, payload
                FROM runtime_events
                WHERE event_type = 'execution-receipt'
                  AND json_valid(payload)
                  AND json_extract(payload, '$.audit_id') IN ({placeholders})
                ORDER BY id DESC
                """,
                tuple(batch),
            ).fetchall()
        for row in rows:
            try:
                payload = decode_json_strict(row["payload"])
            except (TypeError, ValueError, json.JSONDecodeError):
                continue
            if not isinstance(payload, dict):
                continue
            audit_id = str(payload.get("audit_id") or "")
            if audit_id in batch and audit_id not in receipts:
                receipts[audit_id] = {
                    **payload,
                    "event_id": int(row["id"]),
                    "journal_created_at": row["created_at"],
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
              AND json_valid(payload)
              AND json_extract(payload, '$.audit_id') = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (audit_id,),
        ).fetchall()
    for row in rows:
        try:
            payload = decode_json_strict(row["payload"])
        except (TypeError, ValueError, json.JSONDecodeError):
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
    serialized_payload = encode_json_strict(payload, ensure_ascii=False, sort_keys=True)
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
                existing = decode_json_strict(row["payload"])
            except (TypeError, ValueError, json.JSONDecodeError):
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
                serialized_payload,
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


def claim_gateway_execution(
    *,
    audit_id: str,
    claim_id: str,
    agent_id: str,
    session_id: str,
    tool_call_hash: str,
    created_at: str,
) -> dict[str, Any]:
    """Atomically reserve one gateway tool call before executing its side effect.

    The receipt is written after the tool returns, so checking for an existing
    receipt alone leaves a race where two workers execute the same call before
    either worker can persist the receipt.  A durable claim closes that window.
    A claim is deliberately fail-closed: if a worker dies after acquiring it,
    a later request must be inspected/reconciled instead of retrying an
    unknown side effect automatically.
    """
    if not audit_id or not claim_id or not agent_id or not session_id or not tool_call_hash:
        raise ValueError("网关执行占用缺少审计、身份、会话或工具 Hash")
    with get_connection() as conn:
        _ensure_governance_tables(conn)
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            """
            SELECT claim_id, agent_id, session_id, tool_call_hash, status, created_at, completed_at, receipt_id
            FROM gateway_execution_claims
            WHERE audit_id = ?
            """,
            (audit_id,),
        ).fetchone()
        if row is not None:
            existing = dict(row)
            if (
                existing.get("agent_id") == agent_id
                and existing.get("session_id") == session_id
                and existing.get("tool_call_hash") == tool_call_hash
                and existing.get("status") in {"completed", "unknown"}
            ):
                return {"status": str(existing.get("status") or ""), **existing}
            raise ValueError("该网关工具调用已被其他执行请求占用，拒绝重复执行")
        conn.execute(
            """
            INSERT INTO gateway_execution_claims (
                audit_id, claim_id, agent_id, session_id, tool_call_hash,
                status, created_at
            ) VALUES (?, ?, ?, ?, ?, 'running', ?)
            """,
            (audit_id, claim_id, agent_id, session_id, tool_call_hash, created_at),
        )
        return {
            "status": "running",
            "audit_id": audit_id,
            "claim_id": claim_id,
            "agent_id": agent_id,
            "session_id": session_id,
            "tool_call_hash": tool_call_hash,
            "created_at": created_at,
            "completed_at": "",
            "receipt_id": "",
        }


def complete_gateway_execution_claim(
    *,
    audit_id: str,
    claim_id: str,
    receipt_id: str,
    completed_at: str,
) -> None:
    """Mark a previously acquired gateway execution claim as completed."""
    with get_connection() as conn:
        _ensure_governance_tables(conn)
        cursor = conn.execute(
            """
            UPDATE gateway_execution_claims
            SET status = 'completed', completed_at = ?, receipt_id = ?
            WHERE audit_id = ? AND claim_id = ? AND status = 'running'
            """,
            (completed_at, receipt_id, audit_id, claim_id),
        )
        if cursor.rowcount != 1:
            raise ValueError("网关执行占用不存在、已完成或不属于当前请求")


def mark_gateway_execution_claim_unknown(
    *,
    audit_id: str,
    claim_id: str,
    completed_at: str,
) -> bool:
    """Freeze a claim after a side-effect boundary has an uncertain outcome.

    A tool may have changed the outside world before receipt persistence fails.
    Retrying such a claim would be an unsafe duplicate execution, so the claim
    becomes a durable ``unknown`` state that requires operator reconciliation.
    """
    with get_connection() as conn:
        _ensure_governance_tables(conn)
        cursor = conn.execute(
            """
            UPDATE gateway_execution_claims
            SET status = 'unknown', completed_at = ?
            WHERE audit_id = ? AND claim_id = ? AND status = 'running'
            """,
            (completed_at, audit_id, claim_id),
        )
        return cursor.rowcount == 1


def load_gateway_execution_claim(audit_id: str) -> dict[str, Any] | None:
    """Load the durable execution claim for operator reconciliation."""
    if not audit_id:
        return None
    with get_connection() as conn:
        _ensure_governance_tables(conn)
        row = conn.execute(
            """
            SELECT audit_id, claim_id, agent_id, session_id, tool_call_hash,
                   status, created_at, completed_at, receipt_id
            FROM gateway_execution_claims
            WHERE audit_id = ?
            """,
            (audit_id,),
        ).fetchone()
    return dict(row) if row is not None else None


def list_gateway_execution_claims(limit: int = 200) -> list[dict[str, Any]]:
    """Return durable gateway execution states for operator reconciliation."""
    bounded_limit = _bounded_limit(limit, default=200, maximum=1000)
    with get_connection() as conn:
        _ensure_governance_tables(conn)
        rows = conn.execute(
            """
            SELECT audit_id, claim_id, agent_id, session_id, tool_call_hash,
                   status, created_at, completed_at, receipt_id
            FROM gateway_execution_claims
            ORDER BY rowid DESC
            LIMIT ?
            """,
            (bounded_limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def gateway_execution_claims_for_audit_ids(audit_ids: set[str]) -> dict[str, dict[str, Any]]:
    """Load execution claims for exactly the displayed audit identifiers."""
    requested = sorted({str(value) for value in audit_ids if str(value)})
    if not requested:
        return {}
    claims: dict[str, dict[str, Any]] = {}
    for start in range(0, len(requested), 500):
        batch = requested[start : start + 500]
        placeholders = ", ".join("?" for _ in batch)
        with get_connection() as conn:
            _ensure_governance_tables(conn)
            rows = conn.execute(
                f"""
                SELECT audit_id, claim_id, agent_id, session_id, tool_call_hash,
                       status, created_at, completed_at, receipt_id
                FROM gateway_execution_claims
                WHERE audit_id IN ({placeholders})
                """,
                tuple(batch),
            ).fetchall()
        for row in rows:
            item = dict(row)
            audit_id = str(item.get("audit_id") or "")
            if audit_id:
                claims[audit_id] = item
    return claims


def persist_execution_receipt_use(payload: dict[str, Any]) -> dict[str, Any]:
    """Atomically claim one OpenAI proxy tool receipt for one request.

    A verified execution receipt proves that a tool ran, but without a
    consumption record the same result could be replayed in a later request.
    Exact network retries remain idempotent; a different request attempting to
    reuse the same receipt is reported as a conflict.
    """
    event_type = "openai-proxy-tool-receipt-use"
    audit_id = str(payload.get("audit_id") or "")
    request_hash = str(payload.get("request_hash") or "")
    if not audit_id or not request_hash:
        raise ValueError("回执消费记录缺少 audit_id 或 request_hash")
    serialized_payload = encode_json_strict(payload, ensure_ascii=False, sort_keys=True)
    with get_connection() as conn:
        _ensure_governance_tables(conn)
        conn.execute("BEGIN IMMEDIATE")
        rows = conn.execute(
            """
            SELECT id, created_at, payload
            FROM runtime_events
            WHERE event_type = ?
              AND json_valid(payload)
              AND json_extract(payload, '$.audit_id') = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (event_type, audit_id),
        ).fetchall()
        for row in rows:
            try:
                existing = decode_json_strict(row["payload"])
            except (TypeError, ValueError, json.JSONDecodeError):
                continue
            if not isinstance(existing, dict):
                continue
            if (
                str(existing.get("request_hash") or "") == request_hash
                and str(existing.get("agent_id") or "") == str(payload.get("agent_id") or "")
                and str(existing.get("session_id") or "") == str(payload.get("session_id") or "")
            ):
                return {
                    "event_id": int(row["id"]),
                    "event_type": event_type,
                    "created_at": row["created_at"],
                    "payload": existing,
                    "idempotent": True,
                    "conflict": False,
                }
            return {
                "event_id": int(row["id"]),
                "event_type": event_type,
                "created_at": row["created_at"],
                "payload": existing,
                "idempotent": False,
                "conflict": True,
            }

        created_at = str(payload.get("created_at") or datetime.now(timezone.utc).isoformat())
        cursor = conn.execute(
            """
            INSERT INTO runtime_events (event_type, created_at, payload)
            VALUES (?, ?, ?)
            """,
            (event_type, created_at, serialized_payload),
        )
        return {
            "event_id": int(cursor.lastrowid or 0),
            "event_type": event_type,
            "created_at": created_at,
            "payload": payload,
            "idempotent": False,
            "conflict": False,
        }


def enrich_audit_logs_with_execution_receipts(logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Add receipt state to response copies without mutating the hashed audit log."""
    audit_ids = {str(log.get("id") or "") for log in logs if log.get("id")}
    receipts = execution_receipts_for_audit_ids(audit_ids)
    claims = gateway_execution_claims_for_audit_ids(audit_ids)
    enriched: list[dict[str, Any]] = []
    for log in logs:
        copy = dict(log)
        audit_id = str(log.get("id", ""))
        receipt = receipts.get(audit_id)
        claim = claims.get(audit_id)
        copy["execution_receipt"] = receipt
        if claim and str(claim.get("status") or "") == "unknown":
            # An uncertain execution claim means the side effect may already
            # have happened even when a receipt row exists.  Reconciliation
            # status therefore takes precedence over the apparent receipt so
            # operators do not treat the call as safely retryable.
            copy["execution_status"] = "unknown"
            copy["execution_target"] = str(log.get("execution_target") or "unknown")
            copy["gateway_execution_claim_status"] = "unknown"
        elif receipt:
            copy["execution_status"] = str(receipt.get("status"))
            copy["execution_target"] = str(receipt.get("execution_target"))
        elif str(log.get("execution_status") or "") in {"pending", "unknown", "failed"}:
            # MCP intent records are deliberately visible until a result record
            # proves what happened. Do not collapse them into ``not_applicable``
            # merely because they have no generic execution receipt.
            copy["execution_status"] = str(log.get("execution_status"))
            copy["execution_target"] = str(log.get("execution_target") or "mcp-upstream")
        elif log.get("execution_receipt_expected"):
            copy["execution_status"] = "awaiting_receipt"
            copy["execution_target"] = "unknown"
        elif isinstance(log.get("tool_output"), dict) and log["tool_output"].get("executed"):
            copy["execution_status"] = "server_runtime_completed"
            copy["execution_target"] = "local-runtime"
        else:
            copy["execution_status"] = "not_applicable"
            copy["execution_target"] = "none"
        enriched.append(copy)
    return enriched


def latest_runs(limit: int = 20) -> list[dict[str, Any]]:
    bounded_limit = _bounded_limit(limit, default=20)
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT payload FROM experiment_runs ORDER BY created_at DESC LIMIT ?",
            (bounded_limit,),
        ).fetchall()
    return [payload for row in rows if (payload := _decode_json_object(row["payload"])) is not None]


def load_run(run_id: str) -> dict[str, Any] | None:
    with get_connection() as conn:
        row = conn.execute("SELECT payload FROM experiment_runs WHERE id = ?", (run_id,)).fetchone()
    return _decode_json_object(row["payload"]) if row else None


def latest_audit_logs(limit: int = 100) -> list[dict[str, Any]]:
    bounded_limit = _bounded_limit(limit, default=100)
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT payload FROM audit_logs ORDER BY rowid DESC LIMIT ?",
            (bounded_limit,),
        ).fetchall()
    logs = [payload for row in rows if (payload := _decode_json_object(row["payload"])) is not None]
    return enrich_audit_logs_with_execution_receipts(logs)


def load_audit_log(audit_id: str) -> dict[str, Any] | None:
    """Load the original immutable audit payload without response enrichment."""
    with get_connection() as conn:
        row = conn.execute("SELECT payload FROM audit_logs WHERE id = ?", (audit_id,)).fetchone()
    return _decode_json_object(row["payload"]) if row else None


def load_gateway_request_audit_logs(
    request_id: str,
    *,
    agent_id: str = "",
    session_id: str = "",
) -> list[dict[str, Any]]:
    """Load all Provider-stage audits belonging to one gateway request.

    A single Provider response may contain several parallel tool calls, including
    a malformed or output-blocked sibling that has no ``provider_call_id``.  The
    gateway decides that response atomically, so a later execution request must
    see every Provider-stage audit before executing one immutable audit record.
    Filtering only rows with a call id would let a caller replay an allowed
    sibling after the malformed/blocked sibling had been omitted from the
    all-or-nothing check.
    """

    normalized_request_id = str(request_id or "").strip()
    if not normalized_request_id:
        return []
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT payload
            FROM audit_logs
            WHERE json_valid(payload)
              AND json_extract(payload, '$.source_app') = ?
              AND json_extract(payload, '$.stage_context.request_id') = ?
            ORDER BY rowid ASC
            """,
            ("openai-compatible-proxy", normalized_request_id),
        ).fetchall()

    result: list[dict[str, Any]] = []
    for row in rows:
        try:
            payload = decode_json_strict(row["payload"])
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
        if not isinstance(payload, dict):
            continue
        if agent_id and str(payload.get("agent_id") or "") != str(agent_id):
            continue
        stage_context = payload.get("stage_context")
        if not isinstance(stage_context, dict):
            continue
        if session_id and str(stage_context.get("session_id") or "") != str(session_id):
            continue
        if stage_context.get("provider_called") is not True:
            continue
        result.append(payload)
    return enrich_audit_logs_with_execution_receipts(result)


def latest_gateway_audit_logs(
    limit: int = 2000,
    *,
    agent_id: str = "",
    session_id: str = "",
) -> list[dict[str, Any]]:
    """Load recent audit rows produced by the OpenAI-compatible gateway.

    Gateway traces must not depend on the generic ``latest_audit_logs`` window:
    a busy experiment run can otherwise evict the request/response evidence
    before the operator opens the gateway page.  The SQL predicate keeps the
    query focused on the gateway source, while the identity/session filters are
    applied again after JSON decoding so malformed or stale rows cannot widen a
    caller's view.
    """

    bounded_limit = _bounded_limit(limit, default=2000)
    normalized_agent_id = str(agent_id or "")
    normalized_session_id = str(session_id or "")
    predicates = [
        "json_valid(payload)",
        "json_extract(payload, '$.source_app') = ?",
    ]
    parameters: list[Any] = ["openai-compatible-proxy"]
    if normalized_agent_id:
        predicates.append("json_extract(payload, '$.agent_id') = ?")
        parameters.append(normalized_agent_id)
    if normalized_session_id:
        predicates.append("json_extract(payload, '$.stage_context.session_id') = ?")
        parameters.append(normalized_session_id)
    parameters.append(bounded_limit)
    with get_connection() as conn:
        rows = conn.execute(
            f"""
            SELECT payload
            FROM audit_logs
            WHERE {" AND ".join(predicates)}
            ORDER BY rowid DESC
            LIMIT ?
            """,
            tuple(parameters),
        ).fetchall()

    result: list[dict[str, Any]] = []
    for row in rows:
        try:
            payload = decode_json_strict(row["payload"])
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
        if not isinstance(payload, dict):
            continue
        if normalized_agent_id and str(payload.get("agent_id") or "") != normalized_agent_id:
            continue
        stage_context = payload.get("stage_context")
        if not isinstance(stage_context, dict):
            continue
        if normalized_session_id and str(stage_context.get("session_id") or "") != normalized_session_id:
            continue
        if not str(stage_context.get("request_id") or "").strip():
            continue
        result.append(payload)
    return result


def load_gateway_request_audit_events(
    request_id: str,
    *,
    agent_id: str = "",
    session_id: str = "",
) -> list[dict[str, Any]]:
    """Load every gateway audit stage for one request, including plain text.

    ``load_gateway_request_audit_logs`` intentionally returns only Provider
    tool-call siblings for execution.  Operator traces need the broader set:
    pre-provider blocks, provider failures, text responses and post-provider
    tool decisions all belong to the same request timeline.
    """

    normalized_request_id = str(request_id or "").strip()
    if not normalized_request_id:
        return []
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT payload
            FROM audit_logs
            WHERE json_valid(payload)
              AND json_extract(payload, '$.source_app') = ?
              AND json_extract(payload, '$.stage_context.request_id') = ?
            ORDER BY rowid ASC
            """,
            ("openai-compatible-proxy", normalized_request_id),
        ).fetchall()

    result: list[dict[str, Any]] = []
    normalized_agent_id = str(agent_id or "")
    normalized_session_id = str(session_id or "")
    for row in rows:
        try:
            payload = decode_json_strict(row["payload"])
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
        if not isinstance(payload, dict):
            continue
        if normalized_agent_id and str(payload.get("agent_id") or "") != normalized_agent_id:
            continue
        stage_context = payload.get("stage_context")
        if not isinstance(stage_context, dict):
            continue
        if str(stage_context.get("request_id") or "") != normalized_request_id:
            continue
        if normalized_session_id and str(stage_context.get("session_id") or "") != normalized_session_id:
            continue
        result.append(payload)
    return enrich_audit_logs_with_execution_receipts(result)


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
            WHERE json_valid(payload)
              AND json_extract(payload, '$.conversation_id') IN ({placeholders})
            """,
            tuple(requested),
        ).fetchall()
    return [payload for row in rows if (payload := _decode_json_object(row["payload"])) is not None]


def record_policy_version(
    *,
    policy_id: str,
    before: dict[str, Any],
    after: dict[str, Any],
    operator: str = "security-admin",
    comment: str = "",
    operation_id: str = "",
) -> dict[str, Any]:
    created_at = datetime.now(timezone.utc).isoformat()
    serialized_before = encode_json_strict(before, ensure_ascii=False)
    serialized_after = encode_json_strict(after, ensure_ascii=False)
    with get_connection() as conn:
        _ensure_governance_tables(conn)
        if operation_id:
            existing = conn.execute(
                "SELECT id, created_at FROM policy_versions WHERE operation_id = ?", (operation_id,)
            ).fetchone()
            if existing is not None:
                return {
                    "id": existing["id"],
                    "policy_id": policy_id,
                    "operator": operator or "security-admin",
                    "comment": comment,
                    "created_at": existing["created_at"],
                    "before": before,
                    "after": after,
                    "operation_id": operation_id,
                }
        cursor = conn.execute(
            """
            INSERT INTO policy_versions (
                policy_id, operator, comment, created_at, before_payload, after_payload, operation_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                policy_id,
                operator or "security-admin",
                comment,
                created_at,
                serialized_before,
                serialized_after,
                operation_id,
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
        "operation_id": operation_id,
    }


def list_policy_versions(policy_id: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
    bounded_limit = _bounded_limit(limit, default=100)
    query = """
        SELECT id, policy_id, operator, comment, created_at, before_payload, after_payload
        FROM policy_versions
    """
    params: tuple[Any, ...]
    if policy_id:
        query += " WHERE policy_id = ?"
        params = (policy_id, bounded_limit)
    else:
        params = (bounded_limit,)
    query += " ORDER BY id DESC LIMIT ?"
    with get_connection() as conn:
        _ensure_governance_tables(conn)
        rows = conn.execute(query, params).fetchall()
    versions: list[dict[str, Any]] = []
    for row in rows:
        before = _decode_json_object(row["before_payload"])
        after = _decode_json_object(row["after_payload"])
        if before is None or after is None:
            continue
        versions.append(
            {
                "id": row["id"],
                "policy_id": row["policy_id"],
                "operator": row["operator"],
                "comment": row["comment"],
                "created_at": row["created_at"],
                "before": before,
                "after": after,
            }
        )
    return versions


def runtime_metrics_snapshot(limit: Any = 500) -> dict[str, Any]:
    bounded_limit = _bounded_limit(limit, default=500)
    runs = latest_runs(bounded_limit)
    audit_logs = latest_audit_logs(bounded_limit)
    with get_connection() as conn:
        _ensure_governance_tables(conn)
        review_rows = conn.execute(
            "SELECT status, risk_level, reviewed_at FROM approval_reviews ORDER BY rowid DESC LIMIT ?",
            (bounded_limit,),
        ).fetchall()
        policy_version_count = conn.execute("SELECT COUNT(*) AS count FROM policy_versions").fetchone()["count"]
    # Metrics must describe the same bounded audit window shown to the caller.
    # Resolve those audit IDs exactly instead of widening a generic recent-event
    # scan to 500, which both violated small limits and could still miss an old
    # receipt after unrelated traffic.
    audit_ids = {str(log.get("id") or "") for log in audit_logs if log.get("id")}
    receipt_map = execution_receipts_for_audit_ids(audit_ids)
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
        "window": {"run_limit": bounded_limit, "audit_limit": bounded_limit},
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
