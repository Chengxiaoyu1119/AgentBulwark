"""Shared per-Agent resource leases for the OpenAI-compatible gateway.

The gateway reserves the worst-case Provider work before a request starts and
settles it with the usage reported by the Provider.  Reservation state lives
in the gateway SQLite database, so the check-and-reserve operation remains
atomic when several API workers handle the same Agent concurrently.  Expiry
timestamps release reservations left behind by a crashed worker.
"""

from __future__ import annotations

import json
import math
import os
from dataclasses import dataclass
from time import time
from typing import Any
from uuid import uuid4

from apps.api.agent_supervisor.storage.database import _ensure_governance_tables, get_connection

RESOURCE_ENABLED_ENV = "AGENT_SUPERVISOR_PROXY_RESOURCE_GOVERNANCE_ENABLED"
RESOURCE_CONCURRENCY_ENV = "AGENT_SUPERVISOR_PROXY_MAX_CONCURRENCY_PER_AGENT"
RESOURCE_TOKEN_BUDGET_ENV = "AGENT_SUPERVISOR_PROXY_TOKEN_BUDGET_PER_MINUTE"
RESOURCE_COST_BUDGET_ENV = "AGENT_SUPERVISOR_PROXY_COST_BUDGET_PER_MINUTE_USD"
RESOURCE_DEFAULT_OUTPUT_ENV = "AGENT_SUPERVISOR_PROXY_DEFAULT_OUTPUT_TOKENS"
RESOURCE_MANAGED_CONTEXT_ENV = "AGENT_SUPERVISOR_PROXY_MANAGED_CONTEXT_TOKENS"
RESOURCE_MAX_KEYS_ENV = "AGENT_SUPERVISOR_PROXY_RESOURCE_MAX_KEYS"
RESOURCE_INPUT_PRICE_ENV = "AGENT_SUPERVISOR_PROXY_INPUT_COST_PER_1K_USD"
RESOURCE_OUTPUT_PRICE_ENV = "AGENT_SUPERVISOR_PROXY_OUTPUT_COST_PER_1K_USD"
RESOURCE_LEASE_TTL_ENV = "AGENT_SUPERVISOR_PROXY_RESOURCE_LEASE_TTL_SECONDS"

_WINDOW_SECONDS = 60.0
_DEFAULT_CONCURRENCY = 8
_DEFAULT_TOKEN_BUDGET = 1_000_000
_DEFAULT_OUTPUT_TOKENS = 1_024
_DEFAULT_MANAGED_CONTEXT_TOKENS = 16_384
_DEFAULT_LEASE_TTL_SECONDS = 300.0
_MAX_CONCURRENCY = 1_000
_MAX_TOKEN_BUDGET = 10_000_000
_MAX_OUTPUT_TOKENS = 64_000
_MAX_LEASE_TTL_SECONDS = 3_600.0
_DEFAULT_MAX_KEYS = 10_000
_RESOURCE_SCOPE = "sqlite-shared"


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int, *, minimum: int = 0, maximum: int = 10_000_000) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, value))


def _env_float(
    name: str,
    default: float,
    *,
    minimum: float = 0.0,
    maximum: float = 1_000_000.0,
) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return default
    if not math.isfinite(value):
        return default
    return max(minimum, min(maximum, value))


def resource_governance_enabled() -> bool:
    return _env_bool(RESOURCE_ENABLED_ENV, True)


def _lease_ttl_seconds() -> float:
    return _env_float(
        RESOURCE_LEASE_TTL_ENV,
        _DEFAULT_LEASE_TTL_SECONDS,
        minimum=10.0,
        maximum=_MAX_LEASE_TTL_SECONDS,
    )


def _configured_limits(*, tracked_agent_count: int | None = None) -> dict[str, Any]:
    enabled = resource_governance_enabled()
    return {
        "enabled": enabled,
        "scope": _RESOURCE_SCOPE if enabled else "disabled",
        "concurrency_per_agent": _env_int(
            RESOURCE_CONCURRENCY_ENV,
            _DEFAULT_CONCURRENCY,
            minimum=0,
            maximum=_MAX_CONCURRENCY,
        ),
        "token_budget_per_minute": _env_int(
            RESOURCE_TOKEN_BUDGET_ENV,
            _DEFAULT_TOKEN_BUDGET,
            minimum=0,
            maximum=_MAX_TOKEN_BUDGET,
        ),
        "cost_budget_per_minute_usd": _env_float(RESOURCE_COST_BUDGET_ENV, 0.0, maximum=1_000_000.0),
        "input_cost_per_1k_usd": _env_float(RESOURCE_INPUT_PRICE_ENV, 0.0, maximum=1_000_000.0),
        "output_cost_per_1k_usd": _env_float(RESOURCE_OUTPUT_PRICE_ENV, 0.0, maximum=1_000_000.0),
        "default_output_tokens": _env_int(
            RESOURCE_DEFAULT_OUTPUT_ENV,
            _DEFAULT_OUTPUT_TOKENS,
            minimum=1,
            maximum=_MAX_OUTPUT_TOKENS,
        ),
        "managed_context_tokens": _env_int(
            RESOURCE_MANAGED_CONTEXT_ENV,
            _DEFAULT_MANAGED_CONTEXT_TOKENS,
            minimum=1,
            maximum=60_000,
        ),
        "lease_ttl_seconds": _lease_ttl_seconds(),
        "tracked_agent_count": tracked_agent_count if tracked_agent_count is not None else _tracked_agent_count(),
    }


def resource_limits() -> dict[str, Any]:
    """Return effective, non-secret resource policy for status/evidence."""

    return _configured_limits()


@dataclass(frozen=True)
class ResourcePlan:
    """Worst-case reservation calculated before a Provider call."""

    agent_id: str
    mode: str
    provider_calls: int
    completions: int
    prompt_tokens_per_call: int
    output_tokens_per_completion: int
    estimated_tokens: int
    estimated_cost_usd: float


class ProxyResourceLimitError(ValueError):
    """A request rejected before a Provider call because a resource is exhausted."""

    def __init__(
        self,
        message: str,
        *,
        resource: str,
        agent_id: str,
        limit: int | float,
        retry_after_seconds: int = 60,
        plan: ResourcePlan | None = None,
        snapshot: dict[str, Any] | None = None,
        audit_id: str = "",
    ) -> None:
        super().__init__(message)
        self.resource = resource
        self.agent_id = agent_id
        self.limit = limit
        self.retry_after_seconds = retry_after_seconds
        self.plan = plan
        self.snapshot = snapshot or {}
        self.audit_id = audit_id

    def as_detail(self) -> dict[str, Any]:
        plan = self.plan
        return {
            "message": str(self),
            "resource": self.resource,
            "agent_id": self.agent_id,
            "limit": self.limit,
            "retry_after_seconds": self.retry_after_seconds,
            "provider_called": False,
            "audit_id": self.audit_id,
            "resource_plan": {
                "mode": plan.mode,
                "provider_calls": plan.provider_calls,
                "completions": plan.completions,
                "estimated_tokens": plan.estimated_tokens,
                "estimated_cost_usd": plan.estimated_cost_usd,
            }
            if plan
            else {},
            "resource_snapshot": self.snapshot,
        }


def _normalized_agent_id(agent_id: str) -> str:
    value = str(agent_id or "").strip()
    return value[:160] or "shared-agent"


def _tracked_agent_count() -> int:
    with get_connection() as conn:
        _ensure_governance_tables(conn)
        row = conn.execute("SELECT COUNT(*) AS count FROM gateway_resource_buckets").fetchone()
    return int(row["count"] if row is not None else 0)


def _ensure_bucket(conn: Any, agent_id: str, now: float) -> Any:
    conn.execute(
        """
        INSERT OR IGNORE INTO gateway_resource_buckets (
            agent_id, window_started, consumed_tokens, reserved_tokens,
            consumed_cost_usd, reserved_cost_usd, in_flight, last_seen, updated_at
        ) VALUES (?, ?, 0, 0, 0, 0, 0, ?, ?)
        """,
        (agent_id, now, now, now),
    )
    row = conn.execute(
        """
        SELECT agent_id, window_started, consumed_tokens, reserved_tokens,
               consumed_cost_usd, reserved_cost_usd, in_flight, last_seen
        FROM gateway_resource_buckets WHERE agent_id = ?
        """,
        (agent_id,),
    ).fetchone()
    if row is None:
        raise RuntimeError("资源租约桶创建失败")
    return row


def _reset_bucket_window(conn: Any, row: Any, now: float) -> Any:
    # Active reservations may span a minute boundary. Reset measured usage but
    # keep reserved capacity protected until each lease settles.
    if now - float(row["window_started"]) < _WINDOW_SECONDS:
        return row
    conn.execute(
        """
        UPDATE gateway_resource_buckets
        SET window_started = ?, consumed_tokens = 0,
            consumed_cost_usd = 0, updated_at = ?
        WHERE agent_id = ?
        """,
        (now, now, str(row["agent_id"])),
    )
    return _ensure_bucket(conn, str(row["agent_id"]), now)


def _cleanup_expired_leases(conn: Any, now: float, *, agent_id: str | None = None) -> int:
    query = """
        SELECT lease_id, agent_id, estimated_tokens, estimated_cost_usd
        FROM gateway_resource_leases
        WHERE status = 'active' AND expires_at <= ?
    """
    params: list[Any] = [now]
    if agent_id:
        query += " AND agent_id = ?"
        params.append(agent_id)
    rows = conn.execute(query, tuple(params)).fetchall()
    for row in rows:
        bucket = _reset_bucket_window(conn, _ensure_bucket(conn, str(row["agent_id"]), now), now)
        conn.execute(
            """
            UPDATE gateway_resource_buckets
            SET in_flight = MAX(in_flight - 1, 0),
                reserved_tokens = MAX(reserved_tokens - ?, 0),
                reserved_cost_usd = MAX(reserved_cost_usd - ?, 0),
                last_seen = ?, updated_at = ?
            WHERE agent_id = ?
            """,
            (
                int(row["estimated_tokens"]),
                float(row["estimated_cost_usd"]),
                now,
                now,
                str(bucket["agent_id"]),
            ),
        )
        conn.execute(
            """
            UPDATE gateway_resource_leases
            SET status = 'expired', settled_at = ?
            WHERE lease_id = ? AND status = 'active'
            """,
            (now, str(row["lease_id"])),
        )
    return len(rows)


def _prune_buckets(conn: Any) -> None:
    max_keys = _env_int(RESOURCE_MAX_KEYS_ENV, _DEFAULT_MAX_KEYS, minimum=100, maximum=100_000)
    row = conn.execute("SELECT COUNT(*) AS count FROM gateway_resource_buckets").fetchone()
    count = int(row["count"] if row is not None else 0)
    if count <= max_keys:
        return
    stale = conn.execute(
        """
        SELECT agent_id FROM gateway_resource_buckets
        WHERE in_flight = 0 AND reserved_tokens = 0 AND reserved_cost_usd = 0
        ORDER BY last_seen ASC LIMIT ?
        """,
        (count - max_keys,),
    ).fetchall()
    for row in stale:
        conn.execute("DELETE FROM gateway_resource_buckets WHERE agent_id = ?", (str(row["agent_id"]),))


def _snapshot_from_row(
    conn: Any,
    row: Any | None,
    agent_id: str,
    *,
    tracked_agent_count: int | None = None,
) -> dict[str, Any]:
    if tracked_agent_count is None:
        count_row = conn.execute("SELECT COUNT(*) AS count FROM gateway_resource_buckets").fetchone()
        tracked_agent_count = int(count_row["count"] if count_row is not None else 0)
    limits = _configured_limits(tracked_agent_count=tracked_agent_count)
    limits.update(
        {
            "agent_id": agent_id,
            "in_flight": int(row["in_flight"]) if row is not None else 0,
            "consumed_tokens": int(row["consumed_tokens"]) if row is not None else 0,
            "reserved_tokens": int(row["reserved_tokens"]) if row is not None else 0,
            "consumed_cost_usd": round(float(row["consumed_cost_usd"]) if row is not None else 0.0, 8),
            "reserved_cost_usd": round(float(row["reserved_cost_usd"]) if row is not None else 0.0, 8),
        }
    )
    return limits


def reset_resource_governance() -> None:
    """Clear shared leases and buckets; used by deterministic tests and resets."""

    with get_connection() as conn:
        _ensure_governance_tables(conn)
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("DELETE FROM gateway_resource_leases")
        conn.execute("DELETE FROM gateway_resource_buckets")


def estimate_request_plan(
    payload: dict[str, Any],
    *,
    agent_id: str,
    mode: str = "transparent",
    managed_rounds: int = 0,
) -> ResourcePlan:
    """Estimate finite Provider work implied by an OpenAI-shaped request."""

    messages = payload.get("messages", [])
    tools = payload.get("tools", [])
    serialized_messages = json.dumps(messages, ensure_ascii=False, default=str, separators=(",", ":"))
    serialized_tools = json.dumps(tools, ensure_ascii=False, default=str, separators=(",", ":")) if tools else ""
    prompt_tokens = max(1, math.ceil((len(serialized_messages) + len(serialized_tools)) / 4))
    completions_raw = payload.get("n", 1)
    completions = completions_raw if isinstance(completions_raw, int) and not isinstance(completions_raw, bool) else 1
    completions = max(1, completions)
    output_value = payload.get("max_tokens")
    if output_value is None:
        output_value = payload.get("max_completion_tokens")
    if output_value is None:
        output_value = payload.get("max_output_tokens")
    if not isinstance(output_value, int) or isinstance(output_value, bool) or output_value < 1:
        output_value = _env_int(
            RESOURCE_DEFAULT_OUTPUT_ENV,
            _DEFAULT_OUTPUT_TOKENS,
            minimum=1,
            maximum=_MAX_OUTPUT_TOKENS,
        )
    if mode == "managed":
        provider_calls = max(1, managed_rounds + 1)
        prompt_tokens = max(
            prompt_tokens,
            _env_int(RESOURCE_MANAGED_CONTEXT_ENV, _DEFAULT_MANAGED_CONTEXT_TOKENS, minimum=1, maximum=60_000),
        )
    elif mode == "research":
        provider_calls = 4
    else:
        provider_calls = 1
    estimated_tokens = provider_calls * (prompt_tokens + output_value * completions)
    input_price = _env_float(RESOURCE_INPUT_PRICE_ENV, 0.0, maximum=1_000_000.0)
    output_price = _env_float(RESOURCE_OUTPUT_PRICE_ENV, 0.0, maximum=1_000_000.0)
    estimated_cost = (
        provider_calls * prompt_tokens * input_price / 1000.0
        + provider_calls * output_value * completions * output_price / 1000.0
    )
    return ResourcePlan(
        agent_id=_normalized_agent_id(agent_id),
        mode=mode if mode in {"managed", "research"} else "transparent",
        provider_calls=provider_calls,
        completions=completions,
        prompt_tokens_per_call=prompt_tokens,
        output_tokens_per_completion=output_value,
        estimated_tokens=estimated_tokens,
        estimated_cost_usd=round(estimated_cost, 8),
    )


def _settlement_charge(
    plan: ResourcePlan,
    *,
    actual_tokens: int | None,
    actual_cost_usd: float | None,
    provider_called: bool,
) -> tuple[int, float]:
    if not provider_called:
        return 0, 0.0
    if actual_tokens is None:
        return plan.estimated_tokens, plan.estimated_cost_usd
    charged_tokens = max(0, int(actual_tokens))
    if actual_cost_usd is not None and math.isfinite(float(actual_cost_usd)):
        charged_cost = max(0.0, float(actual_cost_usd))
    else:
        average_price = plan.estimated_cost_usd / max(1, plan.estimated_tokens)
        charged_cost = charged_tokens * average_price
    return charged_tokens, charged_cost


@dataclass
class ResourceLease:
    agent_id: str
    plan: ResourcePlan
    concurrency_limit: int
    token_budget: int
    cost_budget_usd: float
    acquired_at: float
    lease_id: str = ""
    scope: str = _RESOURCE_SCOPE
    _released: bool = False

    def settle(
        self,
        *,
        actual_tokens: int | None,
        actual_cost_usd: float | None = None,
        provider_called: bool = True,
    ) -> dict[str, Any]:
        """Release the lease and charge observed usage exactly once."""

        if self._released:
            return {"settled": False, "agent_id": self.agent_id, "reason": "already-settled", "scope": self.scope}
        self._released = True
        charged_tokens, charged_cost = _settlement_charge(
            self.plan,
            actual_tokens=actual_tokens,
            actual_cost_usd=actual_cost_usd,
            provider_called=provider_called,
        )
        if not self.lease_id:
            return {
                "settled": True,
                "agent_id": self.agent_id,
                "provider_called": provider_called,
                "estimated_tokens": self.plan.estimated_tokens,
                "charged_tokens": charged_tokens,
                "estimated_cost_usd": self.plan.estimated_cost_usd,
                "charged_cost_usd": round(charged_cost, 8),
                "provider_calls_reserved": self.plan.provider_calls,
                "mode": self.plan.mode,
                "scope": self.scope,
            }

        now = time()
        final_status = "settled"
        with get_connection() as conn:
            _ensure_governance_tables(conn)
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                """
                SELECT status, agent_id, estimated_tokens, estimated_cost_usd
                FROM gateway_resource_leases WHERE lease_id = ?
                """,
                (self.lease_id,),
            ).fetchone()
            if row is None:
                return {"settled": False, "agent_id": self.agent_id, "reason": "lease-not-found", "scope": self.scope}
            status = str(row["status"] or "")
            if status in {"settled", "settled-late"}:
                return {"settled": False, "agent_id": self.agent_id, "reason": "already-settled", "scope": self.scope}
            bucket = _reset_bucket_window(conn, _ensure_bucket(conn, str(row["agent_id"]), now), now)
            if status == "active":
                conn.execute(
                    """
                    UPDATE gateway_resource_buckets
                    SET in_flight = MAX(in_flight - 1, 0),
                        reserved_tokens = MAX(reserved_tokens - ?, 0),
                        reserved_cost_usd = MAX(reserved_cost_usd - ?, 0),
                        consumed_tokens = consumed_tokens + ?,
                        consumed_cost_usd = consumed_cost_usd + ?,
                        last_seen = ?, updated_at = ?
                    WHERE agent_id = ?
                    """,
                    (
                        int(row["estimated_tokens"]),
                        float(row["estimated_cost_usd"]),
                        charged_tokens,
                        charged_cost,
                        now,
                        now,
                        str(bucket["agent_id"]),
                    ),
                )
            else:
                # Expiry already released the reservation. A late Provider
                # response may be charged but cannot decrement another lease.
                final_status = "settled-late"
                conn.execute(
                    """
                    UPDATE gateway_resource_buckets
                    SET consumed_tokens = consumed_tokens + ?,
                        consumed_cost_usd = consumed_cost_usd + ?,
                        last_seen = ?, updated_at = ?
                    WHERE agent_id = ?
                    """,
                    (charged_tokens, charged_cost, now, now, str(bucket["agent_id"])),
                )
            conn.execute(
                """
                UPDATE gateway_resource_leases
                SET status = ?, provider_called = ?, charged_tokens = ?,
                    charged_cost_usd = ?, settled_at = ?
                WHERE lease_id = ?
                """,
                (final_status, int(provider_called), charged_tokens, charged_cost, now, self.lease_id),
            )
        return {
            "settled": True,
            "agent_id": self.agent_id,
            "provider_called": provider_called,
            "estimated_tokens": self.plan.estimated_tokens,
            "charged_tokens": charged_tokens,
            "estimated_cost_usd": self.plan.estimated_cost_usd,
            "charged_cost_usd": round(charged_cost, 8),
            "provider_calls_reserved": self.plan.provider_calls,
            "mode": self.plan.mode,
            "scope": self.scope,
            "lease_id": self.lease_id,
            "lease_status": final_status,
        }

    def __enter__(self) -> "ResourceLease":
        return self

    def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> None:
        if not self._released:
            self.settle(actual_tokens=None, provider_called=exc_type is not None)


def acquire_resource_lease(plan: ResourcePlan) -> ResourceLease:
    """Reserve concurrency, token budget and optional cost budget atomically."""

    if not resource_governance_enabled():
        return ResourceLease(
            agent_id=plan.agent_id,
            plan=plan,
            concurrency_limit=0,
            token_budget=0,
            cost_budget_usd=0.0,
            acquired_at=time(),
            scope="disabled",
        )

    concurrency_limit = _env_int(
        RESOURCE_CONCURRENCY_ENV,
        _DEFAULT_CONCURRENCY,
        minimum=0,
        maximum=_MAX_CONCURRENCY,
    )
    token_budget = _env_int(
        RESOURCE_TOKEN_BUDGET_ENV,
        _DEFAULT_TOKEN_BUDGET,
        minimum=0,
        maximum=_MAX_TOKEN_BUDGET,
    )
    cost_budget = _env_float(RESOURCE_COST_BUDGET_ENV, 0.0, maximum=1_000_000.0)
    now = time()
    lease_id = uuid4().hex
    with get_connection() as conn:
        _ensure_governance_tables(conn)
        conn.execute("BEGIN IMMEDIATE")
        _cleanup_expired_leases(conn, now, agent_id=plan.agent_id)
        _prune_buckets(conn)
        bucket = _reset_bucket_window(conn, _ensure_bucket(conn, plan.agent_id, now), now)
        snapshot = _snapshot_from_row(conn, bucket, plan.agent_id)
        in_flight = int(bucket["in_flight"])
        consumed_tokens = int(bucket["consumed_tokens"])
        reserved_tokens = int(bucket["reserved_tokens"])
        consumed_cost = float(bucket["consumed_cost_usd"])
        reserved_cost = float(bucket["reserved_cost_usd"])
        if concurrency_limit > 0 and in_flight >= concurrency_limit:
            raise ProxyResourceLimitError(
                f"Agent `{plan.agent_id}` 已达到并发上限，请稍后重试。",
                resource="concurrency",
                agent_id=plan.agent_id,
                limit=concurrency_limit,
                plan=plan,
                snapshot=snapshot,
            )
        if token_budget > 0 and consumed_tokens + reserved_tokens + plan.estimated_tokens > token_budget:
            raise ProxyResourceLimitError(
                f"Agent `{plan.agent_id}` 的每分钟 Token 预算不足，已拒绝本次 Provider 请求。",
                resource="token-budget",
                agent_id=plan.agent_id,
                limit=token_budget,
                plan=plan,
                snapshot=snapshot,
            )
        if cost_budget > 0 and consumed_cost + reserved_cost + plan.estimated_cost_usd > cost_budget:
            raise ProxyResourceLimitError(
                f"Agent `{plan.agent_id}` 的每分钟成本预算不足，已拒绝本次 Provider 请求。",
                resource="cost-budget",
                agent_id=plan.agent_id,
                limit=cost_budget,
                plan=plan,
                snapshot=snapshot,
            )
        if cost_budget > 0 and plan.estimated_cost_usd <= 0:
            raise ProxyResourceLimitError(
                "已配置成本预算，但未配置输入/输出 Token 单价，拒绝在无法计费的状态下调用 Provider。",
                resource="cost-pricing",
                agent_id=plan.agent_id,
                limit=cost_budget,
                plan=plan,
                snapshot=snapshot,
            )
        expires_at = now + _lease_ttl_seconds()
        conn.execute(
            """
            INSERT INTO gateway_resource_leases (
                lease_id, agent_id, mode, provider_calls, estimated_tokens,
                estimated_cost_usd, acquired_at, expires_at, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active')
            """,
            (
                lease_id,
                plan.agent_id,
                plan.mode,
                plan.provider_calls,
                plan.estimated_tokens,
                plan.estimated_cost_usd,
                now,
                expires_at,
            ),
        )
        conn.execute(
            """
            UPDATE gateway_resource_buckets
            SET in_flight = in_flight + 1,
                reserved_tokens = reserved_tokens + ?,
                reserved_cost_usd = reserved_cost_usd + ?,
                last_seen = ?, updated_at = ?
            WHERE agent_id = ?
            """,
            (plan.estimated_tokens, plan.estimated_cost_usd, now, now, plan.agent_id),
        )
    return ResourceLease(
        agent_id=plan.agent_id,
        plan=plan,
        concurrency_limit=concurrency_limit,
        token_budget=token_budget,
        cost_budget_usd=cost_budget,
        acquired_at=now,
        lease_id=lease_id,
        scope=_RESOURCE_SCOPE,
    )


def resource_snapshot(agent_id: str = "") -> dict[str, Any]:
    """Return current counters without exposing request content or credentials."""

    key = _normalized_agent_id(agent_id) if agent_id else ""
    now = time()
    with get_connection() as conn:
        _ensure_governance_tables(conn)
        conn.execute("BEGIN IMMEDIATE")
        _cleanup_expired_leases(conn, now, agent_id=key or None)
        _prune_buckets(conn)
        row = None
        if key:
            row = conn.execute(
                """
                SELECT agent_id, window_started, consumed_tokens, reserved_tokens,
                       consumed_cost_usd, reserved_cost_usd, in_flight, last_seen
                FROM gateway_resource_buckets WHERE agent_id = ?
                """,
                (key,),
            ).fetchone()
            if row is not None:
                row = _reset_bucket_window(conn, row, now)
        return _snapshot_from_row(conn, row, key)
