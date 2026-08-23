from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from apps.api.agent_supervisor.domains.governance.redaction import redact_sensitive
from apps.api.agent_supervisor.domains.governance.tool_contract import normalize_tool_call
from apps.api.agent_supervisor.domains.runtime.event_stream import publish_runtime_event
from apps.api.agent_supervisor.paths import SANDBOX_REPORTS_DIR
from apps.api.agent_supervisor.storage.data import get_policy_settings
from apps.api.agent_supervisor.storage.database import get_connection

REPORT_ROOT = SANDBOX_REPORTS_DIR

PENDING_STATUS = "待复核"
APPROVED_STATUS = "已批准"
REJECTED_STATUS = "已驳回"

STATUS_VALUES = {PENDING_STATUS, APPROVED_STATUS, REJECTED_STATUS}
SCOPE_VALUES = {"operational", "experiment", "demo"}
ACTION_MAP = {
    "approve": (APPROVED_STATUS, "允许", "人工批准后，原始Agent可以领取并恢复一次该工具调用。"),
    "批准": (APPROVED_STATUS, "允许", "人工批准后，原始Agent可以领取并恢复一次该工具调用。"),
    "reject": (REJECTED_STATUS, "拒绝", "人工驳回后，工具调用保持阻断，建议补充业务依据或改用脱敏结果。"),
    "驳回": (REJECTED_STATUS, "拒绝", "人工驳回后，工具调用保持阻断，建议补充业务依据或改用脱敏结果。"),
}


def create_approval_review(
    event: dict[str, Any],
    supervisor_result: dict[str, Any],
    review_scope: str = "operational",
) -> dict[str, Any] | None:
    """Create a review ticket for decisions that require human confirmation."""
    if supervisor_result.get("decision") != "询问":
        return None

    audit_log = supervisor_result.get("audit_log") or {}
    if not audit_log.get("id"):
        return None

    existing = _load_review_by_audit_id(str(audit_log["id"]))
    if existing:
        return existing

    tool_call = event.get("tool_call") or {}
    created_at = _now()
    settings = get_policy_settings()
    sla_minutes = int(settings.get("approval_sla_minutes", 30))
    due_at = (datetime.now(timezone.utc) + timedelta(minutes=sla_minutes)).isoformat()
    escalation_level = "P1" if supervisor_result.get("risk_level") in {"high", "critical"} else "P2"
    review = {
        "id": str(uuid4()),
        "audit_id": str(audit_log["id"]),
        "run_id": str(supervisor_result.get("run_id", audit_log.get("run_id", ""))),
        "status": PENDING_STATUS,
        "scope": _normalize_scope(review_scope),
        "final_decision": "等待人工确认",
        "approval_action": "",
        "tool": str(audit_log.get("tool", tool_call.get("tool", ""))),
        "arguments": redact_sensitive(tool_call.get("arguments", audit_log.get("arguments", {}))),
        "standard_capability": str(audit_log.get("standard_capability", audit_log.get("tool", ""))),
        "standard_arguments": audit_log.get("standard_arguments", audit_log.get("arguments", {})),
        "tool_mapping": audit_log.get("tool_mapping"),
        "policy_id": str(supervisor_result.get("policy_id", audit_log.get("policy_id", ""))),
        "risk_level": str(supervisor_result.get("risk_level", audit_log.get("risk_level", "medium"))),
        "risk_score": supervisor_result.get("risk_score", audit_log.get("risk_score", 0)),
        "risk_factors": supervisor_result.get("risk_factors", audit_log.get("risk_factors", [])),
        "anomaly_score": supervisor_result.get("anomaly_score", audit_log.get("anomaly_score", 0)),
        "anomaly_signals": supervisor_result.get("anomaly_signals", audit_log.get("anomaly_signals", [])),
        "reason": str(supervisor_result.get("reason", audit_log.get("reason", ""))),
        "recommendation": str(supervisor_result.get("recommendation", audit_log.get("recommendation", ""))),
        "source_app": str(event.get("source_app", audit_log.get("source_app", "generic-agent"))),
        "agent_id": str(event.get("agent_id", audit_log.get("agent_id", "external-agent"))),
        "authenticated_agent_id": str(
            event.get("authenticated_agent_id", audit_log.get("authenticated_agent_id", ""))
        ),
        "agent_identity_verified": bool(
            event.get("agent_identity_verified", audit_log.get("agent_identity_verified", False))
        ),
        "agent_identity_admin_override": bool(
            event.get("agent_identity_admin_override", audit_log.get("agent_identity_admin_override", False))
        ),
        "agent_identity_shared_compatibility": bool(
            event.get(
                "agent_identity_shared_compatibility",
                audit_log.get("agent_identity_shared_compatibility", False),
            )
        ),
        "conversation_id": str(event.get("conversation_id", audit_log.get("conversation_id", "external-conversation"))),
        "model_input_excerpt": str(redact_sensitive(str(event.get("model_input", ""))))[:360],
        "model_output_excerpt": str(redact_sensitive(str(event.get("model_output", ""))))[:360],
        "audit_hash": str(audit_log.get("audit_hash", "")),
        "previous_hash": str(audit_log.get("previous_hash", "")),
        "review_previous_hash": str(audit_log.get("audit_hash", "")),
        "operator": "",
        "comment": "",
        "created_at": created_at,
        "reviewed_at": "",
        "due_at": due_at,
        "sla_minutes": sla_minutes,
        "sla_breached": False,
        "escalation_level": escalation_level,
        "execution_note": "监督器已暂停并登记该工具调用；批准后由原始Agent领取并恢复一次。",
        "tool_call_hash": _tool_call_hash(tool_call),
        "execution_status": "pending_review",
        "execution_claim_id": "",
        "execution_claim_agent_id": "",
        "execution_claimed_at": "",
        "execution_completed_at": "",
        "execution_result_hash": "",
        "sandbox_replay_requested": False,
        "sandbox_replayed_at": "",
        "sandbox_replay": None,
        "hash_valid": True,
    }
    review["review_hash"] = _review_hash(review)
    _write_review(review)
    return review


def list_approval_reviews(
    status: str | None = None,
    limit: int = 100,
    scope: str | None = None,
) -> dict[str, Any]:
    selected_status = _normalize_status(status)
    selected_scope = _normalize_scope(scope, allow_all=True)
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT payload FROM approval_reviews ORDER BY rowid DESC LIMIT ?",
            (limit,),
        ).fetchall()

    reviews = [_restore_hash_state(json.loads(row["payload"])) for row in rows]
    if selected_scope:
        reviews = [item for item in reviews if item.get("scope") == selected_scope]
    if selected_status:
        reviews = [item for item in reviews if item.get("status") == selected_status]

    summary = _summary(reviews)
    return {
        "generated_at": _now(),
        "status_filter": selected_status or "全部",
        "scope_filter": selected_scope or "全部",
        "summary": summary,
        "reviews": reviews,
    }


def redact_approval_review_for_observer(review: dict[str, Any]) -> dict[str, Any]:
    """Keep queue state visible without exposing another Agent's context.

    An approval record is an operational security object, not a public report:
    its arguments and model excerpts may contain credentials, business data or
    prompt-injection text.  Analysts and administrators retain the full record;
    observer credentials receive the decision metadata and evidence hashes only.
    """

    redacted = dict(review)
    for key in (
        "arguments",
        "standard_arguments",
        "tool_mapping",
        "model_input_excerpt",
        "model_output_excerpt",
        "comment",
        "execution_note",
        "sandbox_replay",
    ):
        if key in redacted:
            redacted[key] = {} if key.endswith("arguments") or key == "tool_mapping" else ""
    for key in ("agent_id", "authenticated_agent_id", "execution_claim_agent_id"):
        if key in redacted and redacted[key]:
            redacted[key] = "<redacted>"
    redacted["reason"] = "该复核单包含受保护的 Agent 上下文；仅 analyst/admin 可查看详情。"
    redacted["recommendation"] = "请由 analyst/admin 在受控复核界面查看处置依据。"
    redacted["access_scope"] = "summary-redacted"
    return redacted


def redact_approval_inventory_for_observer(data: dict[str, Any]) -> dict[str, Any]:
    """Project an approval inventory for a read-only observer credential."""

    projected = dict(data)
    reviews = data.get("reviews")
    if isinstance(reviews, list):
        projected["reviews"] = [
            redact_approval_review_for_observer(item)
            for item in reviews
            if isinstance(item, dict)
        ]
    projected["access_scope"] = "summary-redacted"
    return projected


def decide_approval_review(
    review_id: str,
    action: str,
    operator: str = "operator",
    comment: str = "",
    execute_in_sandbox: bool = False,
) -> dict[str, Any]:
    normalized_action = action.strip().lower() if action else ""
    if normalized_action not in ACTION_MAP:
        raise ValueError("action 必须是 approve/reject，或中文“批准/驳回”")
    if execute_in_sandbox:
        raise ValueError("审批决策只改变恢复状态，不在数据库事务内执行工具")

    with get_connection() as conn:
        conn.execute("BEGIN IMMEDIATE")
        review = _load_review_from_connection(conn, review_id)
        if not review:
            raise KeyError(review_id)
        if review.get("status") != PENDING_STATUS:
            raise ValueError("该复核单已经处理，不能重复批准或驳回")

        status, final_decision, execution_note = ACTION_MAP[normalized_action]
        sandbox_replay = review.get("sandbox_replay")
        sandbox_replayed_at = review.get("sandbox_replayed_at", "")

        updated = {
            **review,
            "status": status,
            "final_decision": final_decision,
            "approval_action": normalized_action,
            "operator": operator or "operator",
            "comment": comment,
            "reviewed_at": _now(),
            "execution_note": execution_note,
            "sandbox_replay_requested": False,
            "sandbox_replayed_at": sandbox_replayed_at,
            "sandbox_replay": sandbox_replay,
            "execution_status": (
                "ready_to_resume"
                if status == APPROVED_STATUS
                else "rejected"
            ),
        }
        updated["review_hash"] = _review_hash(updated)
        updated["hash_valid"] = True
        _update_review(conn, updated)
    publish_runtime_event(
        "approval-decision",
        {
            "review_id": review_id,
            "status": status,
            "final_decision": final_decision,
            "operator": updated["operator"],
            "sandbox_replay": sandbox_replay,
        },
    )
    return {
        "updated": True,
        "review": updated,
        "summary": list_approval_reviews()["summary"],
    }


def get_approval_review(review_id: str) -> dict[str, Any]:
    review = _load_review(review_id)
    if not review:
        raise KeyError(review_id)
    return review


def claim_approval_execution(review_id: str, agent_id: str, tool_call: dict[str, Any]) -> dict[str, Any]:
    with get_connection() as conn:
        conn.execute("BEGIN IMMEDIATE")
        review = _load_review_from_connection(conn, review_id)
        if not review:
            raise KeyError(review_id)
        if review.get("status") != APPROVED_STATUS:
            return {
                "granted": False,
                "reason": "复核单尚未批准，工具调用保持暂停。",
                "review": review,
            }
        if review.get("agent_id") != agent_id:
            raise ValueError("仅原始Agent可以领取该审批调用")
        if review.get("tool_call_hash") != _tool_call_hash(tool_call):
            raise ValueError("恢复执行的工具调用与原始待审批调用不一致")
        if review.get("execution_status") != "ready_to_resume":
            return {
                "granted": False,
                "reason": "该审批调用尚未进入可恢复状态，或已经被领取、执行、驳回或沙箱重放。",
                "review": review,
            }

        claim_id = str(uuid4())
        updated = {
            **review,
            "execution_status": "claimed",
            "execution_claim_id": claim_id,
            "execution_claim_agent_id": agent_id,
            "execution_claimed_at": _now(),
            "execution_note": "人工批准后的原始工具调用已由原始Agent领取，等待执行结果回执。",
        }
        updated["review_hash"] = _review_hash(updated)
        updated["hash_valid"] = True
        _update_review(conn, updated)
    publish_runtime_event(
        "approval-execution-claimed",
        {"review_id": review_id, "claim_id": claim_id, "agent_id": agent_id},
    )
    return {"granted": True, "claim_id": claim_id, "review": updated}


def complete_approval_execution(
    review_id: str,
    claim_id: str,
    agent_id: str,
    *,
    succeeded: bool,
    result_hash: str = "",
) -> dict[str, Any]:
    with get_connection() as conn:
        conn.execute("BEGIN IMMEDIATE")
        review = _load_review_from_connection(conn, review_id)
        if not review:
            raise KeyError(review_id)
        if review.get("execution_claim_agent_id") != agent_id or review.get("agent_id") != agent_id:
            raise ValueError("仅领取该调用的原始Agent可以提交执行回执")
        if review.get("execution_status") != "claimed" or review.get("execution_claim_id") != claim_id:
            raise ValueError("执行回执与已领取的审批调用不匹配")
        updated = {
            **review,
            "execution_status": "completed" if succeeded else "failed",
            "execution_completed_at": _now(),
            "execution_result_hash": result_hash,
            "execution_note": "原始工具调用已恢复并完成。" if succeeded else "原始工具调用恢复后执行失败。",
        }
        updated["review_hash"] = _review_hash(updated)
        updated["hash_valid"] = True
        _update_review(conn, updated)
    publish_runtime_event(
        "approval-execution-completed",
        {
            "review_id": review_id,
            "claim_id": claim_id,
            "agent_id": agent_id,
            "succeeded": succeeded,
            "result_hash": result_hash,
        },
    )
    return {"updated": True, "review": updated}


def build_approval_review_markdown(data: dict[str, Any] | None = None) -> str:
    inventory = None
    if data is None:
        inventory = list_approval_reviews(limit=200)
        data = list_approval_reviews(limit=200, scope="demo")
    summary = data["summary"]
    lines = [
        "# 人工复核队列与审批闭环报告",
        "",
        "本报告记录监督器判定为“询问”的工具调用。每条复核单都关联原始审计 hash，并在批准或驳回后生成新的 review_hash，便于答辩时证明人工处置没有脱离证据链。",
        "",
        "## 队列概览",
        "",
        f"- 复核单总数：{summary['total']}",
        f"- 待复核：{summary['pending_count']}",
        f"- 已批准：{summary['approved_count']}",
        f"- 已驳回：{summary['rejected_count']}",
        f"- 高危/极高：{summary['high_risk_count']}",
        f"- hash 有效：{summary['hash_valid_count']} / {summary['total']}",
        f"- 队列范围：{data.get('scope_filter', '全部')}（业务 {summary['scope_counts']['operational']}、实验 {summary['scope_counts']['experiment']}、演示 {summary['scope_counts']['demo']}）",
        "",
        "## 复核明细",
        "",
        "| 时间 | 状态 | 工具 | 策略 | 风险 | 操作人 | 结论 | 证据 |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for item in data["reviews"]:
        lines.append(
            "| {created_at} | {status} | `{tool}` | `{policy_id}` | {risk_level}/{risk_score} | {operator} | {final_decision} | {reason} |".format(
                created_at=str(item.get("created_at", ""))[:19].replace("T", " "),
                status=item.get("status", ""),
                tool=item.get("tool", ""),
                policy_id=item.get("policy_id", ""),
                risk_level=item.get("risk_level", ""),
                risk_score=item.get("risk_score", "-"),
                operator=item.get("operator") or "-",
                final_decision=item.get("final_decision") or "-",
                reason=str(item.get("reason", "")).replace("\n", " ")[:120],
            )
        )

    if not data["reviews"]:
        lines.append("| - | - | - | - | - | - | - | 当前没有复核单。 |")

    lines.extend(
        [
            "",
            "## 验收口径",
            "",
            "- 外部智能体调用 `/api/runtime/evaluate` 后，如果策略返回“询问”，系统自动生成待复核单。",
            "- 监督端可以通过 `/api/approvals/{review_id}/decision` 执行批准或驳回。",
            "- 审批结论、操作人、备注、原始审计 hash 和复核 hash 都会写入本地数据库。",
        ]
    )
    if inventory is not None:
        inventory_summary = inventory["summary"]
        scope_counts = inventory_summary["scope_counts"]
        lines.extend(
            [
                "",
                "## 队列隔离清单",
                "",
                f"- 业务记录：{scope_counts['operational']}，待复核 {sum(1 for item in inventory['reviews'] if item.get('scope') == 'operational' and item.get('status') == PENDING_STATUS)}。",
                f"- 实验记录：{scope_counts['experiment']}，待复核 {sum(1 for item in inventory['reviews'] if item.get('scope') == 'experiment' and item.get('status') == PENDING_STATUS)}。",
                f"- 演示记录：{scope_counts['demo']}，当前正文仅用演示记录验证批准、驳回和复核Hash闭环。",
                "- 实验积压与业务待办分开统计，避免批量评测污染日常复核SLA。",
            ]
        )
    return "\n".join(lines)


def write_approval_review_report(output_root: str | Path | None = None) -> dict[str, Any]:
    root = Path(output_root) if output_root else REPORT_ROOT
    root.mkdir(parents=True, exist_ok=True)
    data = list_approval_reviews(limit=200)
    json_path = root / "人工复核队列报告.json"
    markdown_path = root / "人工复核队列报告.md"
    json_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    markdown_path.write_text(build_approval_review_markdown(data), encoding="utf-8")
    return {
        "generated_at": data["generated_at"],
        "json_path": str(json_path.resolve()),
        "markdown_path": str(markdown_path.resolve()),
        "summary": data["summary"],
        "reviews": data["reviews"],
    }


def _write_review(review: dict[str, Any]) -> None:
    with get_connection() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO approval_reviews (
                id, audit_id, run_id, status, final_decision, tool, policy_id,
                risk_level, risk_score, reason, operator, created_at,
                reviewed_at, payload
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                review["id"],
                review["audit_id"],
                review["run_id"],
                review["status"],
                review["final_decision"],
                review["tool"],
                review["policy_id"],
                review["risk_level"],
                int(review.get("risk_score") or 0),
                review["reason"],
                review.get("operator", ""),
                review["created_at"],
                review.get("reviewed_at", ""),
                json.dumps(review, ensure_ascii=False),
            ),
        )


def _update_review(conn: sqlite3.Connection, review: dict[str, Any]) -> None:
    cursor = conn.execute(
        """
        UPDATE approval_reviews SET
            status = ?, final_decision = ?, tool = ?, policy_id = ?,
            risk_level = ?, risk_score = ?, reason = ?, operator = ?,
            reviewed_at = ?, payload = ?
        WHERE id = ?
        """,
        (
            review["status"],
            review["final_decision"],
            review["tool"],
            review["policy_id"],
            review["risk_level"],
            int(review.get("risk_score") or 0),
            review["reason"],
            review.get("operator", ""),
            review.get("reviewed_at", ""),
            json.dumps(review, ensure_ascii=False),
            review["id"],
        ),
    )
    if cursor.rowcount != 1:
        raise KeyError(str(review["id"]))


def _load_review(review_id: str) -> dict[str, Any] | None:
    with get_connection() as conn:
        return _load_review_from_connection(conn, review_id)


def _load_review_from_connection(conn: sqlite3.Connection, review_id: str) -> dict[str, Any] | None:
    row = conn.execute("SELECT payload FROM approval_reviews WHERE id = ?", (review_id,)).fetchone()
    return _restore_hash_state(json.loads(row["payload"])) if row else None


def _load_review_by_audit_id(audit_id: str) -> dict[str, Any] | None:
    with get_connection() as conn:
        row = conn.execute("SELECT payload FROM approval_reviews WHERE audit_id = ?", (audit_id,)).fetchone()
    return _restore_hash_state(json.loads(row["payload"])) if row else None


def _restore_hash_state(review: dict[str, Any]) -> dict[str, Any]:
    review["hash_valid"] = review.get("review_hash") == _review_hash(review)
    review["scope"] = _review_scope(review)
    due_at = str(review.get("due_at", ""))
    if review.get("status") == PENDING_STATUS and due_at:
        try:
            review["sla_breached"] = datetime.fromisoformat(due_at) < datetime.now(timezone.utc)
        except ValueError:
            review["sla_breached"] = False
    return review


def _review_hash(review: dict[str, Any]) -> str:
    payload = {key: value for key, value in review.items() if key not in {"review_hash", "hash_valid"}}
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _tool_call_hash(tool_call: dict[str, Any]) -> str:
    normalized = normalize_tool_call(tool_call)
    encoded = json.dumps(normalized, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _summary(reviews: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "total": len(reviews),
        "pending_count": sum(1 for item in reviews if item.get("status") == PENDING_STATUS),
        "approved_count": sum(1 for item in reviews if item.get("status") == APPROVED_STATUS),
        "rejected_count": sum(1 for item in reviews if item.get("status") == REJECTED_STATUS),
        "high_risk_count": sum(1 for item in reviews if item.get("risk_level") in {"high", "critical"}),
        "hash_valid_count": sum(1 for item in reviews if item.get("hash_valid")),
        "latest_created_at": max((str(item.get("created_at", "")) for item in reviews), default=""),
        "latest_reviewed_at": max((str(item.get("reviewed_at", "")) for item in reviews if item.get("reviewed_at")), default=""),
        "sla_breached_count": sum(
            1 for item in reviews if item.get("status") == PENDING_STATUS and item.get("sla_breached")
        ),
        "scope_counts": {
            scope: sum(1 for item in reviews if item.get("scope") == scope)
            for scope in sorted(SCOPE_VALUES)
        },
    }


def _normalize_status(status: str | None) -> str | None:
    if not status or status == "全部":
        return None
    if status not in STATUS_VALUES:
        raise ValueError(f"未知复核状态：{status}")
    return status


def _normalize_scope(scope: str | None, *, allow_all: bool = False) -> str | None:
    if allow_all and (not scope or scope == "全部"):
        return None
    normalized = (scope or "operational").strip().lower()
    if normalized not in SCOPE_VALUES:
        raise ValueError("scope 必须是 operational、experiment 或 demo")
    return normalized


def _review_scope(review: dict[str, Any]) -> str:
    source_app = str(review.get("source_app", ""))
    agent_id = str(review.get("agent_id", ""))
    conversation_id = str(review.get("conversation_id", ""))
    if (
        source_app == "generic-agent"
        and agent_id in {"sender-agent", "collector-agent"}
        and conversation_id == "chain-test"
    ):
        return "experiment"

    explicit = str(review.get("scope", "")).strip().lower()
    if explicit in SCOPE_VALUES:
        return explicit

    if source_app == "JudgeDemo" and agent_id == "judge-demo-agent" and conversation_id.startswith("judge-demo-"):
        return "demo"
    if (
        (source_app == "generic-agent" and agent_id in {"sender-agent", "collector-agent"} and conversation_id.startswith("chain-"))
        or (
            source_app in {"智安哨本地渗透学习受控实验环境", "智安哨本地渗透学习靶场"}
            and agent_id == "vulnerable-learning-agent"
            and conversation_id.startswith("learning-")
        )
        or (
            source_app == "智安哨攻击功能实验台"
            and agent_id == "attack-lab-agent"
            and conversation_id.startswith("attack-")
        )
    ):
        return "experiment"
    return "operational"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
