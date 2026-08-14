from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from typing import Any

from apps.api.agent_supervisor.domains.governance.integrity import audit_hash, audit_signature
from apps.api.agent_supervisor.domains.governance.redaction import redact_sensitive
from apps.api.agent_supervisor.domains.governance.tool_contract import normalize_tool_call
from apps.api.agent_supervisor.domains.runtime.event_stream import publish_runtime_event
from apps.api.agent_supervisor.storage.database import (
    list_runtime_events,
    load_audit_log,
    load_execution_receipt,
    persist_execution_receipt,
)

EXECUTION_STATUSES = frozenset({"completed", "failed", "not_executed"})
EXECUTION_TARGETS = frozenset({"real", "sandbox", "none"})
KNOWN_DECISIONS = frozenset({"允许", "拒绝", "询问", "隔离"})
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class ExecutionReceiptConflictError(ValueError):
    """Raised when an audit or receipt id already has different evidence."""


def tool_call_hash(tool_call: dict[str, Any]) -> str:
    normalized = normalize_tool_call(tool_call)
    encoded = json.dumps(normalized, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def complete_execution(
    audit_id: str,
    request: dict[str, Any],
) -> dict[str, Any]:
    """Validate and append the external executor's result without rewriting the decision audit."""
    audit_log = load_audit_log(audit_id)
    if not audit_log:
        raise KeyError(audit_id)
    _verify_original_audit(audit_log)

    agent_id = str(request.get("agent_id", ""))
    if str(audit_log.get("agent_id", "")) != agent_id:
        raise ValueError("执行回执的 agent_id 与原始工具调用不一致")

    raw_tool_call = request.get("tool_call")
    if not isinstance(raw_tool_call, dict):
        raise ValueError("执行回执必须包含原始 tool_call")
    submitted_tool_hash = tool_call_hash(raw_tool_call)
    expected_tool_hash = str(audit_log.get("tool_call_hash", ""))
    if not expected_tool_hash:
        raise ValueError("原始审计缺少 tool_call_hash，不能建立可信执行回执")
    if submitted_tool_hash != expected_tool_hash:
        raise ValueError("执行回执的工具调用与原始审计不一致")

    status = str(request.get("status", ""))
    execution_target = str(request.get("execution_target", ""))
    decision = str(audit_log.get("decision", ""))
    _validate_execution_state(decision, status, execution_target)

    result_hash = str(request.get("result_hash", "")).strip().lower()
    if status in {"completed", "failed"} and not SHA256_PATTERN.fullmatch(result_hash):
        raise ValueError("completed 或 failed 回执必须包含 64 位十六进制 SHA-256 result_hash")
    if result_hash and not SHA256_PATTERN.fullmatch(result_hash):
        raise ValueError("result_hash 必须是 64 位十六进制 SHA-256")

    duration_ms = round(float(request.get("duration_ms", 0)), 3)
    if duration_ms < 0 or duration_ms > 86_400_000:
        raise ValueError("duration_ms 必须在 0 到 86400000 之间")

    receipt_id = str(request.get("receipt_id", "")).strip()
    if not receipt_id:
        raise ValueError("receipt_id 不能为空")
    created_at = datetime.now(timezone.utc).isoformat()
    sanitized_error = str(redact_sensitive(str(request.get("error", ""))))[:2000]
    request_fingerprint = {
        "audit_id": audit_id,
        "receipt_id": receipt_id,
        "agent_id": agent_id,
        "tool_call_hash": submitted_tool_hash,
        "status": status,
        "execution_target": execution_target,
        "result_hash": result_hash,
        "duration_ms": duration_ms,
        "error": sanitized_error,
    }
    receipt = {
        **request_fingerprint,
        "run_id": str(audit_log.get("run_id", "")),
        "decision": decision,
        "policy_id": str(audit_log.get("policy_id", "")),
        "audit_hash": str(audit_log.get("audit_hash", "")),
        "created_at": created_at,
        "request_hash": _sha256_payload(request_fingerprint),
        "agent_followed_decision": _agent_followed_decision(decision, status, execution_target),
        "execution_confirmed": status == "completed",
        "control_verified": _control_verified(decision, status, execution_target),
    }
    receipt_hash_value = _receipt_hash(receipt)
    receipt["receipt_hash"] = receipt_hash_value
    signature = audit_signature(receipt_hash_value)
    receipt["receipt_signature"] = signature
    receipt["receipt_signature_key_id"] = os.getenv("AGENT_SUPERVISOR_AUDIT_HMAC_KEY_ID", "local-hmac-v1") if signature else ""

    persisted = persist_execution_receipt(receipt)
    if persisted.get("conflict"):
        raise ExecutionReceiptConflictError("该 audit_id 或 receipt_id 已存在内容不同的执行回执")
    stored_receipt = persisted["payload"]
    response = {
        "persisted": True,
        "idempotent": bool(persisted.get("idempotent")),
        "event_id": persisted.get("event_id"),
        "receipt": stored_receipt,
    }
    if not response["idempotent"]:
        publish_runtime_event(
            "execution-receipt",
            {
                "event_id": response["event_id"],
                "audit_id": audit_id,
                "run_id": stored_receipt.get("run_id"),
                "agent_id": agent_id,
                "decision": decision,
                "status": status,
                "execution_target": execution_target,
                "agent_followed_decision": stored_receipt.get("agent_followed_decision"),
                "control_verified": stored_receipt.get("control_verified"),
            },
        )
    return response


def list_execution_receipts(limit: int = 200) -> dict[str, Any]:
    events = list_runtime_events(event_type="execution-receipt", limit=limit)
    receipts = [event["payload"] | {"event_id": event["event_id"]} for event in events if isinstance(event.get("payload"), dict)]
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total": len(receipts),
            "completed": sum(1 for item in receipts if item.get("status") == "completed"),
            "failed": sum(1 for item in receipts if item.get("status") == "failed"),
            "not_executed": sum(1 for item in receipts if item.get("status") == "not_executed"),
            "decision_followed": sum(1 for item in receipts if item.get("agent_followed_decision")),
            "control_verified": sum(1 for item in receipts if item.get("control_verified")),
            "signed": sum(1 for item in receipts if item.get("receipt_signature")),
        },
        "receipts": receipts,
    }


def get_execution_receipt(audit_id: str) -> dict[str, Any]:
    """Return the latest persisted state for one supervised tool call."""
    if not load_audit_log(audit_id):
        raise KeyError(audit_id)
    return {
        "audit_id": audit_id,
        "receipt": load_execution_receipt(audit_id),
    }


def _verify_original_audit(audit_log: dict[str, Any]) -> None:
    stored_hash = str(audit_log.get("audit_hash", ""))
    if not stored_hash or stored_hash != audit_hash(audit_log):
        raise ValueError("原始审计 Hash 校验失败，执行回执已暂停写入")


def _validate_execution_state(decision: str, status: str, execution_target: str) -> None:
    if decision not in KNOWN_DECISIONS:
        raise ValueError("原始监督决策不是受支持的协议值")
    if status not in EXECUTION_STATUSES:
        raise ValueError("status 必须是 completed、failed 或 not_executed")
    if execution_target not in EXECUTION_TARGETS:
        raise ValueError("execution_target 必须是 real、sandbox 或 none")

    if decision in {"拒绝", "询问"}:
        if status != "not_executed" or execution_target != "none":
            raise ValueError("拒绝或询问决策只能提交 not_executed/none 回执")
        return
    if decision == "隔离":
        if execution_target == "real":
            raise ValueError("隔离决策不得提交真实执行回执")
        if execution_target == "none" and status != "not_executed":
            raise ValueError("未配置隔离执行器时只能提交 not_executed/none 回执")
        if execution_target == "sandbox" and status == "not_executed":
            raise ValueError("not_executed 回执的 execution_target 必须是 none")
        return

    if status == "not_executed" and execution_target != "none":
        raise ValueError("not_executed 回执的 execution_target 必须是 none")
    if status in {"completed", "failed"} and execution_target not in {"real", "sandbox"}:
        raise ValueError("允许决策的 completed/failed 回执必须指向 real 或 sandbox")


def _agent_followed_decision(decision: str, status: str, execution_target: str) -> bool:
    if decision in {"拒绝", "询问"}:
        return status == "not_executed" and execution_target == "none"
    if decision == "隔离":
        return execution_target != "real"
    if decision == "允许":
        return (status == "not_executed" and execution_target == "none") or execution_target in {"real", "sandbox"}
    return False


def _control_verified(decision: str, status: str, execution_target: str) -> bool:
    if decision in {"拒绝", "询问"}:
        return status == "not_executed" and execution_target == "none"
    if decision == "隔离":
        return (execution_target == "sandbox" and status in {"completed", "failed"}) or (
            execution_target == "none" and status == "not_executed"
        )
    return False


def _receipt_hash(receipt: dict[str, Any]) -> str:
    payload = {
        key: value
        for key, value in receipt.items()
        if key not in {"receipt_hash", "receipt_signature", "receipt_signature_key_id"}
    }
    return _sha256_payload(payload)


def _sha256_payload(payload: dict[str, Any]) -> str:
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()
