from __future__ import annotations

import hashlib
import hmac
import json
import os
from typing import Any


def attach_audit_hashes(logs: list[dict[str, Any]], seed: str) -> list[dict[str, Any]]:
    previous_hash = hashlib.sha256(seed.encode("utf-8")).hexdigest()
    for log in logs:
        log["previous_hash"] = previous_hash
        log["audit_hash"] = audit_hash(log)
        signature = audit_signature(log["audit_hash"])
        if signature:
            log["audit_signature"] = signature
            log["audit_signature_key_id"] = os.getenv("AGENT_SUPERVISOR_AUDIT_HMAC_KEY_ID", "local-hmac-v1")
        previous_hash = log["audit_hash"]
    return logs


def audit_hash(log: dict[str, Any]) -> str:
    payload = {
        key: value
        for key, value in log.items()
        if key not in {"audit_hash", "audit_signature", "audit_signature_key_id"}
    }
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def audit_signature(audit_hash_value: str) -> str:
    key = os.getenv("AGENT_SUPERVISOR_AUDIT_HMAC_KEY", "").encode("utf-8")
    if not key:
        return ""
    return hmac.new(key, audit_hash_value.encode("utf-8"), hashlib.sha256).hexdigest()


def audit_signature_required() -> bool:
    """Return whether the deployment has opted into mandatory HMAC evidence.

    Hashes deliberately remain useful in local, keyless development runs.  Once
    an HMAC key is configured, however, an attacker must not be able to delete
    the signature field while leaving the content hash unchanged: signatures
    are excluded from ``audit_hash`` so that exact tampering case needs an
    explicit presence check.
    """
    return bool(os.getenv("AGENT_SUPERVISOR_AUDIT_HMAC_KEY", "").strip())


def verify_audit_signature(value: str, signature: str) -> bool:
    """Verify an optional signature, requiring presence when HMAC is enabled."""
    expected = audit_signature(value)
    supplied = str(signature or "")
    if not expected:
        return not audit_signature_required() and not supplied
    return bool(supplied) and hmac.compare_digest(supplied, expected)


def verify_audit_hashes(logs: list[dict[str, Any]], seed: str) -> dict[str, Any]:
    previous_hash = hashlib.sha256(seed.encode("utf-8")).hexdigest()
    failures = []
    signature_checked = 0
    for index, log in enumerate(logs, start=1):
        if log.get("previous_hash") != previous_hash:
            failures.append({"step": index, "reason": "previous_hash 不连续"})
            previous_hash = str(log.get("audit_hash", ""))
            continue
        expected = audit_hash(log)
        if log.get("audit_hash") != expected:
            failures.append({"step": index, "reason": "audit_hash 与内容不匹配"})
        if audit_signature_required() and not log.get("audit_signature"):
            failures.append({"step": index, "reason": "已配置审计签名密钥但记录缺少 audit_signature"})
        elif log.get("audit_signature"):
            signature_checked += 1
            if not verify_audit_signature(
                str(log.get("audit_hash", "")),
                str(log.get("audit_signature", "")),
            ):
                failures.append({"step": index, "reason": "audit_signature 与审计内容不匹配"})
        previous_hash = str(log.get("audit_hash", ""))
    return {
        "valid": not failures,
        "checked": len(logs),
        "signature_checked": signature_checked,
        "failures": failures,
    }
