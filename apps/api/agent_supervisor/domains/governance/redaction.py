from __future__ import annotations

import hashlib
import json
import re
from typing import Any

SENSITIVE_KEY_MARKERS = (
    "authorization",
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "password",
    "passwd",
    "secret",
    "credential",
    "private_key",
    "cookie",
    "portal_token",
    "judge_token",
    "flag_seed",
    "ctf_token",
    "review_token",
    "session_token",
    "training_platform_token",
)

BEARER_PATTERN = re.compile(r"(?i)\bbearer\s+[a-z0-9._~+/=-]{8,}")
ASSIGNMENT_PATTERN = re.compile(
    r"(?i)\b(api[_-]?key|access[_-]?token|refresh[_-]?token|password|passwd|secret|authorization)"
    r"\s*[:=]\s*([^\s,;]{4,})"
)
EMAIL_PATTERN = re.compile(r"(?i)\b([a-z0-9._%+-])([a-z0-9._%+-]*)@([a-z0-9.-]+\.[a-z]{2,})\b")
FIXTURE_SECRET_PATTERN = re.compile(
    r"(?i)\b(?:portal_token|judge_token|flag_seed|ctf_token|review_token|session_token|training_platform_token)"
    r"(?:[_:=\-][a-z0-9{}.-]+)+\b"
)


def redact_sensitive(value: Any, *, key_hint: str = "", max_depth: int = 8) -> Any:
    """Return a JSON-compatible copy with credentials and direct identifiers masked."""
    if max_depth <= 0:
        return "<redacted:max-depth>"
    if _sensitive_key(key_hint):
        return _fingerprint(value)
    if isinstance(value, dict):
        return {
            str(key): redact_sensitive(item, key_hint=str(key), max_depth=max_depth - 1)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_sensitive(item, max_depth=max_depth - 1) for item in value]
    if isinstance(value, tuple):
        return [redact_sensitive(item, max_depth=max_depth - 1) for item in value]
    if isinstance(value, str):
        return _redact_text(value)
    return value


def _sensitive_key(key: str) -> bool:
    lowered = str(key or "").strip().lower().replace("-", "_")
    return any(marker in lowered for marker in SENSITIVE_KEY_MARKERS)


def _fingerprint(value: Any) -> str:
    digest = hashlib.sha256(str(value).encode("utf-8", errors="replace")).hexdigest()[:12]
    return f"<redacted:sha256:{digest}>"


def _redact_text(text: str) -> str:
    # Tool output is often a JSON string rather than a nested Python object.
    # Parse it before applying key-aware redaction so evidence remains useful
    # while secret-bearing fields are never persisted verbatim.
    try:
        parsed = json.loads(text)
    except (TypeError, ValueError):
        parsed = None
    if isinstance(parsed, (dict, list)):
        return json.dumps(redact_sensitive(parsed), ensure_ascii=False)
    redacted = BEARER_PATTERN.sub("Bearer <redacted>", text)
    redacted = ASSIGNMENT_PATTERN.sub(lambda match: f"{match.group(1)}=<redacted>", redacted)
    redacted = FIXTURE_SECRET_PATTERN.sub("<redacted:fixture-secret>", redacted)
    return EMAIL_PATTERN.sub(lambda match: f"{match.group(1)}***@{match.group(3).lower()}", redacted)
