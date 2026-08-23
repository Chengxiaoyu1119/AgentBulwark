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
    # Runtime metadata is not a credential, but exposing it gives the model
    # the host layout and makes later path traversal attempts easier to target.
    "state_path",
    "workspace_path",
    "runtime_path",
    "working_directory",
    "workdir",
    "cwd",
)

BEARER_PATTERN = re.compile(r"(?i)\bbearer\s+[a-z0-9._~+/=-]{8,}")
ASSIGNMENT_PATTERN = re.compile(
    r"(?i)\b(api[_-]?key|access[_-]?token|refresh[_-]?token|password|passwd|secret|token|authorization)"
    r"\s*[:=]\s*([^\s,;]{4,})"
)
TOKEN_LITERAL_PATTERN = re.compile(
    r"(?i)(?<![a-z0-9])(?:sk|pk|rk|xoxb|ghp|github_pat|AIza)[_-][a-z0-9._-]{8,}(?![a-z0-9])"
)
EMAIL_PATTERN = re.compile(r"(?i)\b([a-z0-9._%+-])([a-z0-9._%+-]*)@([a-z0-9.-]+\.[a-z]{2,})\b")
FIXTURE_SECRET_PATTERN = re.compile(
    r"(?i)\b(?:portal_token|judge_token|flag_seed|ctf_token|review_token|session_token|training_platform_token)"
    r"(?:[_:=\-][a-z0-9{}.-]+)+\b"
)
SYSTEM_PROMPT_ASSIGNMENT_PATTERN = re.compile(
    r"(?is)\b(system\s+prompt|system\s+message|developer\s+message|系统提示词|系统指令|开发者消息)\s*[:=：]\s*([^\r\n]{1,400})"
)
SECRET_LIKE_LITERAL_PATTERN = re.compile(
    r"(?<![A-Za-z0-9])(?:[A-Z0-9]+[_-])*(?:TOP[_-]?SECRET|SECRET|TOKEN|API[_-]?KEY|PASSWORD|CREDENTIAL)(?:[_-][A-Z0-9]+)*(?![A-Za-z0-9])"
)
# A tool result may contain a diagnostic object (for example, a target-lab
# summary) with the absolute path of the runtime state file.  That path is
# model-visible even when the rest of the result is benign.  Redact common
# host/runtime roots while leaving protocol routes such as ``/api/...`` and
# user-facing relative paths intact.
WINDOWS_ABSOLUTE_PATH_PATTERN = re.compile(
    r"(?i)(?<![A-Za-z0-9])(?:[A-Z]:[\\/])(?:[^\\/\s\"'<>|,;\)\]}]+[\\/])*[^\\/\s\"'<>|,;\)\]}]+"
)
POSIX_RUNTIME_PATH_PATTERN = re.compile(
    r"(?<![A-Za-z0-9:])/(?:tmp|var|home|root|app|workspace|mnt|opt|srv|etc|proc|sys|run|Users|private)/[^\s\"'<>|,;\)\]}]+"
)


def sanitize_model_visible_tool_result(
    value: Any,
    *,
    max_serialized_chars: int = 32_000,
) -> dict[str, Any]:
    """Create the single model-visible boundary for a tool result.

    Hashing proves which result was produced; it does not make the result
    trustworthy.  This helper keeps those concerns separate: the original
    canonical hash is retained for receipt binding, secrets are redacted before
    model exposure, and indirect-injection content is replaced by a bounded
    marker instead of being returned as instructions.  Callers should persist
    only the metadata fields and pass ``model_value`` to the next model turn.
    """
    serialized = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str, separators=(",", ":"))
    original_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
    redacted = redact_sensitive(value)
    redacted_serialized = json.dumps(
        redacted,
        ensure_ascii=False,
        sort_keys=True,
        default=str,
        separators=(",", ":"),
    )

    # Keep the generic redaction module independent at import time.  The lazy
    # import also avoids making storage/audit users load the scanner unless a
    # result is actually about to be sent to a model.
    try:
        from apps.api.agent_supervisor.domains.governance.skill_scanner import scan_text

        scan = scan_text(serialized, quarantine_on_truncate=True)
        verdict = str(getattr(scan, "verdict", "clean"))
        signals = [str(item) for item in getattr(scan, "signals", []) if item]
    except Exception:  # noqa: BLE001 - scanner failure must not expose model-visible tool data
        verdict = "quarantine"
        signals = ["context-scanner-error"]

    if verdict == "quarantine":
        model_value: Any = {
            "status": "quarantined",
            "trust": "quarantined",
            "content_hash": original_hash,
            "signals": signals[:12],
            "output": "工具结果已隔离；模型不可见原始内容，请等待人工复核。",
        }
        trust = "quarantined"
    else:
        trust = "untrusted-data"
        if len(redacted_serialized) > max_serialized_chars:
            model_value = {
                "status": "truncated",
                "trust": trust,
                "content_hash": original_hash,
                "output": redacted_serialized[:max_serialized_chars],
            }
        else:
            model_value = redacted

    model_serialized = json.dumps(model_value, ensure_ascii=False, sort_keys=True, default=str, separators=(",", ":"))
    return {
        "model_value": model_value,
        "original_hash": original_hash,
        "model_visible_hash": hashlib.sha256(model_serialized.encode("utf-8")).hexdigest(),
        "redacted": redacted_serialized != serialized,
        "trust": trust,
        "verdict": verdict,
        "signals": signals[:12],
    }


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
    redacted = TOKEN_LITERAL_PATTERN.sub("<redacted:token-literal>", redacted)
    redacted = FIXTURE_SECRET_PATTERN.sub("<redacted:fixture-secret>", redacted)
    # Free-form model messages are not key/value JSON.  A phrase such as
    # ``system prompt: TOP_SECRET_INTERNAL`` would otherwise pass through the
    # key-aware redactor unchanged and become durable audit evidence.
    redacted = SYSTEM_PROMPT_ASSIGNMENT_PATTERN.sub(lambda match: f"{match.group(1)}=<redacted>", redacted)
    redacted = SECRET_LIKE_LITERAL_PATTERN.sub("<redacted:secret-literal>", redacted)
    redacted = WINDOWS_ABSOLUTE_PATH_PATTERN.sub("<redacted:absolute-path>", redacted)
    redacted = POSIX_RUNTIME_PATH_PATTERN.sub("<redacted:absolute-path>", redacted)
    return EMAIL_PATTERN.sub(lambda match: f"{match.group(1)}***@{match.group(3).lower()}", redacted)
