"""Static task-scoped authorization layered below an Agent boundary."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from fnmatch import fnmatchcase
from typing import Any
from urllib.parse import urlsplit

from apps.api.agent_supervisor.domains.governance.tool_contract import (
    SUPPORTED_TOOLS,
    canonical_text,
    endpoint_allowlist_target_is_valid,
    endpoint_allowlist_target_within_scope,
    endpoint_matches_allowlist,
    get_agent_api_allowlist,
    get_agent_tool_allowlist,
    mail_recipient_addresses,
    normalize_path,
    path_is_absolute_or_traversal,
)
from apps.api.agent_supervisor.domains.governance.tool_registry import resolve_tool_call

TASK_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
TASK_CONTEXT_FIELDS = ("task_id", "task_profile_fingerprint", "policy_revision", "task_scope", "task_profile_required")
TASK_CONTEXT_KEY = "__agent_supervisor_task_context"


@dataclass(frozen=True)
class TaskProfileBinding:
    required: bool
    valid: bool
    task_id: str = ""
    profile: dict[str, Any] | None = None
    fingerprint: str = ""
    policy_revision: str = ""
    require_approval: bool = False
    reason: str = ""


@dataclass(frozen=True)
class TaskScopeResult:
    allowed: bool
    scope: str
    reason: str = ""


def normalize_task_id(value: Any) -> str:
    """Accept one header/body task identifier without coercing malformed text."""

    candidate = str(value or "").strip()
    if not candidate:
        return ""
    if not TASK_ID_RE.fullmatch(candidate):
        raise ValueError("task_id 长度或格式无效")
    return candidate


def resolve_task_profile(
    agent_id: str,
    task_id: Any,
    *,
    settings: dict[str, Any] | None = None,
) -> TaskProfileBinding:
    """Resolve the current profile without ever trusting a caller-supplied scope."""

    if settings is None:
        from apps.api.agent_supervisor.storage.data import get_policy_settings

        settings = get_policy_settings()
    policy = settings if isinstance(settings, dict) else {}
    revision = _safe_revision(policy.get("policy_revision"))
    profiles = policy.get("task_profiles")
    profiles = profiles if isinstance(profiles, dict) else {}
    normalized_agent = canonical_text(agent_id)
    raw_task_id = str(task_id or "").strip()
    requested_profile = profiles.get(raw_task_id)
    agent_profiles = [
        value
        for value in profiles.values()
        if isinstance(value, dict) and canonical_text(value.get("agent_id")) == normalized_agent
    ]

    if raw_task_id:
        try:
            normalized_task_id = normalize_task_id(raw_task_id)
        except ValueError:
            return TaskProfileBinding(
                required=bool(agent_profiles or isinstance(requested_profile, dict)),
                valid=False,
                task_id=raw_task_id[:160],
                policy_revision=revision,
                reason="任务标识格式无效。",
            )
    else:
        normalized_task_id = ""

    if not agent_profiles:
        if isinstance(requested_profile, dict):
            return TaskProfileBinding(
                required=True,
                valid=False,
                task_id=normalized_task_id,
                policy_revision=revision,
                reason="任务档案不属于当前 Agent。",
            )
        return TaskProfileBinding(required=False, valid=True, policy_revision=revision)

    if not normalized_task_id:
        return TaskProfileBinding(
            required=True,
            valid=False,
            policy_revision=revision,
            reason="当前 Agent 已配置任务授权，必须提供 X-Agent-Task-ID。",
        )
    if not isinstance(requested_profile, dict):
        return TaskProfileBinding(
            required=True,
            valid=False,
            task_id=normalized_task_id,
            policy_revision=revision,
            reason="任务档案不存在。",
        )
    if canonical_text(requested_profile.get("agent_id")) != normalized_agent:
        return TaskProfileBinding(
            required=True,
            valid=False,
            task_id=normalized_task_id,
            policy_revision=revision,
            reason="任务档案与当前 Agent 不匹配。",
        )
    if requested_profile.get("enabled") is not True:
        return TaskProfileBinding(
            required=True,
            valid=False,
            task_id=normalized_task_id,
            policy_revision=revision,
            reason="任务档案已停用。",
        )
    if _is_expired(requested_profile.get("expires_at")):
        return TaskProfileBinding(
            required=True,
            valid=False,
            task_id=normalized_task_id,
            policy_revision=revision,
            reason="任务档案已过期。",
        )
    return TaskProfileBinding(
        required=True,
        valid=True,
        task_id=normalized_task_id,
        profile=requested_profile,
        fingerprint=task_profile_fingerprint(requested_profile),
        policy_revision=revision,
        require_approval=bool(requested_profile.get("require_approval")),
    )


def evaluate_task_scope(
    binding: TaskProfileBinding,
    raw_tool_call: dict[str, Any],
    *,
    agent_id: str,
) -> TaskScopeResult:
    """Check an already-resolved profile against the canonical tool contract."""

    if not binding.required:
        return TaskScopeResult(True, "not-required")
    if not binding.valid or not isinstance(binding.profile, dict):
        return TaskScopeResult(False, "task-invalid", binding.reason or "任务档案无效。")
    try:
        resolution = resolve_tool_call(raw_tool_call, agent_id=agent_id)
        tool_call = resolution.effective_tool_call
        capability = canonical_text(tool_call.get("tool")).lower()
        arguments = tool_call.get("arguments")
        arguments = arguments if isinstance(arguments, dict) else {}
    except (TypeError, ValueError) as exc:
        return TaskScopeResult(False, "task-contract-denied", f"任务范围无法解析工具调用：{exc}")
    if capability not in SUPPORTED_TOOLS:
        return TaskScopeResult(False, "task-capability-denied", "任务范围未允许未登记能力。")
    if capability != "model.respond":
        allowed = {canonical_text(item).lower() for item in _string_list(binding.profile, "allowed_capabilities")}
        if capability not in allowed:
            return TaskScopeResult(False, "task-capability-denied", "任务范围未允许该工具能力。")
    if capability in {"file.read", "file.write"}:
        path = normalize_path(arguments.get("path"))
        patterns = _string_list(binding.profile, "allowed_file_paths")
        if not patterns or path_is_absolute_or_traversal(path) or not any(fnmatchcase(path, pattern) for pattern in patterns):
            return TaskScopeResult(False, "task-path-denied", "文件目标不在当前任务路径范围内。")
    if capability == "api.call":
        endpoint = str(arguments.get("endpoint") or "")
        parsed = urlsplit(endpoint)
        if parsed.scheme or parsed.netloc:
            origins = _string_list(binding.profile, "allowed_api_origins")
            if not origins or not endpoint_matches_allowlist(endpoint, origins):
                return TaskScopeResult(False, "task-origin-denied", "API 目标不在当前任务 Origin 范围内。")
    if capability == "mail.send":
        domains = {value.lower().lstrip("@") for value in _string_list(binding.profile, "allowed_email_domains")}
        recipients = mail_recipient_addresses(arguments.get("to"))
        if not domains or not recipients or any(address.rsplit("@", 1)[1] not in domains for address in recipients):
            return TaskScopeResult(False, "task-mail-denied", "邮件收件人不在当前任务域范围内。")
    return TaskScopeResult(True, "approval-required" if binding.require_approval and capability != "model.respond" else "allowed")


def task_audit_context(binding: TaskProfileBinding, scope: str = "") -> dict[str, Any]:
    """Return the non-sensitive binding fields that belong in signed evidence."""

    return {
        "task_id": binding.task_id,
        "task_profile_fingerprint": binding.fingerprint,
        "policy_revision": binding.policy_revision,
        "task_scope": scope or ("task-invalid" if binding.required and not binding.valid else "not-required"),
        "task_profile_required": binding.required,
    }


def task_binding_mismatch_reason(
    context: dict[str, Any],
    *,
    agent_id: str,
    raw_tool_call: dict[str, Any],
) -> str | None:
    """Reject post-approval/post-audit execution after a task policy changes."""

    task_id = str(context.get("task_id") or "").strip()
    if not task_id:
        if context.get("task_profile_required") is True:
            return "执行上下文缺少任务授权绑定。"
        return None
    binding = resolve_task_profile(agent_id, task_id)
    if not binding.valid:
        return binding.reason or "任务档案不再有效。"
    if binding.fingerprint != str(context.get("task_profile_fingerprint") or ""):
        return "任务档案已变更，原审批或执行意图失效。"
    if binding.policy_revision != str(context.get("policy_revision") or ""):
        return "策略版本已变更，原审批或执行意图失效。"
    scope = evaluate_task_scope(binding, raw_tool_call, agent_id=agent_id)
    return None if scope.allowed else scope.reason


def validate_task_profiles_config(settings: dict[str, Any]) -> None:
    """Keep profiles strictly narrower than the configured Agent boundary."""

    profiles = settings.get("task_profiles")
    if not isinstance(profiles, dict):
        raise ValueError("task_profiles 必须是对象")
    for raw_task_id, raw_profile in profiles.items():
        task_id = normalize_task_id(raw_task_id)
        if not isinstance(raw_profile, dict):
            raise ValueError(f"任务档案 {task_id} 必须是对象")
        agent_id = canonical_text(raw_profile.get("agent_id"))
        if not TASK_ID_RE.fullmatch(agent_id):
            raise ValueError(f"任务档案 {task_id} 的 agent_id 无效")
        capabilities = {canonical_text(item).lower() for item in _string_list(raw_profile, "allowed_capabilities")}
        if not capabilities.issubset(SUPPORTED_TOOLS):
            raise ValueError(f"任务档案 {task_id} 包含未登记能力")
        agent_capabilities = get_agent_tool_allowlist(settings, agent_id)
        if capabilities and (agent_capabilities is None or not capabilities.issubset(set(agent_capabilities))):
            raise ValueError(f"任务档案 {task_id} 的能力范围不能扩大 Agent {agent_id} 的权限")
        for path in _string_list(raw_profile, "allowed_file_paths"):
            if path_is_absolute_or_traversal(path):
                raise ValueError(f"任务档案 {task_id} 包含越界文件路径范围")
        agent_origins = get_agent_api_allowlist(settings, agent_id)
        for origin in _string_list(raw_profile, "allowed_api_origins"):
            if not endpoint_allowlist_target_is_valid(origin):
                raise ValueError(f"任务档案 {task_id} 包含无效 API Origin")
            if not endpoint_allowlist_target_within_scope(origin, agent_origins):
                raise ValueError(f"任务档案 {task_id} 的 API Origin 不能扩大 Agent {agent_id} 的范围")
        for domain in _string_list(raw_profile, "allowed_email_domains"):
            if not _valid_email_domain(domain):
                raise ValueError(f"任务档案 {task_id} 包含无效邮件域")
        if _expiry_issue(raw_profile.get("expires_at")):
            raise ValueError(f"任务档案 {task_id} 的 expires_at 必须是带时区的 ISO-8601 时间")


def task_profile_fingerprint(profile: dict[str, Any]) -> str:
    payload = {
        "agent_id": canonical_text(profile.get("agent_id")),
        "name": canonical_text(profile.get("name")),
        "enabled": bool(profile.get("enabled")),
        "allowed_capabilities": _string_list(profile, "allowed_capabilities"),
        "allowed_file_paths": _string_list(profile, "allowed_file_paths"),
        "allowed_api_origins": _string_list(profile, "allowed_api_origins"),
        "allowed_email_domains": _string_list(profile, "allowed_email_domains"),
        "require_approval": bool(profile.get("require_approval")),
        "expires_at": str(profile.get("expires_at") or "").strip(),
    }
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _string_list(profile: dict[str, Any], key: str) -> list[str]:
    raw = profile.get(key)
    if not isinstance(raw, list):
        return []
    values: list[str] = []
    for item in raw[:100]:
        value = canonical_text(item)
        if value and value not in values:
            values.append(value)
    return values


def _safe_revision(value: Any) -> str:
    candidate = str(value or "bootstrap").strip()
    return candidate if TASK_ID_RE.fullmatch(candidate) else "bootstrap"


def _is_expired(value: Any) -> bool:
    if not str(value or "").strip():
        return False
    parsed = _parse_expiry(value)
    return parsed is None or parsed <= datetime.now(timezone.utc)


def _expiry_issue(value: Any) -> bool:
    return bool(str(value or "").strip()) and _parse_expiry(value) is None


def _parse_expiry(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.astimezone(timezone.utc) if parsed.tzinfo is not None else None


def _valid_email_domain(value: str) -> bool:
    address = mail_recipient_addresses(f"scope@{value.lstrip('@')}")
    return bool(address) and address[0].rsplit("@", 1)[1] == value.lower().lstrip("@")
