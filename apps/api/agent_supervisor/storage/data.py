from __future__ import annotations

import json
import os
import threading
import time
import uuid
from copy import deepcopy
from typing import Any, cast

from apps.api.agent_supervisor.domains.runtime.security_profile import production_security_profile
from apps.api.agent_supervisor.paths import PACKAGE_DIR, RUNTIME_DIR
from apps.api.agent_supervisor.storage.database import record_policy_version
from apps.api.agent_supervisor.storage.json_store import exclusive_file_lock, load_json, load_json_existing, save_json

CONFIG_DIR = PACKAGE_DIR / "config"
POLICY_OVERRIDES_PATH = RUNTIME_DIR / "policy_overrides.json"
POLICY_SETTINGS_PATH = RUNTIME_DIR / "policy_settings.json"
POLICY_AUDIT_OUTBOX_PATH = RUNTIME_DIR / "policy_audit_outbox.json"
POLICY_EDITABLE_FIELDS = {"enabled", "name", "description", "decision", "layer", "risk_controls"}
DEFAULT_POLICY_SETTINGS: dict[str, Any] = {
    "anomaly_review_threshold": 55,
    "anomaly_reject_threshold": 85,
    "approval_sla_minutes": 30,
    "high_risk_auto_escalation": True,
    # Keep local fixtures compatible by default; production deployments should
    # enable both registration gates before issuing Agent tokens.
    "require_agent_capability_registration": False,
    "require_agent_model_registration": False,
    # MCP resources/prompts are model-visible context. Production deployments
    # must register an explicit per-Agent context scope as well.
    "require_agent_context_registration": False,
    "internal_email_domains": ["internal.example"],
    "sensitive_path_markers": [
        "confidential",
        "secret",
        "secrets",
        "token",
        "tokens",
        "credential",
        "credentials",
        ".env",
        "private-key",
        "private_key",
    ],
    "sensitive_api_markers": [
        "admin",
        "scoreboard",
        "challenge",
        "seed",
        "judge",
        "session",
        "campus-net",
    ],
    "agent_tool_allowlists": {
        "judge-demo-agent": ["file.read", "mail.send", "api.call", "memory.write"],
        "minimal-external-agent": ["file.read", "api.call", "mail.send"],
    },
    # Absolute HTTP destinations are a separate authority boundary from tool
    # capability grants.  Empty by default: a production Agent must register
    # its provider/business API hosts explicitly; relative fixture routes keep
    # working without a host entry.
    "agent_api_allowlists": {},
    # Model identifiers are another authority boundary: a valid Agent token
    # must not silently select an arbitrary provider/model once this map is
    # configured.  Empty keeps backwards-compatible local bootstrap behavior;
    # readiness reports it as a gap until each production Agent is registered.
    "agent_model_allowlists": {},
    # Resource URI/template and prompt-name scopes for MCP context reads.
    "agent_context_allowlists": {},
    "agent_tool_mappings": {},
}


_json_cache: dict[str, tuple[float, Any]] = {}
_enabled_cache: dict[str, tuple[float, bool]] = {}
_POLICY_CONFIG_LOCK = threading.RLock()
ENABLED_CACHE_TTL_SECONDS = 1.0


def _load_json_cached(path: Any, cache_key: str) -> Any:
    """带 mtime 失效的 JSON 读取缓存；缓存键含路径，支持测试中替换路径。

    decide() 热路径的高频查询由 is_policy_enabled 的 TTL 结果缓存兜住，
    本层每次做 stat 比对以保证文件变更即时生效。
    """
    cache_id = f"{path}|{cache_key}"
    mtime = path.stat().st_mtime
    cached = _json_cache.get(cache_id)
    if cached is not None and cached[0] == mtime:
        return cached[1]
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    _json_cache[cache_id] = (mtime, data)
    return data


def _load_json(filename: str) -> Any:
    return _load_json_cached(CONFIG_DIR / filename, filename)


def _load_json_list(filename: str) -> list[dict[str, Any]]:
    data = _load_json(filename)
    if not isinstance(data, list):
        raise TypeError(f"{filename} must contain a JSON list")
    return cast(list[dict[str, Any]], data)


def _load_json_dict(filename: str) -> dict[str, Any]:
    data = _load_json(filename)
    if not isinstance(data, dict):
        raise TypeError(f"{filename} must contain a JSON object")
    return cast(dict[str, Any], data)


_overrides_cache: dict[str, tuple[int, int, dict[str, dict[str, Any]]]] = {}


def _load_policy_overrides(
    *, force_refresh: bool = False, reject_invalid_existing: bool = False
) -> dict[str, dict[str, Any]]:
    try:
        stat = POLICY_OVERRIDES_PATH.stat()
    except FileNotFoundError:
        return {}
    except OSError:
        if reject_invalid_existing:
            raise
        return {}
    cache_id = str(POLICY_OVERRIDES_PATH)
    mtime_ns = stat.st_mtime_ns
    file_size = stat.st_size
    cached = _overrides_cache.get(cache_id)
    if not force_refresh and cached is not None and cached[0] == mtime_ns and cached[1] == file_size:
        return deepcopy(cached[2])
    try:
        raw = (
            load_json_existing(POLICY_OVERRIDES_PATH)
            if reject_invalid_existing
            else load_json(POLICY_OVERRIDES_PATH)
        )
    except FileNotFoundError:
        return {}
    if not isinstance(raw, dict):
        if reject_invalid_existing:
            raise ValueError(f"{POLICY_OVERRIDES_PATH} must contain a JSON object")
        return {}
    overrides: dict[str, dict[str, Any]] = {}
    for key, value in raw.items():
        policy_id = str(key)
        if isinstance(value, (bool, int, str)):
            overrides[policy_id] = {"enabled": value}
        elif isinstance(value, dict):
            clean = {field: item for field, item in value.items() if field in POLICY_EDITABLE_FIELDS}
            if "enabled" in clean:
                clean["enabled"] = bool(clean["enabled"])
            overrides[policy_id] = clean
    # Callers receive a detached value.  In particular, a writer must not
    # mutate the process-wide read cache before its atomic file replacement has
    # succeeded; otherwise a failed update can become effective in memory only.
    _overrides_cache[cache_id] = (mtime_ns, file_size, deepcopy(overrides))
    return overrides


def _invalidate_overrides_cache() -> None:
    _overrides_cache.clear()
    _enabled_cache.clear()


def _save_policy_overrides(overrides: dict[str, dict[str, Any]]) -> None:
    save_json(POLICY_OVERRIDES_PATH, overrides)
    _invalidate_overrides_cache()


_settings_cache: dict[str, tuple[float, dict[str, Any]]] = {}
# stat 节流时间戳：decide() 热路径每次调用会触发 2 次 _load_policy_settings，
# 文件系统 stat 在仓库目录树上存在毫秒级抖动（cProfile 实测占 decide() 76% 耗时）。
# 进程内更新经 _invalidate_settings_cache() 立即生效，仅进程外改文件延迟至多 1s 生效。
_settings_stat_at: dict[str, float] = {}
SETTINGS_STAT_TTL_SECONDS = 1.0


def _load_policy_settings(*, force_refresh: bool = False, reject_invalid_existing: bool = False) -> dict[str, Any]:
    cache_id = str(POLICY_SETTINGS_PATH)
    now = time.monotonic()
    cached = _settings_cache.get(cache_id)
    if not force_refresh and cached is not None and (now - _settings_stat_at.get(cache_id, 0.0)) < SETTINGS_STAT_TTL_SECONDS:
        return deepcopy(cached[1])
    try:
        mtime = os.stat(POLICY_SETTINGS_PATH).st_mtime
    except FileNotFoundError:
        defaults = deepcopy(DEFAULT_POLICY_SETTINGS)
        _settings_cache[cache_id] = (0.0, deepcopy(defaults))
        _settings_stat_at[cache_id] = now
        return defaults
    except OSError:
        if reject_invalid_existing:
            raise
        defaults = deepcopy(DEFAULT_POLICY_SETTINGS)
        _settings_cache[cache_id] = (0.0, deepcopy(defaults))
        _settings_stat_at[cache_id] = now
        return defaults
    _settings_stat_at[cache_id] = now
    if not force_refresh and cached is not None and cached[0] == mtime:
        return deepcopy(cached[1])
    try:
        raw = (
            load_json_existing(POLICY_SETTINGS_PATH)
            if reject_invalid_existing
            else load_json(POLICY_SETTINGS_PATH)
        )
    except FileNotFoundError:
        return deepcopy(DEFAULT_POLICY_SETTINGS)
    if not isinstance(raw, dict):
        if reject_invalid_existing:
            raise ValueError(f"{POLICY_SETTINGS_PATH} must contain a JSON object")
        return deepcopy(DEFAULT_POLICY_SETTINGS)
    settings = deepcopy(DEFAULT_POLICY_SETTINGS)
    settings.update(deepcopy(raw))
    settings = _normalize_policy_settings(settings)
    _settings_cache[cache_id] = (mtime, deepcopy(settings))
    return settings


def _invalidate_settings_cache() -> None:
    _settings_cache.clear()
    _settings_stat_at.clear()


def _normalize_policy_settings(settings: dict[str, Any]) -> dict[str, Any]:
    settings["anomaly_review_threshold"] = _clamp_int(settings.get("anomaly_review_threshold"), 1, 100)
    settings["anomaly_reject_threshold"] = _clamp_int(settings.get("anomaly_reject_threshold"), 1, 100)
    if settings["anomaly_reject_threshold"] < settings["anomaly_review_threshold"]:
        settings["anomaly_reject_threshold"] = settings["anomaly_review_threshold"]
    settings["approval_sla_minutes"] = _clamp_int(settings.get("approval_sla_minutes"), 1, 24 * 60)
    settings["high_risk_auto_escalation"] = bool(settings.get("high_risk_auto_escalation", True))
    settings["require_agent_capability_registration"] = bool(settings.get("require_agent_capability_registration", False))
    settings["require_agent_model_registration"] = bool(settings.get("require_agent_model_registration", False))
    settings["require_agent_context_registration"] = bool(settings.get("require_agent_context_registration", False))
    settings["internal_email_domains"] = _string_list(
        settings.get("internal_email_domains"), DEFAULT_POLICY_SETTINGS["internal_email_domains"], max_items=50
    )
    settings["sensitive_path_markers"] = _string_list(
        settings.get("sensitive_path_markers"), DEFAULT_POLICY_SETTINGS["sensitive_path_markers"], max_items=100
    )
    settings["sensitive_api_markers"] = _string_list(
        settings.get("sensitive_api_markers"), DEFAULT_POLICY_SETTINGS["sensitive_api_markers"], max_items=100
    )
    settings["agent_tool_allowlists"] = _tool_allowlists(settings.get("agent_tool_allowlists"))
    settings["agent_api_allowlists"] = _api_allowlists(settings.get("agent_api_allowlists"))
    settings["agent_model_allowlists"] = _model_allowlists(settings.get("agent_model_allowlists"))
    settings["agent_context_allowlists"] = _context_allowlists(settings.get("agent_context_allowlists"))
    settings["agent_tool_mappings"] = _tool_mappings(settings.get("agent_tool_mappings"))
    return settings


def _string_list(value: Any, default: list[str], *, max_items: int) -> list[str]:
    if not isinstance(value, list):
        return list(default)
    result: list[str] = []
    for item in value[:max_items]:
        normalized = str(item).strip().lower()
        if normalized and normalized not in result:
            result.append(normalized)
    return result or list(default)


def _tool_allowlists(value: Any) -> dict[str, list[str]]:
    if not isinstance(value, dict):
        return {}
    result: dict[str, list[str]] = {}
    for raw_agent_id, raw_tools in list(value.items())[:100]:
        agent_id = str(raw_agent_id).strip()
        if not agent_id or not isinstance(raw_tools, list):
            continue
        tools: list[str] = []
        for raw_tool in raw_tools[:100]:
            tool = str(raw_tool).strip().lower()
            if tool and tool not in tools:
                tools.append(tool)
        result[agent_id] = tools
    return result


def _api_allowlists(value: Any) -> dict[str, list[str]]:
    """Normalize Agent-bound external API host registrations.

    Validation of scheme/host syntax happens at decision time so malformed
    entries fail closed without making policy-file loading brittle.
    """
    if not isinstance(value, dict):
        return {}
    result: dict[str, list[str]] = {}
    for raw_agent_id, raw_targets in list(value.items())[:100]:
        agent_id = str(raw_agent_id).strip()
        if not agent_id or not isinstance(raw_targets, list):
            continue
        targets: list[str] = []
        for raw_target in raw_targets[:100]:
            target = str(raw_target).strip().lower()
            if target and target not in targets:
                targets.append(target)
        result[agent_id] = targets
    return result


def _model_allowlists(value: Any) -> dict[str, list[str]]:
    """Normalize Agent-bound model identifiers without accepting free-form maps."""
    if not isinstance(value, dict):
        return {}
    result: dict[str, list[str]] = {}
    for raw_agent_id, raw_models in list(value.items())[:100]:
        agent_id = str(raw_agent_id).strip()
        if not agent_id or not isinstance(raw_models, list):
            continue
        models: list[str] = []
        for raw_model in raw_models[:100]:
            model = str(raw_model).strip().replace("\r", "").replace("\n", "")[:160]
            if model and model.lower() not in {item.lower() for item in models}:
                models.append(model)
        result[agent_id] = models
    return result


def _context_allowlists(value: Any) -> dict[str, dict[str, list[str]]]:
    """Normalize Agent-bound MCP resource/prompt scopes.

    Entries are exact URIs/names or bounded shell-style patterns. The matcher
    is intentionally small so an operator can inspect the effective scope in
    the policy snapshot without introducing an expression language.
    """
    if not isinstance(value, dict):
        return {}
    result: dict[str, dict[str, list[str]]] = {}
    allowed_kinds = {"resources", "resource_templates", "prompts"}
    for raw_agent_id, raw_scope in list(value.items())[:100]:
        agent_id = str(raw_agent_id).strip()
        if not agent_id or not isinstance(raw_scope, dict):
            continue
        scope: dict[str, list[str]] = {}
        for raw_kind, raw_values in raw_scope.items():
            kind = str(raw_kind).strip().lower()
            if kind not in allowed_kinds or not isinstance(raw_values, list):
                continue
            values: list[str] = []
            for raw_value in raw_values[:100]:
                value_text = str(raw_value).strip()
                if value_text and len(value_text) <= 512 and value_text not in values:
                    values.append(value_text)
            scope[kind] = values
        result[agent_id] = scope
    return result


def _tool_mappings(value: Any) -> dict[str, dict[str, dict[str, Any]]]:
    if not isinstance(value, dict):
        return {}
    result: dict[str, dict[str, dict[str, Any]]] = {}
    for raw_agent_id, raw_mappings in list(value.items())[:100]:
        agent_id = str(raw_agent_id).strip()
        if not agent_id or not isinstance(raw_mappings, dict):
            continue
        mappings: dict[str, dict[str, Any]] = {}
        for raw_tool, raw_config in list(raw_mappings.items())[:100]:
            tool = str(raw_tool).strip().lower()
            if not tool or not isinstance(raw_config, dict):
                continue
            raw_argument_mapping = raw_config.get("argument_mapping", {})
            argument_mapping = (
                {
                    str(source).strip(): str(target).strip()
                    for source, target in list(raw_argument_mapping.items())[:100]
                    if str(source).strip() and str(target).strip()
                }
                if isinstance(raw_argument_mapping, dict)
                else {}
            )
            raw_required = raw_config.get("required_arguments", [])
            required_arguments = (
                list(dict.fromkeys(str(item).strip() for item in raw_required[:100] if str(item).strip()))
                if isinstance(raw_required, list)
                else []
            )
            mappings[tool] = {
                "capability": str(raw_config.get("capability", "")).strip().lower(),
                "argument_mapping": argument_mapping,
                "required_arguments": required_arguments,
                "risk_hint": str(raw_config.get("risk_hint", "")).strip().lower()[:160],
                "description": str(raw_config.get("description", "")).strip()[:500],
            }
        if mappings:
            result[agent_id] = mappings
    return result


def _save_policy_settings(settings: dict[str, Any]) -> None:
    save_json(POLICY_SETTINGS_PATH, settings)
    _invalidate_settings_cache()


def _load_policy_audit_outbox() -> dict[str, dict[str, Any]]:
    try:
        raw = load_json_existing(POLICY_AUDIT_OUTBOX_PATH)
    except FileNotFoundError:
        return {}
    if not isinstance(raw, dict):
        raise ValueError(f"{POLICY_AUDIT_OUTBOX_PATH} must contain a JSON object")
    if any(not isinstance(value, dict) for value in raw.values()):
        raise ValueError(f"{POLICY_AUDIT_OUTBOX_PATH} contains an invalid audit entry")
    return {str(key): value for key, value in raw.items()}


def _write_policy_audit_outbox(entries: dict[str, dict[str, Any]]) -> None:
    save_json(POLICY_AUDIT_OUTBOX_PATH, entries)


def _prepare_policy_audit_outbox(entry: dict[str, Any]) -> None:
    operation_id = str(entry["operation_id"])
    with exclusive_file_lock(POLICY_AUDIT_OUTBOX_PATH):
        _prepare_policy_audit_outbox_unlocked(operation_id, entry)


def _prepare_policy_audit_outbox_unlocked(operation_id: str, entry: dict[str, Any]) -> None:
    entries = _load_policy_audit_outbox()
    entries[operation_id] = entry
    _write_policy_audit_outbox(entries)


def _mark_policy_audit_outbox_applied(operation_id: str) -> None:
    with exclusive_file_lock(POLICY_AUDIT_OUTBOX_PATH):
        _mark_policy_audit_outbox_applied_unlocked(operation_id)


def _mark_policy_audit_outbox_applied_unlocked(operation_id: str) -> None:
    entries = _load_policy_audit_outbox()
    entry = entries.get(operation_id)
    if entry is None:
        raise RuntimeError("策略审计待发记录意外丢失")
    entry["state"] = "applied"
    entries[operation_id] = entry
    _write_policy_audit_outbox(entries)


def _remove_policy_audit_outbox_entry(operation_id: str) -> None:
    with exclusive_file_lock(POLICY_AUDIT_OUTBOX_PATH):
        _remove_policy_audit_outbox_entry_unlocked(operation_id)


def _remove_policy_audit_outbox_entry_unlocked(operation_id: str) -> None:
    entries = _load_policy_audit_outbox()
    if operation_id not in entries:
        return
    del entries[operation_id]
    _write_policy_audit_outbox(entries)


def _new_policy_audit_entry(
    *,
    resource: str,
    policy_id: str,
    before: dict[str, Any],
    after: dict[str, Any],
    operator: str,
    comment: str,
    expected_config: dict[str, Any],
) -> dict[str, Any]:
    return {
        "operation_id": uuid.uuid4().hex,
        "resource": resource,
        "policy_id": policy_id,
        "before": deepcopy(before),
        "after": deepcopy(after),
        "operator": operator or "security-admin",
        "comment": comment,
        "expected_config": deepcopy(expected_config),
        "state": "prepared",
    }


def _current_outbox_resource_config(resource: str) -> dict[str, Any] | None:
    if resource == "policy_overrides":
        return _load_policy_overrides(force_refresh=True, reject_invalid_existing=True)
    if resource == "policy_settings":
        return _load_policy_settings(force_refresh=True, reject_invalid_existing=True)
    return None


def recover_policy_audit_outbox() -> None:
    """Replay durable policy audit entries left after a database write failure.

    Runtime config becomes effective before its audit record is committed.  The
    file-backed outbox makes that boundary restart-safe.  Only entries whose
    intended configuration still matches the current file are replayed; a
    mismatch remains visible for later reconciliation rather than inventing an
    audit history for a superseded update.
    """
    with exclusive_file_lock(POLICY_AUDIT_OUTBOX_PATH):
        entries = _load_policy_audit_outbox()
        changed = False
        for operation_id, entry in list(entries.items()):
            resource = str(entry.get("resource") or "")
            expected_config = entry.get("expected_config")
            before = entry.get("before")
            after = entry.get("after")
            if not isinstance(expected_config, dict) or not isinstance(before, dict) or not isinstance(after, dict):
                continue
            current_config = _current_outbox_resource_config(resource)
            state = str(entry.get("state") or "")
            if state == "uncertain":
                # Once a prepared write has been observed behind a newer
                # configuration, a later coincidental value match is not proof
                # that the original operation was applied.  Keep it for
                # explicit reconciliation rather than manufacturing history.
                continue
            if current_config != expected_config:
                # ``save_json`` can replace the config immediately before a
                # process exits, leaving the outbox in ``prepared`` state.  A
                # surviving writer may then supersede that real change.  A
                # mismatch therefore cannot prove the prepared operation was
                # never applied; preserve the evidence as uncertain.
                if state == "prepared":
                    entry["state"] = "uncertain"
                    entries[operation_id] = entry
                    changed = True
                continue
            try:
                record_policy_version(
                    policy_id=str(entry.get("policy_id") or ""),
                    before=before,
                    after=after,
                    operator=str(entry.get("operator") or "security-admin"),
                    comment=str(entry.get("comment") or ""),
                    operation_id=operation_id,
                )
            except Exception:
                # Database availability must not prevent a server from
                # starting; retain the durable record for the next init.
                continue
            del entries[operation_id]
            changed = True
        if changed:
            _write_policy_audit_outbox(entries)


def _clamp_int(value: Any, min_value: int, max_value: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        number = min_value
    return max(min_value, min(max_value, number))


def get_policies() -> list[dict[str, Any]]:
    policies = _load_json_list("policies.json")
    overrides = _load_policy_overrides()
    enriched = []
    for policy in policies:
        override = overrides.get(policy["id"], {})
        merged = {**policy, **override}
        merged["enabled"] = bool(merged.get("enabled", policy["enabled"]))
        enriched.append(merged)
    return enriched


def set_policy_enabled(policy_id: str, enabled: bool) -> dict[str, Any]:
    return update_policy(policy_id, {"enabled": enabled}, operator="security-admin", comment="策略启停")


def update_policy(
    policy_id: str,
    updates: dict[str, Any],
    *,
    operator: str = "security-admin",
    comment: str = "",
) -> dict[str, Any]:
    with _POLICY_CONFIG_LOCK:
        # The outbox lock is the transaction-wide, cross-process mutex.  It
        # prevents startup recovery from discarding a prepared entry between
        # the config read and its atomic replacement.  Every writer takes locks
        # in the same order (outbox, then resource) to avoid lock inversion.
        with exclusive_file_lock(POLICY_AUDIT_OUTBOX_PATH):
            with exclusive_file_lock(POLICY_OVERRIDES_PATH):
                return _update_policy_unlocked(policy_id, updates, operator=operator, comment=comment)


def _update_policy_unlocked(
    policy_id: str,
    updates: dict[str, Any],
    *,
    operator: str = "security-admin",
    comment: str = "",
) -> dict[str, Any]:
    policies = _load_json_list("policies.json")
    # Cross-process writers must discard any process-local snapshot while the
    # file lock is held, then perform the complete read/merge/write sequence.
    _invalidate_overrides_cache()
    overrides = _load_policy_overrides(force_refresh=True, reject_invalid_existing=True)
    for policy in policies:
        if policy["id"] == policy_id:
            before = next(item for item in get_policies() if item["id"] == policy_id)
            current_override = overrides.get(policy_id, {})
            clean_updates = {key: value for key, value in updates.items() if key in POLICY_EDITABLE_FIELDS}
            if "enabled" in clean_updates:
                clean_updates["enabled"] = bool(clean_updates["enabled"])
            if "risk_controls" in clean_updates and not isinstance(clean_updates["risk_controls"], list):
                clean_updates.pop("risk_controls")
            overrides[policy_id] = {**current_override, **clean_updates}
            after = {**policy, **overrides[policy_id]}
            entry = _new_policy_audit_entry(
                resource="policy_overrides",
                policy_id=policy_id,
                before=before,
                after=after,
                operator=operator,
                comment=comment or "策略配置更新",
                expected_config=overrides,
            )
            operation_id = str(entry["operation_id"])
            _prepare_policy_audit_outbox_unlocked(operation_id, entry)
            try:
                _save_policy_overrides(overrides)
            except Exception:
                # A replace may have completed even when a later durability
                # step reports an error.  Keep the prepared intent so startup
                # recovery can compare it with disk, and ensure readers reload
                # the actual file rather than a transaction-local object.
                _invalidate_overrides_cache()
                raise
            _mark_policy_audit_outbox_applied_unlocked(operation_id)
            try:
                record_policy_version(
                    policy_id=policy_id,
                    before=before,
                    after=after,
                    operator=operator,
                    comment=comment or "策略配置更新",
                    operation_id=operation_id,
                )
            except Exception:
                # The applied entry is deliberately retained for init_db() to
                # replay after a transient audit-store failure.
                raise
            _remove_policy_audit_outbox_entry_unlocked(operation_id)
            return after
    raise KeyError(f"Policy not found: {policy_id}")


def is_policy_enabled(policy_id: str) -> bool:
    """decide() 热路径高频调用：策略开关按 TTL 结果缓存，每秒至多一次真实加载。"""
    now = time.monotonic()
    cache_key = f"{POLICY_OVERRIDES_PATH}|{CONFIG_DIR / 'policies.json'}|{policy_id}"
    cached = _enabled_cache.get(cache_key)
    if cached is not None and (now - cached[0]) < ENABLED_CACHE_TTL_SECONDS:
        return cached[1]
    policies = _load_json_list("policies.json")
    overrides = _load_policy_overrides()
    snapshot_at = now
    for policy in policies:
        enabled = bool(overrides.get(str(policy["id"]), {}).get("enabled", policy["enabled"]))
        _enabled_cache[f"{POLICY_OVERRIDES_PATH}|{CONFIG_DIR / 'policies.json'}|{policy['id']}"] = (
            snapshot_at,
            enabled,
        )
        if str(policy["id"]) == policy_id:
            return enabled
    return False


def get_policy_settings() -> dict[str, Any]:
    settings = _load_policy_settings()
    if production_security_profile():
        # A deployed gateway must not inherit the local fixture compatibility
        # mode. Tool, model and MCP context registration are separate authority
        # boundaries and are all forced on in the production profile.
        settings["require_agent_capability_registration"] = True
        settings["require_agent_model_registration"] = True
        settings["require_agent_context_registration"] = True
    return settings


def update_policy_settings(updates: dict[str, Any]) -> dict[str, Any]:
    with _POLICY_CONFIG_LOCK:
        with exclusive_file_lock(POLICY_AUDIT_OUTBOX_PATH):
            with exclusive_file_lock(POLICY_SETTINGS_PATH):
                return _update_policy_settings_unlocked(updates)


def _update_policy_settings_unlocked(updates: dict[str, Any]) -> dict[str, Any]:
    _invalidate_settings_cache()
    before = _load_policy_settings(force_refresh=True, reject_invalid_existing=True)
    if production_security_profile():
        before["require_agent_capability_registration"] = True
        before["require_agent_model_registration"] = True
        before["require_agent_context_registration"] = True
    settings = _normalize_policy_settings(
        {**before, **{key: value for key, value in updates.items() if key in DEFAULT_POLICY_SETTINGS}}
    )
    if production_security_profile():
        settings["require_agent_capability_registration"] = True
        settings["require_agent_model_registration"] = True
        settings["require_agent_context_registration"] = True
    operator = str(updates.get("operator", "security-admin"))
    comment = str(updates.get("comment", "运行阈值更新"))
    entry = _new_policy_audit_entry(
        resource="policy_settings",
        policy_id="__runtime_settings__",
        before=before,
        after=settings,
        operator=operator,
        comment=comment,
        expected_config=settings,
    )
    operation_id = str(entry["operation_id"])
    _prepare_policy_audit_outbox_unlocked(operation_id, entry)
    try:
        _save_policy_settings(settings)
    except Exception:
        # Treat the write result as uncertain: retain the prepared intent and
        # force subsequent reads to reflect the file that is actually on disk.
        _invalidate_settings_cache()
        raise
    _mark_policy_audit_outbox_applied_unlocked(operation_id)
    record_policy_version(
        policy_id="__runtime_settings__",
        before=before,
        after=settings,
        operator=operator,
        comment=comment,
        operation_id=operation_id,
    )
    _remove_policy_audit_outbox_entry_unlocked(operation_id)
    return settings
