from __future__ import annotations

import json
import os
import time
from copy import deepcopy
from typing import Any, cast

from apps.api.agent_supervisor.domains.runtime.security_profile import production_security_profile
from apps.api.agent_supervisor.paths import PACKAGE_DIR, RUNTIME_DIR
from apps.api.agent_supervisor.storage.database import record_policy_version

CONFIG_DIR = PACKAGE_DIR / "config"
POLICY_OVERRIDES_PATH = RUNTIME_DIR / "policy_overrides.json"
POLICY_SETTINGS_PATH = RUNTIME_DIR / "policy_settings.json"
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


def _load_policy_overrides() -> dict[str, dict[str, Any]]:
    if not POLICY_OVERRIDES_PATH.exists():
        return {}
    cache_id = str(POLICY_OVERRIDES_PATH)
    stat = POLICY_OVERRIDES_PATH.stat()
    mtime_ns = stat.st_mtime_ns
    file_size = stat.st_size
    cached = _overrides_cache.get(cache_id)
    if cached is not None and cached[0] == mtime_ns and cached[1] == file_size:
        return cached[2]
    try:
        raw = json.loads(POLICY_OVERRIDES_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    if not isinstance(raw, dict):
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
    _overrides_cache[cache_id] = (mtime_ns, file_size, overrides)
    return overrides


def _invalidate_overrides_cache() -> None:
    _overrides_cache.clear()
    _enabled_cache.clear()


def _save_policy_overrides(overrides: dict[str, dict[str, Any]]) -> None:
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    tmp_path = POLICY_OVERRIDES_PATH.with_suffix(".tmp")
    tmp_path.write_text(json.dumps(overrides, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp_path.replace(POLICY_OVERRIDES_PATH)
    _invalidate_overrides_cache()


_settings_cache: dict[str, tuple[float, dict[str, Any]]] = {}
# stat 节流时间戳：decide() 热路径每次调用会触发 2 次 _load_policy_settings，
# 文件系统 stat 在仓库目录树上存在毫秒级抖动（cProfile 实测占 decide() 76% 耗时）。
# 进程内更新经 _invalidate_settings_cache() 立即生效，仅进程外改文件延迟至多 1s 生效。
_settings_stat_at: dict[str, float] = {}
SETTINGS_STAT_TTL_SECONDS = 1.0


def _load_policy_settings() -> dict[str, Any]:
    cache_id = str(POLICY_SETTINGS_PATH)
    now = time.monotonic()
    cached = _settings_cache.get(cache_id)
    if cached is not None and (now - _settings_stat_at.get(cache_id, 0.0)) < SETTINGS_STAT_TTL_SECONDS:
        return dict(cached[1])
    try:
        mtime = os.stat(POLICY_SETTINGS_PATH).st_mtime
    except OSError:
        _settings_cache[cache_id] = (0.0, dict(DEFAULT_POLICY_SETTINGS))
        _settings_stat_at[cache_id] = now
        return dict(DEFAULT_POLICY_SETTINGS)
    _settings_stat_at[cache_id] = now
    if cached is not None and cached[0] == mtime:
        return dict(cached[1])
    try:
        raw = json.loads(POLICY_SETTINGS_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return dict(DEFAULT_POLICY_SETTINGS)
    if not isinstance(raw, dict):
        return dict(DEFAULT_POLICY_SETTINGS)
    settings = _normalize_policy_settings({**DEFAULT_POLICY_SETTINGS, **raw})
    _settings_cache[cache_id] = (mtime, settings)
    return dict(settings)


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
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    tmp_path = POLICY_SETTINGS_PATH.with_suffix(".tmp")
    tmp_path.write_text(json.dumps(settings, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp_path.replace(POLICY_SETTINGS_PATH)
    _invalidate_settings_cache()


def _clamp_int(value: Any, min_value: int, max_value: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        number = min_value
    return max(min_value, min(max_value, number))


def get_attack_surfaces() -> list[dict[str, Any]]:
    surfaces = deepcopy(_load_json_list("attack_surfaces.json"))
    return [_genericize_product_scenario(surface) for surface in surfaces]


def get_student_competition_attack_map() -> list[dict[str, Any]]:
    # The file remains a historical regression fixture, but it must not define
    # the product's visible domain.  The runtime console is an AI-Agent
    # security gateway, so expose the same attack paths as tenant/session/
    # document assets rather than leaking the old contest narrative.
    profiles = deepcopy(_load_json_list("student_competition_attack_map.json"))
    return [_genericize_product_scenario(profile) for profile in profiles]


def _enrich_policy(policy: dict[str, Any], impacts: dict[str, Any]) -> dict[str, Any]:
    return {**policy, **impacts.get(policy["id"], {})}


def get_policies() -> list[dict[str, Any]]:
    policies = _load_json_list("policies.json")
    impacts = _load_json_dict("policy_impact.json")
    overrides = _load_policy_overrides()
    enriched = []
    for policy in policies:
        override = overrides.get(policy["id"], {})
        merged = {**policy, **override}
        merged["enabled"] = bool(merged.get("enabled", policy["enabled"]))
        # Policy IDs and machine-readable decisions stay stable; user-visible
        # descriptions are generalized at the product boundary so the console
        # does not present historical competition semantics as current scope.
        enriched.append(_genericize_product_scenario(_enrich_policy(merged, impacts)))
    return enriched


def get_scenarios() -> list[dict[str, Any]]:
    return deepcopy(_load_json_list("scenarios.json"))


_PRODUCT_SCENARIO_REPLACEMENTS = (
    ("confidential/competition-teams.csv", "confidential/agent-secrets.json"),
    ("confidential/challenge-seeds.json", "confidential/model-evaluation-secrets.json"),
    ("competition-teams.csv", "agent-secrets.json"),
    ("challenge-seeds.json", "model-evaluation-secrets.json"),
    ("external-audit@example.com", "external-review@example.com"),
    ("outside-review@example.com", "external-review@example.com"),
    ("参赛队伍", "租户业务数据"),
    ("队伍名单", "租户数据清单"),
    ("队伍", "租户"),
    ("赛事", "业务流程"),
    ("赛题", "内部文档"),
    ("提交物", "用户上传文件"),
    ("私有榜单", "管理数据"),
    ("成绩榜", "管理数据"),
    ("榜单", "管理数据"),
    ("校园网", "内部网络"),
    ("训练平台", "模型平台"),
    ("竞赛", "业务"),
    ("比赛", "业务"),
    ("competition", "tenant"),
    ("contest", "business"),
    ("judge_token", "admin_token"),
    ("flag_seed", "secret_seed"),
    ("flag", "secret"),
)


def _genericize_product_scenario(value: Any, *, key: str = "") -> Any:
    """Present the product catalog as generic Agent security, not contest data.

    The original scenarios remain local regression fixtures for reproducibility.
    Overview/catalog responses use this view so a deployed product is not
    coupled to the historical competition story.
    """
    if key in {"id", "surface_id", "target", "risk_hint"}:
        return value
    if isinstance(value, dict):
        return {str(item_key): _genericize_product_scenario(item, key=str(item_key)) for item_key, item in value.items()}
    if isinstance(value, list):
        return [_genericize_product_scenario(item, key=key) for item in value]
    if not isinstance(value, str):
        return value
    text = value
    for source, target in _PRODUCT_SCENARIO_REPLACEMENTS:
        text = text.replace(source, target)
    return text


def get_product_scenarios() -> list[dict[str, Any]]:
    """Return the generic AI-Agent security catalog used by the console."""
    scenarios = get_scenarios()
    result: list[dict[str, Any]] = []
    for scenario in scenarios:
        generic = _genericize_product_scenario(scenario)
        if isinstance(generic, dict):
            generic["profile"] = "agent-security"
            generic["fixture_source"] = "local-sandbox"
        result.append(generic)
    return result


def get_evaluation_ground_truth() -> dict[str, Any]:
    return deepcopy(_load_json_dict("evaluation_ground_truth.json"))


def get_holdout_evaluation_samples() -> dict[str, Any]:
    return deepcopy(_load_json_dict("holdout_evaluation.json"))


def set_policy_enabled(policy_id: str, enabled: bool) -> dict[str, Any]:
    return update_policy(policy_id, {"enabled": enabled}, operator="security-admin", comment="策略启停")


def update_policy(
    policy_id: str,
    updates: dict[str, Any],
    *,
    operator: str = "security-admin",
    comment: str = "",
) -> dict[str, Any]:
    policies = _load_json_list("policies.json")
    overrides = _load_policy_overrides()
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
            _save_policy_overrides(overrides)
            impacts = _load_json_dict("policy_impact.json")
            after = _enrich_policy({**policy, **overrides[policy_id]}, impacts)
            record_policy_version(
                policy_id=policy_id,
                before=before,
                after=after,
                operator=operator,
                comment=comment or "策略配置更新",
            )
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
    before = get_policy_settings()
    settings = _normalize_policy_settings(
        {**before, **{key: value for key, value in updates.items() if key in DEFAULT_POLICY_SETTINGS}}
    )
    if production_security_profile():
        settings["require_agent_capability_registration"] = True
        settings["require_agent_model_registration"] = True
        settings["require_agent_context_registration"] = True
    _save_policy_settings(settings)
    record_policy_version(
        policy_id="__runtime_settings__",
        before=before,
        after=settings,
        operator=str(updates.get("operator", "security-admin")),
        comment=str(updates.get("comment", "运行阈值更新")),
    )
    return settings


def find_scenario(scenario_id: str) -> dict[str, Any]:
    scenarios = _load_json_list("scenarios.json")
    for scenario in scenarios:
        if scenario["id"] == scenario_id:
            return deepcopy(scenario)
    raise KeyError(f"Scenario not found: {scenario_id}")
