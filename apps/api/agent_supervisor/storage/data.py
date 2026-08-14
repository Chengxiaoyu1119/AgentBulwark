from __future__ import annotations

import json
from copy import deepcopy
from typing import Any, cast

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
    "agent_tool_mappings": {},
}


def _load_json(filename: str) -> Any:
    with open(CONFIG_DIR / filename, encoding="utf-8") as f:
        return json.load(f)


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


def _load_policy_overrides() -> dict[str, dict[str, Any]]:
    if not POLICY_OVERRIDES_PATH.exists():
        return {}
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
    return overrides


def _save_policy_overrides(overrides: dict[str, dict[str, Any]]) -> None:
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    tmp_path = POLICY_OVERRIDES_PATH.with_suffix(".tmp")
    tmp_path.write_text(json.dumps(overrides, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp_path.replace(POLICY_OVERRIDES_PATH)


def _load_policy_settings() -> dict[str, Any]:
    if not POLICY_SETTINGS_PATH.exists():
        return dict(DEFAULT_POLICY_SETTINGS)
    try:
        raw = json.loads(POLICY_SETTINGS_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return dict(DEFAULT_POLICY_SETTINGS)
    if not isinstance(raw, dict):
        return dict(DEFAULT_POLICY_SETTINGS)
    settings = _normalize_policy_settings({**DEFAULT_POLICY_SETTINGS, **raw})

    return settings


def _normalize_policy_settings(settings: dict[str, Any]) -> dict[str, Any]:
    settings["anomaly_review_threshold"] = _clamp_int(settings.get("anomaly_review_threshold"), 1, 100)
    settings["anomaly_reject_threshold"] = _clamp_int(settings.get("anomaly_reject_threshold"), 1, 100)
    if settings["anomaly_reject_threshold"] < settings["anomaly_review_threshold"]:
        settings["anomaly_reject_threshold"] = settings["anomaly_review_threshold"]
    settings["approval_sla_minutes"] = _clamp_int(settings.get("approval_sla_minutes"), 1, 24 * 60)
    settings["high_risk_auto_escalation"] = bool(settings.get("high_risk_auto_escalation", True))
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


def _clamp_int(value: Any, min_value: int, max_value: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        number = min_value
    return max(min_value, min(max_value, number))


def get_attack_surfaces() -> list[dict[str, Any]]:
    return deepcopy(_load_json_list("attack_surfaces.json"))


def get_student_competition_attack_map() -> list[dict[str, Any]]:
    return deepcopy(_load_json_list("student_competition_attack_map.json"))


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
        enriched.append(_enrich_policy(merged, impacts))
    return enriched


def get_scenarios() -> list[dict[str, Any]]:
    return deepcopy(_load_json_list("scenarios.json"))


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
    policies = _load_json_list("policies.json")
    overrides = _load_policy_overrides()
    for policy in policies:
        if policy["id"] == policy_id:
            return bool(overrides.get(policy_id, {}).get("enabled", policy["enabled"]))
    return False


def get_policy_settings() -> dict[str, Any]:
    return _load_policy_settings()


def update_policy_settings(updates: dict[str, Any]) -> dict[str, Any]:
    before = _load_policy_settings()
    settings = _normalize_policy_settings(
        {**before, **{key: value for key, value in updates.items() if key in DEFAULT_POLICY_SETTINGS}}
    )
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
