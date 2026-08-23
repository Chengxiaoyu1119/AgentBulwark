from __future__ import annotations

import json
import os
from typing import Any

from apps.api.agent_supervisor.paths import RUNTIME_DIR

MODEL_RUNTIME_CONFIG_PATH = RUNTIME_DIR / "model_runtime_config.json"

PROVIDER_LABELS = {
    "openai-compatible": "OpenAI 兼容接口",
    "deepseek": "DeepSeek",
    "zhipu": "智谱",
}
ALLOWED_PROVIDERS = tuple(PROVIDER_LABELS)
PROFILE_IDS = ("global", "optimizer", "target")
DEFAULT_PROFILE_PRIORITIES = {
    "global": ["openai-compatible", "deepseek", "zhipu"],
    "optimizer": ["zhipu", "deepseek", "openai-compatible"],
    "target": ["deepseek", "zhipu", "openai-compatible"],
}


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _normalize_profile(profile: str = "") -> str:
    normalized = profile.strip().lower()
    return normalized if normalized in PROFILE_IDS else "global"


def normalize_provider_priority(value: Any, fallback: list[str] | None = None) -> list[str]:
    if isinstance(value, str):
        raw_items = value.split(",")
    elif isinstance(value, list):
        raw_items = value
    else:
        raw_items = []
    priority: list[str] = []
    for item in raw_items:
        provider = str(item).strip().lower()
        if provider in ALLOWED_PROVIDERS and provider not in priority:
            priority.append(provider)
    if priority:
        return priority
    return list(fallback or [])


def _sanitize_model_overrides(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    overrides: dict[str, str] = {}
    for key, raw_model in value.items():
        provider = str(key).strip().lower()
        if provider not in ALLOWED_PROVIDERS:
            continue
        model = str(raw_model or "").strip().replace("\r", "").replace("\n", "")[:160]
        if model:
            overrides[provider] = model
    return overrides


def _load_raw_config() -> dict[str, Any]:
    if not MODEL_RUNTIME_CONFIG_PATH.exists():
        return {}
    try:
        raw = json.loads(MODEL_RUNTIME_CONFIG_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return raw if isinstance(raw, dict) else {}


def _save_raw_config(config: dict[str, Any]) -> None:
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    tmp_path = MODEL_RUNTIME_CONFIG_PATH.with_suffix(".tmp")
    tmp_path.write_text(json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp_path.replace(MODEL_RUNTIME_CONFIG_PATH)


def runtime_real_api_enabled(default: bool) -> bool:
    raw = _load_raw_config().get("real_api_enabled")
    return raw if isinstance(raw, bool) else default


def runtime_provider_priority(profile: str = "") -> list[str] | None:
    profile_id = _normalize_profile(profile)
    raw_profiles = _load_raw_config().get("profiles")
    if not isinstance(raw_profiles, dict):
        return None
    raw_profile = raw_profiles.get(profile_id)
    if not isinstance(raw_profile, dict):
        return None
    priority = normalize_provider_priority(raw_profile.get("provider_priority"))
    return priority or None


def runtime_model_override(profile: str, provider: str) -> str:
    profile_id = _normalize_profile(profile)
    provider_id = provider.strip().lower()
    raw_profiles = _load_raw_config().get("profiles")
    if not isinstance(raw_profiles, dict):
        return ""
    raw_profile = raw_profiles.get(profile_id)
    if not isinstance(raw_profile, dict):
        return ""
    overrides = _sanitize_model_overrides(raw_profile.get("model_overrides"))
    return overrides.get(provider_id, "")


def effective_provider_priority(profile: str = "", env_value: str | None = None) -> list[str]:
    profile_id = _normalize_profile(profile)
    runtime_priority = runtime_provider_priority(profile_id)
    if runtime_priority:
        return runtime_priority
    env_priority = normalize_provider_priority(env_value)
    if env_priority:
        return env_priority
    return list(DEFAULT_PROFILE_PRIORITIES[profile_id])


def get_model_runtime_config() -> dict[str, Any]:
    raw = _load_raw_config()
    raw_profiles = raw.get("profiles") if isinstance(raw.get("profiles"), dict) else {}
    profiles: dict[str, dict[str, Any]] = {}
    for profile_id in PROFILE_IDS:
        raw_profile = raw_profiles.get(profile_id) if isinstance(raw_profiles, dict) else {}
        raw_profile = raw_profile if isinstance(raw_profile, dict) else {}
        profiles[profile_id] = {
            "provider_priority": effective_provider_priority(profile_id),
            "model_overrides": _sanitize_model_overrides(raw_profile.get("model_overrides")),
        }
    real_api_override = raw.get("real_api_enabled")
    return {
        "real_api_enabled": runtime_real_api_enabled(_env_bool("MODEL_REAL_API_ENABLED", False)),
        "real_api_enabled_source": "runtime" if isinstance(real_api_override, bool) else "env",
        "allowed_providers": [{"id": key, "label": label} for key, label in PROVIDER_LABELS.items()],
        "profiles": profiles,
        # The config endpoint is readable by observer credentials.  Expose a
        # stable logical location rather than the host's absolute path.
        "config_path": "runtime/model_runtime_config.json",
    }


def update_model_runtime_config(updates: dict[str, Any]) -> dict[str, Any]:
    current = _load_raw_config()
    next_config: dict[str, Any] = dict(current)
    if isinstance(updates.get("real_api_enabled"), bool):
        next_config["real_api_enabled"] = updates["real_api_enabled"]

    raw_profiles = next_config.get("profiles")
    profiles: dict[str, Any] = raw_profiles if isinstance(raw_profiles, dict) else {}
    update_profiles = updates.get("profiles")
    if isinstance(update_profiles, dict):
        for profile_key, profile_update in update_profiles.items():
            profile_id = _normalize_profile(str(profile_key))
            if not isinstance(profile_update, dict):
                continue
            current_profile = profiles.get(profile_id)
            current_profile = dict(current_profile) if isinstance(current_profile, dict) else {}
            if "provider_priority" in profile_update:
                priority = normalize_provider_priority(profile_update.get("provider_priority"))
                if priority:
                    current_profile["provider_priority"] = priority
            if "model_overrides" in profile_update:
                merged_overrides = _sanitize_model_overrides(current_profile.get("model_overrides"))
                for provider, model in _sanitize_model_overrides(profile_update.get("model_overrides")).items():
                    merged_overrides[provider] = model
                for provider, raw_model in dict(profile_update.get("model_overrides") or {}).items():
                    provider_id = str(provider).strip().lower()
                    if provider_id in ALLOWED_PROVIDERS and not str(raw_model or "").strip():
                        merged_overrides.pop(provider_id, None)
                current_profile["model_overrides"] = merged_overrides
            profiles[profile_id] = current_profile
    next_config["profiles"] = profiles
    _save_raw_config(next_config)
    return get_model_runtime_config()
