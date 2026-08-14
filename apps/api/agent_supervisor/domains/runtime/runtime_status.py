from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

from apps.api.agent_supervisor.adapters.models.model_adapter import provider_status
from apps.api.agent_supervisor.adapters.models.model_runtime_config import runtime_real_api_enabled
from apps.api.agent_supervisor.adapters.proxy.proxy_security import proxy_security_snapshot
from apps.api.agent_supervisor.domains.attacks.target_lab import target_lab_snapshot
from apps.api.agent_supervisor.paths import MEMORY_DIR, OUTBOX_DIR, SANDBOX_RUNTIME_DIR, WORKSPACE_DIR


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _path_status(path: Path) -> dict:
    return {
        "path": str(path),
        "exists": path.exists(),
        "writable": path.exists() and os.access(path, os.W_OK),
    }


def _cors_origins() -> list[str]:
    configured = [item.strip() for item in os.getenv("AGENT_SUPERVISOR_CORS_ORIGINS", "").split(",") if item.strip()]
    return configured or ["http://127.0.0.1:5178", "http://localhost:5178"]


def build_runtime_status() -> dict:
    target_lab = target_lab_snapshot()
    global_models = provider_status()
    optimizer_models = provider_status("optimizer")
    target_models = provider_status("target")
    real_model_configured = any(
        item.get("configured")
        for item in global_models + optimizer_models + target_models
        if item.get("mode") != "fallback"
    )
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "backend": {
            "ok": True,
            "service": "agent-security-supervisor",
            "auth_disabled": _env_bool("AGENT_SUPERVISOR_AUTH_DISABLED"),
            "cors_origins": _cors_origins(),
        },
        "models": {
            "real_api_enabled": runtime_real_api_enabled(_env_bool("MODEL_REAL_API_ENABLED")),
            "real_model_configured": real_model_configured,
            "global": global_models,
            "optimizer": optimizer_models,
            "target": target_models,
        },
        "sandbox": {
            "ready": WORKSPACE_DIR.exists() and OUTBOX_DIR.exists() and MEMORY_DIR.exists(),
            "runtime": _path_status(SANDBOX_RUNTIME_DIR),
            "workspace": _path_status(WORKSPACE_DIR),
            "outbox": _path_status(OUTBOX_DIR),
            "memory": _path_status(MEMORY_DIR),
            "target_lab": {
                "ready": bool(target_lab.get("version")),
                "state_path": target_lab.get("state_path", ""),
                "api_call_count": target_lab.get("api_call_count", 0),
                "bulk_export_count": target_lab.get("bulk_export_count", 0),
                "sensitive_read_count": target_lab.get("sensitive_read_count", 0),
            },
        },
        "proxy": {
            **proxy_security_snapshot(),
            "optimizer_enabled": _env_bool("AGENT_SUPERVISOR_PROXY_OPTIMIZER_ENABLED", True),
            "force_real_optimizer": _env_bool("AGENT_SUPERVISOR_PROXY_FORCE_REAL_OPTIMIZER", False),
            "force_real_target": _env_bool("AGENT_SUPERVISOR_PROXY_FORCE_REAL_TARGET", False),
            "optimizer_model": os.getenv("AGENT_SUPERVISOR_PROXY_OPTIMIZER_MODEL", ""),
            "target_model": os.getenv("AGENT_SUPERVISOR_PROXY_TARGET_MODEL", ""),
        },
    }
