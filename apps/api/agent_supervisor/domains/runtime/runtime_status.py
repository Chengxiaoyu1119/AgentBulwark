from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from apps.api.agent_supervisor.adapters.models.model_adapter import provider_status
from apps.api.agent_supervisor.adapters.models.model_runtime_config import runtime_real_api_enabled
from apps.api.agent_supervisor.adapters.proxy.proxy_security import proxy_security_snapshot
from apps.api.agent_supervisor.domains.evidence.gateway_evidence import (
    gateway_code_fingerprint,
    gateway_runtime_evidence,
    gateway_source_fingerprint,
)
from apps.api.agent_supervisor.domains.governance.semantic_detector import semantic_detector_status
from apps.api.agent_supervisor.domains.runtime.security_profile import security_profile
from apps.api.agent_supervisor.mcp_gateway.config import (
    gateway_enabled,
    gateway_guard_enabled,
    gateway_max_sessions,
    gateway_max_subscriptions,
    gateway_mrtr_timeout_seconds,
    gateway_network_mode,
    gateway_resource_limits,
    gateway_routes,
    gateway_session_isolation,
    gateway_timeout_seconds,
    upstream_command,
)
from apps.api.agent_supervisor.mcp_gateway.http_transport import LOG_LEVELS, MODERN_PROTOCOL_VERSION, SUPPORTED_PROTOCOL_VERSIONS
from apps.api.agent_supervisor.paths import MEMORY_DIR, OUTBOX_DIR, RUNTIME_DIR, WORKSPACE_DIR


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    return default if value is None else value.strip().lower() in {"1", "true", "yes", "on"}


def _path_status(path: Path, label: str) -> dict[str, Any]:
    return {"path": label, "exists": path.exists(), "writable": path.exists() and os.access(path, os.W_OK)}


def _cors_origins() -> list[str]:
    configured = [item.strip() for item in os.getenv("AGENT_SUPERVISOR_CORS_ORIGINS", "").split(",") if item.strip()]
    return configured or ["http://127.0.0.1:5178", "http://localhost:5178"]


def build_runtime_status(*, expose_provider_endpoints: bool = True) -> dict[str, Any]:
    models = {profile: provider_status(profile) for profile in ("global", "optimizer", "target")}
    real_model_configured = any(item.get("configured") for group in models.values() for item in group)
    if not expose_provider_endpoints:
        for group in models.values():
            for item in group:
                item.pop("endpoint", None)
    evidence = gateway_runtime_evidence()
    profile = security_profile()
    stream_window = os.getenv("AGENT_SUPERVISOR_PROXY_STREAM_SAFETY_WINDOW_CHARS", "256")
    try:
        stream_window_value = max(64, min(int(stream_window), 4096))
    except ValueError:
        stream_window_value = 256
    snapshot = evidence.get("snapshot") if isinstance(evidence.get("snapshot"), dict) else None
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "backend": {
            "ok": True,
            "service": "agent-security-supervisor",
            "auth_disabled": _env_bool("AGENT_SUPERVISOR_AUTH_DISABLED"),
            "security_profile": profile,
            "cors_origins": _cors_origins(),
            "data_plane": "operational",
            "storage": _path_status(RUNTIME_DIR, "runtime/operational"),
            "workspace": _path_status(WORKSPACE_DIR, "runtime/operational/workspace"),
            "outbox": _path_status(OUTBOX_DIR, "runtime/operational/outbox"),
            "memory": _path_status(MEMORY_DIR, "runtime/operational/memory"),
        },
        "models": {
            "real_api_enabled": runtime_real_api_enabled(_env_bool("MODEL_REAL_API_ENABLED")),
            "real_model_configured": real_model_configured,
            **models,
        },
        "proxy": {
            **proxy_security_snapshot(),
            "mode": os.getenv("AGENT_SUPERVISOR_PROXY_MODE", "transparent"),
            "streaming": {
                "supported": True,
                "mode": "bounded-safety-window",
                "safety_window_chars": stream_window_value,
                "tool_calls_buffered_until_final_supervision": True,
                "reasoning_buffered": True,
            },
        },
        "gateway_evidence": {
            "fingerprint": str(evidence.get("fingerprint") or ""),
            "source_fingerprint": gateway_source_fingerprint(snapshot),
            "code_fingerprint": str(evidence.get("code_fingerprint") or gateway_code_fingerprint(snapshot)),
            "started_at": str(evidence.get("started_at") or ""),
        },
        "semantic_detector": semantic_detector_status(),
        "mcp": {
            "configured": bool(upstream_command()),
            "enabled": gateway_enabled(),
            "guard_enabled": gateway_guard_enabled(),
            "routes": ["default", *gateway_routes().keys()] if upstream_command() else [],
            "timeout_seconds": gateway_timeout_seconds(),
            "resource_limits": gateway_resource_limits(),
            "network_mode": gateway_network_mode(),
            "transport": {
                "mode": "streamable-http",
                "supported_versions": list(SUPPORTED_PROTOCOL_VERSIONS),
                "modern_version": MODERN_PROTOCOL_VERSION,
                "max_subscriptions": gateway_max_subscriptions(),
                "request_logs": {"opt_in": "io.modelcontextprotocol/logLevel", "levels": list(LOG_LEVELS)},
                "mrtr": {
                    "input_required": True,
                    "request_state": "hmac-ttl-single-use",
                    "request_state_secret_configured": bool(os.getenv("MCP_GATEWAY_REQUEST_STATE_SECRET", "").strip() or os.getenv("AGENT_SUPERVISOR_AUDIT_HMAC_KEY", "").strip()),
                    "request_state_ttl_seconds": gateway_mrtr_timeout_seconds(),
                },
            },
            "session_isolation": {
                "enabled": gateway_session_isolation(),
                "scope": "agent+session" if gateway_session_isolation() else "gateway-shared",
                "max_sessions": gateway_max_sessions(),
            },
        },
    }
