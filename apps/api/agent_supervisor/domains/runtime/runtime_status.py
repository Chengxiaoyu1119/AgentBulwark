from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

from apps.api.agent_supervisor.adapters.models.model_adapter import provider_status
from apps.api.agent_supervisor.adapters.models.model_runtime_config import runtime_real_api_enabled
from apps.api.agent_supervisor.adapters.proxy.proxy_security import proxy_security_snapshot
from apps.api.agent_supervisor.domains.governance.semantic_detector import semantic_detector_status
from apps.api.agent_supervisor.domains.reports.gateway_evidence import (
    gateway_code_fingerprint,
    gateway_runtime_evidence,
    gateway_source_fingerprint,
)
from apps.api.agent_supervisor.domains.runtime.lab_access import labs_enabled
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
from apps.api.agent_supervisor.paths import MEMORY_DIR, OUTBOX_DIR, RUNTIME_DIR, SANDBOX_RUNTIME_DIR, WORKSPACE_DIR


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _path_status(path: Path, label: str) -> dict:
    return {
        # Runtime status is observable by read-only integrations.  Returning
        # absolute paths would disclose usernames, checkout locations and
        # custom runtime directories without adding operational value.
        "path": label,
        "exists": path.exists(),
        "writable": path.exists() and os.access(path, os.W_OK),
    }


def _cors_origins() -> list[str]:
    configured = [item.strip() for item in os.getenv("AGENT_SUPERVISOR_CORS_ORIGINS", "").split(",") if item.strip()]
    return configured or ["http://127.0.0.1:5178", "http://localhost:5178"]


def build_runtime_status(*, expose_provider_endpoints: bool = True) -> dict:
    current_labs_enabled = labs_enabled()
    target_lab: dict = {}
    if current_labs_enabled:
        from apps.api.agent_supervisor.domains.attacks.target_lab import target_lab_snapshot

        target_lab = target_lab_snapshot()
    global_models = provider_status()
    optimizer_models = provider_status("optimizer")
    target_models = provider_status("target")
    real_model_configured = any(
        item.get("configured")
        for item in global_models + optimizer_models + target_models
        if item.get("mode") != "fallback"
    )
    if not expose_provider_endpoints:
        for group in (global_models, optimizer_models, target_models):
            for item in group:
                item.pop("endpoint", None)

    gateway_evidence = gateway_runtime_evidence()
    current_security_profile = security_profile()
    research_mode_allowed = (
        current_security_profile != "production"
        and _env_bool("AGENT_SUPERVISOR_PROXY_ALLOW_RESEARCH_MODE")
    )

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "backend": {
            "ok": True,
            "service": "agent-security-supervisor",
            "auth_disabled": _env_bool("AGENT_SUPERVISOR_AUTH_DISABLED"),
            "security_profile": current_security_profile,
            "cors_origins": _cors_origins(),
            "data_plane": "operational",
            "labs_enabled": current_labs_enabled,
            "storage": _path_status(RUNTIME_DIR, "runtime/operational"),
        },
        "models": {
            "real_api_enabled": runtime_real_api_enabled(_env_bool("MODEL_REAL_API_ENABLED")),
            "real_model_configured": real_model_configured,
            "global": global_models,
            "optimizer": optimizer_models,
            "target": target_models,
        },
        "sandbox": {
            "labs_enabled": current_labs_enabled,
            "ready": WORKSPACE_DIR.exists() and OUTBOX_DIR.exists() and MEMORY_DIR.exists(),
            "agent_runtime": _path_status(RUNTIME_DIR / "agents", "runtime/operational/agents"),
            "runtime": _path_status(SANDBOX_RUNTIME_DIR, "sandbox/runtime"),
            "workspace": _path_status(WORKSPACE_DIR, "sandbox/runtime/workspace"),
            "outbox": _path_status(OUTBOX_DIR, "sandbox/runtime/outbox"),
            "memory": _path_status(MEMORY_DIR, "sandbox/runtime/memory"),
            "target_lab": {
                "enabled": current_labs_enabled,
                "ready": bool(target_lab.get("version")),
                "state_path": "sandbox/runtime/target_lab/agent_security_fixture.json"
                if target_lab.get("state_path")
                else "",
                "api_call_count": target_lab.get("api_call_count", 0),
                "bulk_export_count": target_lab.get("bulk_export_count", 0),
                "sensitive_read_count": target_lab.get("sensitive_read_count", 0),
            },
        },
        "proxy": {
            **proxy_security_snapshot(),
            "mode": os.getenv("AGENT_SUPERVISOR_PROXY_MODE", "transparent"),
            # Research mode contains prompt rewriting and is never a
            # production gateway capability, even if a stale environment flag
            # remains set.  Expose the effective posture, not the raw switch.
            "research_mode_allowed": research_mode_allowed,
            "streaming": {
                "supported": True,
                "mode": "bounded-safety-window",
                "safety_window_chars": max(
                    64,
                    min(
                        int(os.getenv("AGENT_SUPERVISOR_PROXY_STREAM_SAFETY_WINDOW_CHARS", "256"))
                        if os.getenv("AGENT_SUPERVISOR_PROXY_STREAM_SAFETY_WINDOW_CHARS", "256").isdigit()
                        else 256,
                        4096,
                    ),
                ),
                "tool_calls_buffered_until_final_supervision": True,
                "reasoning_buffered": True,
            },
            "optimizer_enabled": _env_bool("AGENT_SUPERVISOR_PROXY_OPTIMIZER_ENABLED", True),
            "force_real_optimizer": _env_bool("AGENT_SUPERVISOR_PROXY_FORCE_REAL_OPTIMIZER", False),
            "force_real_target": _env_bool("AGENT_SUPERVISOR_PROXY_FORCE_REAL_TARGET", False),
            "optimizer_model": os.getenv("AGENT_SUPERVISOR_PROXY_OPTIMIZER_MODEL", ""),
            "target_model": os.getenv("AGENT_SUPERVISOR_PROXY_TARGET_MODEL", ""),
        },
        "gateway_evidence": {
            "fingerprint": str(gateway_evidence.get("fingerprint") or ""),
            "source_fingerprint": gateway_source_fingerprint(
                gateway_evidence.get("snapshot") if isinstance(gateway_evidence.get("snapshot"), dict) else None
            ),
            "code_fingerprint": str(
                gateway_evidence.get("code_fingerprint")
                or gateway_code_fingerprint(
                    gateway_evidence.get("snapshot") if isinstance(gateway_evidence.get("snapshot"), dict) else None
                )
            ),
            "started_at": str(gateway_evidence.get("started_at") or ""),
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
            "upstream_environment": "minimal-allowlist",
            "transport": {
                "mode": "streamable-http-dual-era",
                "supported_versions": list(SUPPORTED_PROTOCOL_VERSIONS),
                "modern_version": MODERN_PROTOCOL_VERSION,
                "request_metadata": "protocolVersion+clientCapabilities required; clientInfo optional",
                "server_discover": True,
                "subscriptions_listen": True,
                "max_subscriptions": gateway_max_subscriptions(),
                "legacy_initialize_bridge": True,
                "request_logs": {
                    "opt_in": "io.modelcontextprotocol/logLevel",
                    "levels": list(LOG_LEVELS),
                    "lower_severity_filtered": True,
                },
                "mrtr": {
                    "input_required": True,
                    "request_state": "hmac-ttl-single-use",
                    "request_state_secret_configured": bool(os.getenv("MCP_GATEWAY_REQUEST_STATE_SECRET", "").strip() or os.getenv("AGENT_SUPERVISOR_AUDIT_HMAC_KEY", "").strip()),
                    "request_state_ttl_seconds": gateway_mrtr_timeout_seconds(),
                    "request_state_replay_scope": "process",
                },
            },
            "session_isolation": {
                "enabled": gateway_session_isolation(),
                "scope": "agent+session" if gateway_session_isolation() else "gateway-shared",
                "max_sessions": gateway_max_sessions(),
                "child_process_per_session": gateway_session_isolation(),
            },
        },
    }
