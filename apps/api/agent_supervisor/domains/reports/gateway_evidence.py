"""Current-code fingerprint for OpenAI/MCP gateway evidence.

The gateway probe is a persisted release artifact.  A probe can be internally
consistent and still describe an older checkout, policy file, or gateway
configuration.  This module provides one small, secret-free fingerprint that
the probe writer and the readiness reader can calculate independently.
"""

from __future__ import annotations

import hashlib
import json
import os
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
from threading import Lock
from typing import Any, Iterator

from apps.api.agent_supervisor.domains.runtime.security_profile import security_profile
from apps.api.agent_supervisor.paths import REPO_ROOT, RUNTIME_DIR

GATEWAY_EVIDENCE_SOURCE_FILES: tuple[str, ...] = (
    # HTTP authentication, role scoping and router registration are part of
    # the boundary just as much as the Provider adapter itself.  Omitting one
    # of these files would allow a changed enforcement layer to reuse an old
    # green probe.
    "apps/api/agent_supervisor/auth.py",
    "apps/api/agent_supervisor/main.py",
    "apps/api/agent_supervisor/routers/core.py",
    "apps/api/agent_supervisor/routers/evaluations.py",
    "apps/api/agent_supervisor/routers/proxy.py",
    "apps/api/agent_supervisor/routers/mcp.py",
    # Persisted release evidence is only trustworthy while both the probe
    # writer and its readiness verifier are bound to the same contract.
    "apps/api/agent_supervisor/commands/cli.py",
    "apps/api/agent_supervisor/domains/reports/readiness_checks.py",
    "apps/api/agent_supervisor/adapters/proxy/openai_proxy.py",
    "apps/api/agent_supervisor/adapters/proxy/proxy_security.py",
    "apps/api/agent_supervisor/adapters/proxy/responses_compat.py",
    "apps/api/agent_supervisor/adapters/proxy/resource_governance.py",
    "apps/api/agent_supervisor/adapters/models/model_adapter.py",
    "apps/api/agent_supervisor/adapters/models/model_runtime_config.py",
    "apps/api/agent_supervisor/domains/governance/integrity.py",
    "apps/api/agent_supervisor/domains/governance/approvals.py",
    "apps/api/agent_supervisor/domains/governance/redaction.py",
    "apps/api/agent_supervisor/domains/governance/skill_scanner.py",
    "apps/api/agent_supervisor/domains/governance/anomaly.py",
    "apps/api/agent_supervisor/domains/governance/correlation.py",
    "apps/api/agent_supervisor/domains/governance/risk_score.py",
    "apps/api/agent_supervisor/domains/governance/semantic_detector.py",
    "apps/api/agent_supervisor/domains/governance/supervisor.py",
    "apps/api/agent_supervisor/domains/governance/tool_contract.py",
    "apps/api/agent_supervisor/domains/governance/tool_registry.py",
    "apps/api/agent_supervisor/domains/evaluations/outcomes.py",
    "apps/api/agent_supervisor/domains/attacks/target_lab.py",
    "apps/api/agent_supervisor/domains/runtime/execution_receipts.py",
    # The generic Agent event path is also used to persist Provider response
    # audits and the supervisor-owned execution contract.  It must participate
    # in the startup fingerprint so a changed execution boundary cannot reuse
    # an older green HTTP probe.
    "apps/api/agent_supervisor/domains/runtime/events.py",
    # Same-request baseline/protected comparison is an evidence-producing
    # gateway surface.  A probe generated before its authorization or
    # persistence rules changed must not be accepted as current evidence.
    "apps/api/agent_supervisor/domains/runtime/gateway_comparison.py",
    "apps/api/agent_supervisor/domains/runtime/gateway_execution.py",
    "apps/api/agent_supervisor/domains/runtime/agent_credentials.py",
    "apps/api/agent_supervisor/domains/runtime/route_scope.py",
    "apps/api/agent_supervisor/domains/runtime/security_profile.py",
    "apps/api/agent_supervisor/domains/runtime/server_security.py",
    "apps/api/agent_supervisor/domains/runtime/tools.py",
    "apps/api/agent_supervisor/domains/runtime/request_limits.py",
    "apps/api/agent_supervisor/domains/runtime/app_lifespan.py",
    "apps/api/agent_supervisor/domains/runtime/runtime_status.py",
    "apps/api/agent_supervisor/domains/runtime/mcp_access.py",
    "apps/api/agent_supervisor/domains/runtime/event_stream.py",
    "apps/api/agent_supervisor/domains/reports/gateway_evidence.py",
    "apps/api/agent_supervisor/mcp_gateway/config.py",
    "apps/api/agent_supervisor/mcp_gateway/audit.py",
    "apps/api/agent_supervisor/mcp_gateway/gateway.py",
    "apps/api/agent_supervisor/mcp_gateway/http_transport.py",
    "apps/api/agent_supervisor/mcp_gateway/interceptor.py",
    "apps/api/agent_supervisor/mcp_gateway/mrtr.py",
    "apps/api/agent_supervisor/mcp_gateway/router.py",
    "apps/api/agent_supervisor/mcp_gateway/subscriptions.py",
    "apps/api/agent_supervisor/mcp_gateway/upstream.py",
    "apps/api/agent_supervisor/storage/data.py",
    "apps/api/agent_supervisor/storage/database.py",
    "apps/api/agent_supervisor/routers/integrations.py",
    "apps/api/agent_supervisor/schemas/main_models.py",
    "apps/api/agent_supervisor/config/policies.json",
)

GATEWAY_EVIDENCE_SECURITY_ENV: tuple[str, ...] = (
    "AGENT_SUPERVISOR_PROXY_MODE",
    "AGENT_SUPERVISOR_AUTH_DISABLED",
    "AGENT_SUPERVISOR_TRUST_PROXY_HEADERS",
    "AGENT_SUPERVISOR_PROXY_ALLOW_LOCAL_UNAUTHENTICATED",
    "AGENT_SUPERVISOR_PROXY_ALLOW_UNAUTHENTICATED_PUBLIC",
    "AGENT_SUPERVISOR_PROXY_REQUIRE_TOOL_RECEIPTS",
    "AGENT_SUPERVISOR_PROXY_REQUIRE_SERVER_OBSERVED_RECEIPTS",
    "AGENT_SUPERVISOR_PROXY_ALLOW_PROVIDER_FAILOVER",
    "AGENT_SUPERVISOR_PROXY_ALLOW_MODEL_OVERRIDE",
    "AGENT_SUPERVISOR_PROXY_ALLOW_RESEARCH_MODE",
    "AGENT_SUPERVISOR_PROXY_OPTIMIZER_ENABLED",
    "AGENT_SUPERVISOR_PROXY_FORCE_REAL_OPTIMIZER",
    "AGENT_SUPERVISOR_PROXY_FORCE_REAL_TARGET",
    "AGENT_SUPERVISOR_PROXY_EXPOSE_REASONING",
    "AGENT_SUPERVISOR_PROXY_RATE_LIMIT_PER_MINUTE",
    "AGENT_SUPERVISOR_PROXY_RATE_LIMIT_MAX_KEYS",
    "AGENT_SUPERVISOR_PROXY_RESOURCE_GOVERNANCE_ENABLED",
    "AGENT_SUPERVISOR_PROXY_MAX_CONCURRENCY_PER_AGENT",
    "AGENT_SUPERVISOR_PROXY_TOKEN_BUDGET_PER_MINUTE",
    "AGENT_SUPERVISOR_PROXY_COST_BUDGET_PER_MINUTE_USD",
    "AGENT_SUPERVISOR_PROXY_DEFAULT_OUTPUT_TOKENS",
    "AGENT_SUPERVISOR_PROXY_MANAGED_CONTEXT_TOKENS",
    "AGENT_SUPERVISOR_PROXY_INPUT_COST_PER_1K_USD",
    "AGENT_SUPERVISOR_PROXY_OUTPUT_COST_PER_1K_USD",
    "AGENT_SUPERVISOR_PROXY_RESOURCE_MAX_KEYS",
    "AGENT_SUPERVISOR_PROXY_MAX_TOOL_ROUNDS",
    "AGENT_SUPERVISOR_ALLOW_SHARED_EXECUTOR_TOKEN",
    "AGENT_SUPERVISOR_DEFAULT_ROLE",
    "AGENT_SUPERVISOR_SECURITY_PROFILE",
    "AGENT_SUPERVISOR_API_TOKEN_OBSERVER",
    "AGENT_SUPERVISOR_API_TOKEN_EXECUTOR",
    "AGENT_SUPERVISOR_API_TOKEN_ANALYST",
    "AGENT_SUPERVISOR_API_TOKEN_ADMIN",
    "AGENT_SUPERVISOR_AGENT_TOKENS_JSON",
    "MCP_GATEWAY_GUARD_ENABLED",
    "MCP_GATEWAY_ENABLED",
    "MCP_GATEWAY_SERVER_NAME",
    "MCP_GATEWAY_TIMEOUT_SECONDS",
    "MCP_GATEWAY_ALLOW_SIDE_EFFECT_NOTIFICATIONS",
    "MCP_GATEWAY_NETWORK_MODE",
    "MCP_GATEWAY_RESOURCE_LIMITS_ENABLED",
    "MCP_GATEWAY_MAX_MESSAGE_BYTES",
    "MCP_GATEWAY_MAX_PENDING_RESPONSES",
)

# These values define which executable and working directory sit behind the
# MCP enforcement boundary.  They may contain command-line secrets, so keep
# only presence and a digest in evidence; a stale probe must still become
# invalid when an operator swaps the upstream or route table.
GATEWAY_EVIDENCE_MCP_SECRET_ENV: tuple[str, ...] = (
    "MCP_GATEWAY_UPSTREAM_COMMAND",
    "MCP_GATEWAY_ROUTES_JSON",
    "MCP_GATEWAY_UPSTREAM_CWD",
    "MCP_GATEWAY_UPSTREAM_ENV_ALLOWLIST",
)

# Provider routing and runtime policy are part of the security boundary even
# though they are not source files.  A probe bound only to Python source could
# be replayed after an operator changed the upstream host, model binding, or a
# persisted allowlist.  Keep values that are useful to operators (model IDs,
# priorities, feature switches) and represent URL/command/key material only by
# presence plus a digest.  No secret or endpoint is emitted in the evidence
# payload.
GATEWAY_EVIDENCE_PROVIDER_ENV: tuple[str, ...] = (
    "MODEL_REAL_API_ENABLED",
    "MODEL_PROVIDER_PRIORITY",
    "TARGET_MODEL_PROVIDER_PRIORITY",
    "TARGET_REAL_MODEL_PROVIDER",
    "REAL_MODEL_EVALUATION_PROVIDER",
    "OPENAI_COMPATIBLE_API_KEY",
    "OPENAI_COMPATIBLE_BASE_URL",
    "OPENAI_COMPATIBLE_MODEL",
    "DEEPSEEK_API_KEY",
    "DEEPSEEK_BASE_URL",
    "DEEPSEEK_MODEL",
    "ZHIPU_API_KEY",
    "ZHIPU_API_URL",
    "ZHIPU_MODEL",
    "TARGET_OPENAI_COMPATIBLE_API_KEY",
    "TARGET_OPENAI_COMPATIBLE_BASE_URL",
    "TARGET_OPENAI_COMPATIBLE_MODEL",
    "TARGET_DEEPSEEK_API_KEY",
    "TARGET_DEEPSEEK_BASE_URL",
    "TARGET_DEEPSEEK_MODEL",
    "TARGET_ZHIPU_API_KEY",
    "TARGET_ZHIPU_API_URL",
    "TARGET_ZHIPU_MODEL",
    "AGENT_SUPERVISOR_PROXY_TARGET_MODEL",
)

GATEWAY_EVIDENCE_RUNTIME_FILES: tuple[str, ...] = (
    "policy_settings.json",
    "policy_overrides.json",
    "model_runtime_config.json",
)

_RUNTIME_EVIDENCE_LOCK = Lock()
_RUNTIME_EVIDENCE: dict[str, Any] | None = None
_SCOPED_GATEWAY_EVIDENCE: ContextVar[dict[str, Any] | None] = ContextVar(
    "scoped_gateway_evidence",
    default=None,
)


def _digest_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _provider_evidence_config() -> dict[str, Any]:
    config: dict[str, Any] = {}
    for name in GATEWAY_EVIDENCE_PROVIDER_ENV:
        value = os.getenv(name, "").strip()
        upper_name = name.upper()
        if "API_KEY" in upper_name:
            config[name] = {"configured": bool(value)}
        elif any(marker in upper_name for marker in ("BASE_URL", "API_URL")):
            config[name] = {
                "configured": bool(value),
                "sha256": _digest_text(value) if value else "",
            }
        else:
            config[name] = value[:200]
    return config


def _mcp_evidence_config() -> dict[str, Any]:
    from apps.api.agent_supervisor.mcp_gateway.config import (
        gateway_allow_side_effect_notifications,
        gateway_enabled,
        gateway_guard_enabled,
        gateway_max_sessions,
        gateway_max_subscriptions,
        gateway_mrtr_timeout_seconds,
        gateway_network_mode,
        gateway_resource_limits,
        gateway_server_name,
        gateway_session_isolation,
        gateway_timeout_seconds,
    )

    config: dict[str, Any] = {}
    for name in GATEWAY_EVIDENCE_MCP_SECRET_ENV:
        value = os.getenv(name, "").strip()
        config[name] = {
            "configured": bool(value),
            "sha256": _digest_text(value) if value else "",
        }
    explicit_state_secret = os.getenv("MCP_GATEWAY_REQUEST_STATE_SECRET", "").strip()
    audit_hmac_fallback = os.getenv("AGENT_SUPERVISOR_AUDIT_HMAC_KEY", "").strip()
    config["effective"] = {
        "enabled": gateway_enabled(),
        "guard_enabled": gateway_guard_enabled(),
        "allow_side_effect_notifications": gateway_allow_side_effect_notifications(),
        "network_mode": gateway_network_mode(),
        "session_isolation": gateway_session_isolation(),
        "max_sessions": gateway_max_sessions(),
        "max_subscriptions": gateway_max_subscriptions(),
        "request_state_timeout_seconds": gateway_mrtr_timeout_seconds(),
        "request_state_key_source": (
            "explicit"
            if explicit_state_secret
            else "audit-hmac-fallback"
            if audit_hmac_fallback
            else "ephemeral"
        ),
        "request_state_key_persistent": bool(explicit_state_secret or audit_hmac_fallback),
        "timeout_seconds": gateway_timeout_seconds(),
        "server_name": gateway_server_name(),
        "resource_limits": gateway_resource_limits(),
    }
    return config


def _runtime_file_digests() -> dict[str, str | None]:
    digests: dict[str, str | None] = {}
    for name in GATEWAY_EVIDENCE_RUNTIME_FILES:
        path = RUNTIME_DIR / name
        try:
            digests[f"runtime/{name}"] = _digest_text(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError):
            digests[f"runtime/{name}"] = None
    return digests


def _effective_execution_evidence_config() -> dict[str, Any]:
    """Normalize the receipt trust boundary for server/CLI fingerprinting.

    Raw environment values are insufficient evidence because production makes
    the server-observed invariant mandatory even when the compatibility switch
    contains ``false``.  Persist the effective policy so a probe from a weaker
    runtime cannot be reused after the deployment posture changes.
    """

    profile = security_profile()
    raw_server_observed = os.getenv(
        "AGENT_SUPERVISOR_PROXY_REQUIRE_SERVER_OBSERVED_RECEIPTS",
        "",
    ).strip().lower()
    server_observed_required = profile == "production" or raw_server_observed in {
        "1",
        "true",
        "yes",
        "on",
    }
    raw_receipts = os.getenv("AGENT_SUPERVISOR_PROXY_REQUIRE_TOOL_RECEIPTS")
    tool_receipts_required = (
        True
        if raw_receipts is None
        else raw_receipts.strip().lower() in {"1", "true", "yes", "on"}
    ) or server_observed_required
    return {
        "security_profile": profile,
        "tool_receipts_required": tool_receipts_required,
        "server_observed_receipts_required": server_observed_required,
    }


def _build_gateway_evidence_snapshot() -> dict[str, Any]:
    """Return a deterministic, non-secret snapshot of the gateway boundary."""

    source_files: dict[str, str | None] = {}
    for relative_path in GATEWAY_EVIDENCE_SOURCE_FILES:
        path = REPO_ROOT / relative_path
        try:
            source_files[relative_path] = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError:
            source_files[relative_path] = None
    # Keep secrets out of evidence while still binding the fingerprint to the
    # authorization posture that controls who may create Provider traffic.
    # Presence, role names and Agent IDs are security-relevant; raw token values
    # are intentionally represented only by a boolean/shape summary.
    raw_agent_tokens = os.getenv("AGENT_SUPERVISOR_AGENT_TOKENS_JSON", "")
    try:
        parsed_agent_tokens = json.loads(raw_agent_tokens) if raw_agent_tokens.strip() else {}
    except json.JSONDecodeError:
        parsed_agent_tokens = {"<invalid>": ""}
    agent_ids = sorted(str(key) for key in parsed_agent_tokens) if isinstance(parsed_agent_tokens, dict) else ["<invalid>"]
    security_config: dict[str, Any] = {
        name: os.getenv(name, "")
        for name in GATEWAY_EVIDENCE_SECURITY_ENV
        if name not in {
            "AGENT_SUPERVISOR_API_TOKEN_OBSERVER",
            "AGENT_SUPERVISOR_API_TOKEN_EXECUTOR",
            "AGENT_SUPERVISOR_API_TOKEN_ANALYST",
            "AGENT_SUPERVISOR_API_TOKEN_ADMIN",
            "AGENT_SUPERVISOR_AGENT_TOKENS_JSON",
        }
    }
    security_config.update(
        {
            "AGENT_SUPERVISOR_API_TOKEN_CONFIGURED": bool(os.getenv("AGENT_SUPERVISOR_API_TOKEN", "").strip()),
            "AGENT_SUPERVISOR_API_TOKEN_OBSERVER_CONFIGURED": bool(os.getenv("AGENT_SUPERVISOR_API_TOKEN_OBSERVER", "").strip()),
            "AGENT_SUPERVISOR_API_TOKEN_EXECUTOR_CONFIGURED": bool(os.getenv("AGENT_SUPERVISOR_API_TOKEN_EXECUTOR", "").strip()),
            "AGENT_SUPERVISOR_API_TOKEN_ANALYST_CONFIGURED": bool(os.getenv("AGENT_SUPERVISOR_API_TOKEN_ANALYST", "").strip()),
            "AGENT_SUPERVISOR_API_TOKEN_ADMIN_CONFIGURED": bool(os.getenv("AGENT_SUPERVISOR_API_TOKEN_ADMIN", "").strip()),
            "AGENT_SUPERVISOR_AGENT_TOKEN_IDS": agent_ids,
            "AGENT_SUPERVISOR_AGENT_TOKEN_COUNT": len(agent_ids) if agent_ids != ["<invalid>"] else 0,
            "AGENT_SUPERVISOR_AGENT_TOKENS_CONFIGURED": bool(raw_agent_tokens.strip()),
        }
    )
    return {
        "schema_version": "agent-supervisor.gateway-evidence-fingerprint.v1",
        "source_files": source_files,
        "execution_evidence_config": _effective_execution_evidence_config(),
        "security_config": security_config,
        "provider_config": _provider_evidence_config(),
        "mcp_config": _mcp_evidence_config(),
        "runtime_files": _runtime_file_digests(),
    }


def gateway_evidence_snapshot() -> dict[str, Any]:
    """Return a current snapshot, reusing the active readiness scope."""

    scoped = _SCOPED_GATEWAY_EVIDENCE.get()
    return scoped if scoped is not None else _build_gateway_evidence_snapshot()


@contextmanager
def gateway_evidence_snapshot_scope() -> Iterator[dict[str, Any]]:
    """Pin one source/config snapshot for a multi-artifact readiness read.

    A readiness report may inspect hundreds of candidate probe files.  Every
    candidate still gets compared against the same point-in-time snapshot, but
    the gateway source and deployment files are read only once per report.
    Direct fingerprint callers remain uncached outside this explicit scope.
    """

    current = _SCOPED_GATEWAY_EVIDENCE.get()
    if current is not None:
        yield current
        return
    snapshot = _build_gateway_evidence_snapshot()
    token = _SCOPED_GATEWAY_EVIDENCE.set(snapshot)
    try:
        yield snapshot
    finally:
        _SCOPED_GATEWAY_EVIDENCE.reset(token)


def gateway_evidence_fingerprint(snapshot: dict[str, Any] | None = None) -> str:
    """Hash the current gateway source/config snapshot for probe binding."""

    payload = snapshot if snapshot is not None else gateway_evidence_snapshot()
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def gateway_source_fingerprint(snapshot: dict[str, Any] | None = None) -> str:
    """Hash the gateway source and secret-free deployment configuration.

    The full evidence fingerprint also includes the running authorization
    posture.  That is useful for describing a deployment, but it is not a
    stable identity for a client-side probe: the API process may receive
    short-lived Agent tokens or deployment-only credentials that are
    intentionally absent from the CLI process.  This boundary fingerprint
    therefore binds source files, Provider routing/model configuration and
    persisted runtime policy digests, while deliberately excluding raw
    credentials.  A probe from a different upstream or policy snapshot cannot
    be reused as current evidence.
    """

    payload = snapshot if snapshot is not None else gateway_evidence_snapshot()
    source_files = payload.get("source_files") if isinstance(payload, dict) else None
    provider_config = payload.get("provider_config") if isinstance(payload, dict) else None
    mcp_config = payload.get("mcp_config") if isinstance(payload, dict) else None
    runtime_files = payload.get("runtime_files") if isinstance(payload, dict) else None
    execution_evidence_config = payload.get("execution_evidence_config") if isinstance(payload, dict) else None
    canonical = json.dumps(
        {
            "schema_version": "agent-supervisor.gateway-source-fingerprint.v3",
            "source_files": source_files if isinstance(source_files, dict) else {},
            "execution_evidence_config": (
                execution_evidence_config if isinstance(execution_evidence_config, dict) else {}
            ),
            "provider_config": provider_config if isinstance(provider_config, dict) else {},
            "mcp_config": mcp_config if isinstance(mcp_config, dict) else {},
            "runtime_files": runtime_files if isinstance(runtime_files, dict) else {},
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def gateway_code_fingerprint(snapshot: dict[str, Any] | None = None) -> str:
    """Hash the immutable code/contract identity used by probe validation.

    ``gateway_source_fingerprint`` intentionally includes Provider routing,
    MCP command digests and persisted policy files.  Those values can change
    during a running deployment (for example when an administrator registers
    an Agent model), so using that full deployment fingerprint to validate a
    later CLI artifact creates a false negative even though the request crossed
    the same source revision.  The CLI and API process can also intentionally
    use different deployment profiles (for example a production API with
    server-observed receipts and a local CLI that only submits the probe), so
    the profile-specific execution-evidence posture belongs to the full/source
    deployment fingerprint, not to this immutable code identity.  This
    narrower identity therefore binds only the gateway source files.  The full
    and source fingerprints are still retained in every artifact as deployment
    evidence and are checked when both processes share the same posture.
    """

    payload = snapshot if snapshot is not None else gateway_evidence_snapshot()
    source_files = payload.get("source_files") if isinstance(payload, dict) else None
    canonical = json.dumps(
        {
            "schema_version": "agent-supervisor.gateway-code-fingerprint.v1",
            "source_files": source_files if isinstance(source_files, dict) else {},
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def initialize_gateway_runtime_evidence() -> dict[str, Any]:
    """Capture the gateway source/config evidence at server startup.

    A CLI-side fingerprint only proves what the probe process can see on disk;
    it does not prove that the already-running API process was started from the
    same checkout.  The lifespan records a startup snapshot and exposes its
    digest in every gateway response so a stale server cannot silently satisfy
    a current-code probe.
    """

    global _RUNTIME_EVIDENCE
    snapshot = gateway_evidence_snapshot()
    evidence = {
        "fingerprint": gateway_evidence_fingerprint(snapshot),
        "source_fingerprint": gateway_source_fingerprint(snapshot),
        "code_fingerprint": gateway_code_fingerprint(snapshot),
        "snapshot": snapshot,
        "started_at": datetime.now(timezone.utc).isoformat(),
    }
    with _RUNTIME_EVIDENCE_LOCK:
        _RUNTIME_EVIDENCE = evidence
    return dict(evidence)


def gateway_runtime_evidence() -> dict[str, Any]:
    """Return the startup-bound gateway evidence for response metadata."""

    with _RUNTIME_EVIDENCE_LOCK:
        evidence = _RUNTIME_EVIDENCE
    if evidence is None:
        # Unit tests and direct function callers may not enter FastAPI's
        # lifespan.  Initialise lazily while retaining the same contract.
        evidence = initialize_gateway_runtime_evidence()
    return {
        "fingerprint": str(evidence.get("fingerprint") or ""),
        "snapshot": evidence.get("snapshot", {}),
        "started_at": str(evidence.get("started_at") or ""),
        "code_fingerprint": str(evidence.get("code_fingerprint") or ""),
    }
