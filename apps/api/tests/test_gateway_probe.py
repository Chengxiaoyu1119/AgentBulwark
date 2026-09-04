from __future__ import annotations

import argparse
import io
import json
import os
import tempfile
import unittest
import urllib.parse
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch
from urllib.error import URLError

from apps.api.agent_supervisor.commands.cli import (
    _case_session_id,
    _gateway_contract_evidence,
    _mcp_call_contract,
    _timestamped_probe_name,
    cmd_gateway_probe,
    cmd_mcp_probe,
)
from apps.api.agent_supervisor.domains.reports.gateway_evidence import (
    GATEWAY_EVIDENCE_SOURCE_FILES,
    gateway_code_fingerprint,
    gateway_evidence_fingerprint,
    gateway_evidence_snapshot,
    gateway_source_fingerprint,
)
from apps.api.agent_supervisor.domains.reports.readiness_checks import (
    _gateway_artifact_matches_current_source,
    _gateway_boundary_check,
    _latest_gateway_agent_run,
    _latest_gateway_probe,
    _latest_mcp_probe,
)


class _FakeResponse:
    status = 200

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self) -> bytes:
        return json.dumps(
            {
                "agent_supervisor": {
                    "decision": "允许",
                    "provider_response_hash": "response-hash",
                    "gateway_evidence_fingerprint": gateway_evidence_fingerprint(),
                },
                "choices": [{"message": {"content": "token: sk-live-secret-123456"}}],
            },
            ensure_ascii=False,
        ).encode("utf-8")


class _JsonResponse:
    def __init__(self, payload: dict, status: int = 200) -> None:
        self.status = status
        self._body = json.dumps(payload, ensure_ascii=False).encode("utf-8")

    def __enter__(self) -> "_JsonResponse":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self) -> bytes:
        return self._body


class GatewayProbeTests(unittest.TestCase):
    def test_case_session_id_stays_within_gateway_limit_for_causal_suffixes(self) -> None:
        session_id = _case_session_id("gateway-run", "case-" + ("x" * 180))
        self.assertLessEqual(len(session_id), 120)
        self.assertRegex(session_id, r"-[0-9a-f]{16}$")
        self.assertLessEqual(len(f"{session_id}-causal"), 160)
        # The digest keeps different long case ids distinguishable instead of
        # silently aliasing them after a fixed-width truncation.
        other = _case_session_id("gateway-run", "case-" + ("y" * 180))
        self.assertNotEqual(session_id, other)
        default_session = _case_session_id("", "case-1")
        self.assertTrue(default_session.startswith("gateway-run-case-1"))
        self.assertLessEqual(len(f"{default_session}-causal"), 160)

    def test_timestamped_probe_names_do_not_collide_in_parallel_runs(self) -> None:
        names = {_timestamped_probe_name("probe") for _ in range(256)}
        self.assertEqual(len(names), 256)
        self.assertTrue(all(name.startswith("probe-") and name.endswith(".json") for name in names))

    def test_gateway_fingerprint_covers_provider_receipt_and_audit_dependencies(self) -> None:
        source_files = gateway_evidence_snapshot()["source_files"]
        for path in (
            "apps/api/agent_supervisor/auth.py",
            "apps/api/agent_supervisor/routers/proxy.py",
            "apps/api/agent_supervisor/adapters/models/model_adapter.py",
            "apps/api/agent_supervisor/domains/runtime/execution_receipts.py",
            "apps/api/agent_supervisor/domains/runtime/gateway_comparison.py",
            "apps/api/agent_supervisor/domains/runtime/tools.py",
            "apps/api/agent_supervisor/mcp_gateway/interceptor.py",
            "apps/api/agent_supervisor/storage/database.py",
        ):
            self.assertIn(path, source_files)
            self.assertIsNotNone(source_files[path])

    def test_gateway_evidence_binds_auth_posture_without_persisting_tokens(self) -> None:
        with patch.dict(
            "os.environ",
            {
                "AGENT_SUPERVISOR_API_TOKEN": "shared-secret",
                "AGENT_SUPERVISOR_API_TOKEN_EXECUTOR": "executor-secret",
                "AGENT_SUPERVISOR_AGENT_TOKENS_JSON": '{"agent-a":"agent-secret"}',
                "AGENT_SUPERVISOR_ALLOW_SHARED_EXECUTOR_TOKEN": "false",
            },
            clear=False,
        ):
            snapshot = gateway_evidence_snapshot()

        security_config = snapshot["security_config"]
        dumped = json.dumps(snapshot, ensure_ascii=False)
        self.assertEqual(security_config["AGENT_SUPERVISOR_AGENT_TOKEN_IDS"], ["agent-a"])
        self.assertTrue(security_config["AGENT_SUPERVISOR_API_TOKEN_CONFIGURED"])
        self.assertTrue(security_config["AGENT_SUPERVISOR_API_TOKEN_EXECUTOR_CONFIGURED"])
        self.assertNotIn("shared-secret", dumped)
        self.assertNotIn("executor-secret", dumped)
        self.assertNotIn("agent-secret", dumped)

    def test_gateway_evidence_binds_provider_route_without_persisting_endpoint_or_key(self) -> None:
        with patch.dict(
            "os.environ",
            {
                "TARGET_DEEPSEEK_API_KEY": "target-secret-a",
                "TARGET_DEEPSEEK_BASE_URL": "https://provider-a.example/v1",
                "TARGET_DEEPSEEK_MODEL": "model-a",
            },
            clear=False,
        ):
            first = gateway_evidence_snapshot()
            first_fingerprint = gateway_evidence_fingerprint(first)

        with patch.dict(
            "os.environ",
            {
                "TARGET_DEEPSEEK_API_KEY": "target-secret-b",
                "TARGET_DEEPSEEK_BASE_URL": "https://provider-b.example/v1",
                "TARGET_DEEPSEEK_MODEL": "model-b",
            },
            clear=False,
        ):
            second = gateway_evidence_snapshot()
            second_fingerprint = gateway_evidence_fingerprint(second)

        self.assertNotEqual(first_fingerprint, second_fingerprint)
        self.assertNotEqual(gateway_source_fingerprint(first), gateway_source_fingerprint(second))
        dumped = json.dumps(first, ensure_ascii=False)
        self.assertNotIn("target-secret-a", dumped)
        self.assertNotIn("provider-a.example", dumped)
        self.assertEqual(
            first["provider_config"]["TARGET_DEEPSEEK_BASE_URL"]["configured"],
            True,
        )
        self.assertEqual(len(first["provider_config"]["TARGET_DEEPSEEK_BASE_URL"]["sha256"]), 64)

    def test_gateway_code_fingerprint_ignores_runtime_provider_and_policy_values(self) -> None:
        with patch.dict(
            os.environ,
            {
                "TARGET_DEEPSEEK_API_KEY": "code-fp-provider-a",
                "TARGET_DEEPSEEK_BASE_URL": "https://provider-a.example/v1",
                "TARGET_DEEPSEEK_MODEL": "model-a",
            },
            clear=False,
        ):
            first = gateway_evidence_snapshot()
        with patch.dict(
            os.environ,
            {
                "TARGET_DEEPSEEK_API_KEY": "code-fp-provider-b",
                "TARGET_DEEPSEEK_BASE_URL": "https://provider-b.example/v1",
                "TARGET_DEEPSEEK_MODEL": "model-b",
            },
            clear=False,
        ):
            second = gateway_evidence_snapshot()

        self.assertNotEqual(gateway_source_fingerprint(first), gateway_source_fingerprint(second))
        self.assertEqual(gateway_code_fingerprint(first), gateway_code_fingerprint(second))

    def test_readiness_requires_source_binding_when_artifact_has_split_fingerprints(self) -> None:
        """A code match alone must not bless evidence for another Provider route."""
        current_code = gateway_code_fingerprint()
        current_source = gateway_source_fingerprint()
        self.assertTrue(
            _gateway_artifact_matches_current_source(
                {
                    "gateway_code_fingerprint": current_code,
                    "gateway_source_fingerprint": current_source,
                }
            )
        )
        self.assertFalse(
            _gateway_artifact_matches_current_source(
                {
                    "gateway_code_fingerprint": current_code,
                    "gateway_source_fingerprint": "0" * 64,
                }
            )
        )
        self.assertFalse(
            _gateway_artifact_matches_current_source(
                {
                    "gateway_code_fingerprint": "0" * 64,
                    "gateway_source_fingerprint": current_source,
                }
            )
        )

    def test_gateway_code_fingerprint_is_stable_across_cli_and_api_security_profiles(self) -> None:
        """A production API may be probed by a local CLI process.

        The full/source deployment fingerprints must retain the receipt posture,
        but the immutable code identity used by the HTTP contract cannot reject
        a valid probe merely because the API process enforces server-observed
        receipts while the CLI process does not own that runtime setting.
        """
        with patch.dict(
            "os.environ",
            {
                "AGENT_SUPERVISOR_SECURITY_PROFILE": "local",
                "AGENT_SUPERVISOR_PROXY_REQUIRE_SERVER_OBSERVED_RECEIPTS": "false",
            },
            clear=False,
        ):
            local = gateway_evidence_snapshot()
        with patch.dict(
            "os.environ",
            {
                "AGENT_SUPERVISOR_SECURITY_PROFILE": "production",
                "AGENT_SUPERVISOR_PROXY_REQUIRE_SERVER_OBSERVED_RECEIPTS": "false",
            },
            clear=False,
        ):
            production = gateway_evidence_snapshot()

        self.assertNotEqual(gateway_source_fingerprint(local), gateway_source_fingerprint(production))
        self.assertEqual(gateway_code_fingerprint(local), gateway_code_fingerprint(production))

    def test_gateway_source_fingerprint_binds_effective_execution_evidence_policy(self) -> None:
        with patch.dict(
            "os.environ",
            {
                "AGENT_SUPERVISOR_SECURITY_PROFILE": "local",
                "AGENT_SUPERVISOR_PROXY_REQUIRE_SERVER_OBSERVED_RECEIPTS": "false",
            },
            clear=False,
        ):
            compatibility = gateway_evidence_snapshot()

        with patch.dict(
            "os.environ",
            {
                "AGENT_SUPERVISOR_SECURITY_PROFILE": "local",
                "AGENT_SUPERVISOR_PROXY_REQUIRE_SERVER_OBSERVED_RECEIPTS": "true",
            },
            clear=False,
        ):
            strict_local = gateway_evidence_snapshot()

        with patch.dict(
            "os.environ",
            {
                "AGENT_SUPERVISOR_SECURITY_PROFILE": "production",
                "AGENT_SUPERVISOR_PROXY_REQUIRE_SERVER_OBSERVED_RECEIPTS": "false",
                "AGENT_SUPERVISOR_PROXY_REQUIRE_TOOL_RECEIPTS": "false",
            },
            clear=False,
        ):
            production_false = gateway_evidence_snapshot()

        with patch.dict(
            "os.environ",
            {
                "AGENT_SUPERVISOR_SECURITY_PROFILE": "production",
                "AGENT_SUPERVISOR_PROXY_REQUIRE_SERVER_OBSERVED_RECEIPTS": "true",
                "AGENT_SUPERVISOR_PROXY_REQUIRE_TOOL_RECEIPTS": "true",
            },
            clear=False,
        ):
            production_true = gateway_evidence_snapshot()

        self.assertFalse(compatibility["execution_evidence_config"]["server_observed_receipts_required"])
        self.assertTrue(strict_local["execution_evidence_config"]["server_observed_receipts_required"])
        self.assertTrue(production_false["execution_evidence_config"]["server_observed_receipts_required"])
        self.assertTrue(production_false["execution_evidence_config"]["tool_receipts_required"])
        self.assertNotEqual(
            gateway_source_fingerprint(compatibility),
            gateway_source_fingerprint(strict_local),
        )
        self.assertEqual(
            gateway_source_fingerprint(production_false),
            gateway_source_fingerprint(production_true),
        )

    def test_gateway_execution_evidence_snapshot_exposes_effective_policy_without_secret_values(self) -> None:
        with patch.dict(
            "os.environ",
            {
                "AGENT_SUPERVISOR_SECURITY_PROFILE": "production",
                "AGENT_SUPERVISOR_PROXY_REQUIRE_SERVER_OBSERVED_RECEIPTS": "false",
                "AGENT_SUPERVISOR_API_TOKEN": "snapshot-secret-token",
                "AGENT_SUPERVISOR_AGENT_TOKENS_JSON": '{"snapshot-agent":"snapshot-agent-secret"}',
            },
            clear=False,
        ):
            snapshot = gateway_evidence_snapshot()

        self.assertEqual(
            snapshot["execution_evidence_config"],
            {
                "security_profile": "production",
                "tool_receipts_required": True,
                "server_observed_receipts_required": True,
            },
        )
        dumped = json.dumps(snapshot, ensure_ascii=False)
        self.assertNotIn("snapshot-secret-token", dumped)
        self.assertNotIn("snapshot-agent-secret", dumped)

    def test_readiness_blocks_when_runtime_accepts_caller_declared_execution_evidence(self) -> None:
        with (
            patch(
                "apps.api.agent_supervisor.domains.reports.readiness_checks.proxy_security_snapshot",
                return_value={
                    "tool_receipts_required": True,
                    "server_observed_receipts_required": False,
                },
            ),
            patch(
                "apps.api.agent_supervisor.mcp_gateway.config.gateway_enabled",
                return_value=False,
            ),
            patch(
                "apps.api.agent_supervisor.mcp_gateway.config.gateway_guard_enabled",
                return_value=True,
            ),
            patch(
                "apps.api.agent_supervisor.mcp_gateway.config.gateway_allow_side_effect_notifications",
                return_value=False,
            ),
            patch(
                "apps.api.agent_supervisor.domains.reports.readiness_checks._latest_gateway_probe",
                return_value={"contract": {"passed": True}},
            ),
            patch(
                "apps.api.agent_supervisor.domains.reports.readiness_checks._latest_gateway_agent_run",
                return_value={},
            ),
            patch(
                "apps.api.agent_supervisor.domains.reports.readiness_checks._latest_mcp_probe",
                return_value={},
            ),
        ):
            result = _gateway_boundary_check()

        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["severity"], "P0")
        self.assertFalse(result["details"]["server_observed_receipts_required"])
        self.assertIn("服务端观察", result["next_action"])

    def test_readiness_does_not_block_verified_http_gateway_when_mcp_is_optional(self) -> None:
        with (
            patch(
                "apps.api.agent_supervisor.domains.reports.readiness_checks.proxy_security_snapshot",
                return_value={
                    "tool_receipts_required": True,
                    "server_observed_receipts_required": True,
                },
            ),
            patch(
                "apps.api.agent_supervisor.mcp_gateway.config.gateway_enabled",
                return_value=False,
            ),
            patch(
                "apps.api.agent_supervisor.mcp_gateway.config.gateway_guard_enabled",
                return_value=True,
            ),
            patch(
                "apps.api.agent_supervisor.mcp_gateway.config.gateway_allow_side_effect_notifications",
                return_value=False,
            ),
            patch(
                "apps.api.agent_supervisor.domains.reports.readiness_checks._latest_gateway_probe",
                return_value={"contract": {"passed": True}},
            ),
            patch(
                "apps.api.agent_supervisor.domains.reports.readiness_checks._latest_gateway_agent_run",
                return_value={},
            ),
            patch(
                "apps.api.agent_supervisor.domains.reports.readiness_checks._latest_mcp_probe",
                return_value={},
            ),
        ):
            result = _gateway_boundary_check()

        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["severity"], "P1")
        self.assertIn("未配置（可选）", result["evidence"])

    def test_readiness_exposes_current_gateway_artifact_paths(self) -> None:
        probe = {"artifact_path": "reports/current-gateway-probe.json", "contract": {"passed": True}}
        agent_run = {"artifact_path": "reports/current-gateway-agent-run.json", "summary": {}}
        mcp_probe = {"artifact_path": "reports/current-mcp-probe.json", "summary": {}}
        with (
            patch(
                "apps.api.agent_supervisor.domains.reports.readiness_checks.proxy_security_snapshot",
                return_value={
                    "tool_receipts_required": True,
                    "server_observed_receipts_required": True,
                },
            ),
            patch(
                "apps.api.agent_supervisor.mcp_gateway.config.gateway_enabled",
                return_value=False,
            ),
            patch(
                "apps.api.agent_supervisor.mcp_gateway.config.gateway_guard_enabled",
                return_value=True,
            ),
            patch(
                "apps.api.agent_supervisor.mcp_gateway.config.gateway_allow_side_effect_notifications",
                return_value=False,
            ),
            patch(
                "apps.api.agent_supervisor.domains.reports.readiness_checks._latest_gateway_probe",
                return_value=probe,
            ),
            patch(
                "apps.api.agent_supervisor.domains.reports.readiness_checks._latest_gateway_agent_run",
                return_value=agent_run,
            ),
            patch(
                "apps.api.agent_supervisor.domains.reports.readiness_checks._latest_mcp_probe",
                return_value=mcp_probe,
            ),
        ):
            result = _gateway_boundary_check()

        self.assertEqual(
            result["artifact_paths"],
            [
                "reports/current-gateway-probe.json",
                "reports/current-gateway-agent-run.json",
                "reports/current-mcp-probe.json",
            ],
        )

    def test_readiness_does_not_hide_failed_requested_mcp_operator_evidence(self) -> None:
        mcp_probe = {
            "summary": {
                "evidence_verdict": "complete",
                "initialize_ok": True,
                "tools_list_ok": True,
                "tool_call_passed": True,
                "audit_id_present": True,
                "operator_evidence_requested": True,
                "operator_evidence_passed": False,
            }
        }
        with (
            patch(
                "apps.api.agent_supervisor.domains.reports.readiness_checks.proxy_security_snapshot",
                return_value={
                    "tool_receipts_required": True,
                    "server_observed_receipts_required": True,
                },
            ),
            patch(
                "apps.api.agent_supervisor.mcp_gateway.config.gateway_enabled",
                return_value=True,
            ),
            patch(
                "apps.api.agent_supervisor.mcp_gateway.config.gateway_guard_enabled",
                return_value=True,
            ),
            patch(
                "apps.api.agent_supervisor.mcp_gateway.config.gateway_allow_side_effect_notifications",
                return_value=False,
            ),
            patch(
                "apps.api.agent_supervisor.domains.reports.readiness_checks._latest_gateway_probe",
                return_value={"contract": {"passed": True}},
            ),
            patch(
                "apps.api.agent_supervisor.domains.reports.readiness_checks._latest_gateway_agent_run",
                return_value={},
            ),
            patch(
                "apps.api.agent_supervisor.domains.reports.readiness_checks._latest_mcp_probe",
                return_value=mcp_probe,
            ),
        ):
            result = _gateway_boundary_check()

        self.assertEqual(result["status"], "warning")
        self.assertEqual(result["details"]["mcp_protocol_passed"], True)
        self.assertTrue(result["details"]["mcp_operator_evidence_requested"])
        self.assertFalse(result["details"]["mcp_operator_evidence_passed"])
        self.assertFalse(result["details"]["mcp_probe_passed"])
        self.assertIn("operator", result["evidence"])

    def test_gateway_evidence_binds_mcp_upstream_without_persisting_command(self) -> None:
        with patch.dict(
            "os.environ",
            {
                "MCP_GATEWAY_UPSTREAM_COMMAND": "python mcp_server.py --token upstream-secret-a",
                "MCP_GATEWAY_ROUTES_JSON": '[{"name":"files","command":"python files.py","cwd":"C:/data-a"}]',
                "MCP_GATEWAY_UPSTREAM_CWD": "C:/data-a",
                "MCP_GATEWAY_UPSTREAM_ENV_ALLOWLIST": "MCP_ECHO_MODE",
            },
            clear=False,
        ):
            first = gateway_evidence_snapshot()
            first_fingerprint = gateway_source_fingerprint(first)

        with patch.dict(
            "os.environ",
            {
                "MCP_GATEWAY_UPSTREAM_COMMAND": "python mcp_server.py --token upstream-secret-b",
                "MCP_GATEWAY_ROUTES_JSON": '[{"name":"files","command":"python files.py","cwd":"C:/data-b"}]',
                "MCP_GATEWAY_UPSTREAM_CWD": "C:/data-b",
                "MCP_GATEWAY_UPSTREAM_ENV_ALLOWLIST": "MCP_ECHO_MODE,MCP_ECHO_TRACE",
            },
            clear=False,
        ):
            second = gateway_evidence_snapshot()
            second_fingerprint = gateway_source_fingerprint(second)

        self.assertNotEqual(first_fingerprint, second_fingerprint)
        dumped = json.dumps(first, ensure_ascii=False)
        self.assertNotIn("upstream-secret-a", dumped)
        self.assertNotIn("mcp_server.py --token", dumped)
        self.assertEqual(first["mcp_config"]["MCP_GATEWAY_UPSTREAM_COMMAND"]["configured"], True)
        self.assertEqual(len(first["mcp_config"]["MCP_GATEWAY_UPSTREAM_COMMAND"]["sha256"]), 64)

    def test_gateway_evidence_binds_modern_mcp_contract_and_effective_posture(self) -> None:
        required_sources = {
            "apps/api/agent_supervisor/commands/cli.py",
            "apps/api/agent_supervisor/domains/reports/readiness_checks.py",
            "apps/api/agent_supervisor/domains/runtime/mcp_access.py",
            "apps/api/agent_supervisor/mcp_gateway/http_transport.py",
            "apps/api/agent_supervisor/mcp_gateway/mrtr.py",
            "apps/api/agent_supervisor/mcp_gateway/subscriptions.py",
        }
        self.assertTrue(required_sources.issubset(set(GATEWAY_EVIDENCE_SOURCE_FILES)))

        with patch.dict(
            "os.environ",
            {
                "AGENT_SUPERVISOR_SECURITY_PROFILE": "local",
                "MCP_GATEWAY_UPSTREAM_COMMAND": "python mcp_server.py",
                "MCP_GATEWAY_GUARD_ENABLED": "true",
                "MCP_GATEWAY_ALLOW_SIDE_EFFECT_NOTIFICATIONS": "false",
                "MCP_GATEWAY_NETWORK_MODE": "reject-unpinned",
                "MCP_GATEWAY_SESSION_ISOLATION": "true",
                "MCP_GATEWAY_MAX_SESSIONS": "64",
                "MCP_GATEWAY_MAX_SUBSCRIPTIONS": "32",
                "MCP_GATEWAY_MRTR_TIMEOUT_SECONDS": "180",
                "MCP_GATEWAY_REQUEST_STATE_SECRET": "s" * 48,
            },
            clear=False,
        ):
            secure = gateway_evidence_snapshot()
            secure_fingerprint = gateway_source_fingerprint(secure)

        with patch.dict(
            "os.environ",
            {
                "AGENT_SUPERVISOR_SECURITY_PROFILE": "local",
                "MCP_GATEWAY_UPSTREAM_COMMAND": "python mcp_server.py",
                "MCP_GATEWAY_GUARD_ENABLED": "false",
                "MCP_GATEWAY_ALLOW_SIDE_EFFECT_NOTIFICATIONS": "true",
                "MCP_GATEWAY_NETWORK_MODE": "allow-unpinned",
                "MCP_GATEWAY_SESSION_ISOLATION": "false",
                "MCP_GATEWAY_MAX_SESSIONS": "16",
                "MCP_GATEWAY_MAX_SUBSCRIPTIONS": "8",
                "MCP_GATEWAY_MRTR_TIMEOUT_SECONDS": "60",
                "MCP_GATEWAY_REQUEST_STATE_SECRET": "",
                "AGENT_SUPERVISOR_AUDIT_HMAC_KEY": "",
            },
            clear=False,
        ):
            downgraded = gateway_evidence_snapshot()
            downgraded_fingerprint = gateway_source_fingerprint(downgraded)

        self.assertNotEqual(secure_fingerprint, downgraded_fingerprint)
        self.assertEqual(secure["mcp_config"]["effective"]["guard_enabled"], True)
        self.assertEqual(secure["mcp_config"]["effective"]["session_isolation"], True)
        self.assertEqual(secure["mcp_config"]["effective"]["request_state_key_source"], "explicit")
        self.assertEqual(downgraded["mcp_config"]["effective"]["guard_enabled"], False)
        self.assertEqual(downgraded["mcp_config"]["effective"]["session_isolation"], False)
        self.assertEqual(downgraded["mcp_config"]["effective"]["request_state_key_source"], "ephemeral")
        self.assertNotIn("s" * 48, json.dumps(secure, ensure_ascii=False))

    def test_gateway_contract_requires_explicit_provider_fact(self) -> None:
        request_hash = "a" * 64
        evidence = _gateway_contract_evidence(
            status=200,
            request_hash=request_hash,
            response_payload={
                "choices": [{"message": {"role": "assistant", "content": "ok"}}],
                "agent_supervisor": {
                    "decision": "允许",
                    "gateway_evidence_fingerprint": gateway_evidence_fingerprint(),
                    "provider_called": True,
                    "evidence_scope": "gateway-contract",
                    "request_hash": request_hash,
                    "provider_request_hash": "b" * 64,
                    "provider_response_hash": "c" * 64,
                    "audit_id": "audit-1",
                    "execution_boundary": "caller-owned-tool-execution",
                    "decision_enforced_before_tool_execution": False,
                },
            },
        )

        self.assertTrue(evidence["passed"])
        self.assertEqual(evidence["status"], "passed")

    def test_gateway_contract_rejects_missing_provider_fact(self) -> None:
        evidence = _gateway_contract_evidence(
            status=200,
            request_hash="a" * 64,
            response_payload={"agent_supervisor": {"decision": "允许"}, "choices": []},
        )

        self.assertFalse(evidence["passed"])
        self.assertIn("provider_called_declared", evidence["failure_reasons"])

    def test_gateway_contract_rejects_post_provider_block_without_execution_boundary(self) -> None:
        request_hash = "a" * 64
        evidence = _gateway_contract_evidence(
            status=200,
            request_hash=request_hash,
            response_payload={
                "model": "fixture-model",
                "choices": [{"message": {"role": "assistant", "content": "blocked"}}],
                "agent_supervisor": {
                    "decision": "拒绝",
                    "provider_called": True,
                    "request_stage": "post-provider-output",
                    "gateway_evidence_fingerprint": gateway_evidence_fingerprint(),
                    "evidence_scope": "gateway-contract",
                    "request_hash": request_hash,
                    "provider_request_hash": "b" * 64,
                    "provider_response_hash": "c" * 64,
                    "audit_id": "audit-post-provider-block",
                    "execution_boundary": "provider-output-filter",
                    "decision_enforced_before_tool_execution": False,
                },
            },
        )

        self.assertFalse(evidence["passed"])
        self.assertIn("blocked_before_tool_execution", evidence["failure_reasons"])

    def test_gateway_contract_rejects_stale_server_runtime_fingerprint(self) -> None:
        evidence = _gateway_contract_evidence(
            status=200,
            request_hash="a" * 64,
            response_payload={
                "choices": [{"message": {"role": "assistant", "content": "ok"}}],
                "agent_supervisor": {
                    "decision": "允许",
                    "provider_called": True,
                    "gateway_evidence_fingerprint": "0" * 64,
                    "evidence_scope": "gateway-contract",
                    "request_hash": "a" * 64,
                    "provider_request_hash": "b" * 64,
                    "provider_response_hash": "c" * 64,
                    "audit_id": "audit-1",
                    "execution_boundary": "caller-owned-tool-execution",
                    "decision_enforced_before_tool_execution": False,
                },
            },
        )

        self.assertFalse(evidence["passed"])
        self.assertIn("gateway_runtime_fingerprint_valid", evidence["failure_reasons"])

    def test_gateway_contract_accepts_server_only_auth_posture_when_source_matches(self) -> None:
        request_hash = "a" * 64
        evidence = _gateway_contract_evidence(
            status=200,
            request_hash=request_hash,
            response_payload={
                "choices": [{"message": {"role": "assistant", "content": "ok"}}],
                "agent_supervisor": {
                    "decision": "允许",
                    # The full runtime fingerprint intentionally differs from
                    # the CLI's environment, while the source identity is the
                    # same checkout.
                    "gateway_evidence_fingerprint": "f" * 64,
                    "gateway_source_fingerprint": gateway_source_fingerprint(),
                    "provider_called": True,
                    "evidence_scope": "gateway-contract",
                    "request_hash": request_hash,
                    "provider_request_hash": "b" * 64,
                    "provider_response_hash": "c" * 64,
                    "audit_id": "audit-server-only-auth",
                    "execution_boundary": "caller-owned-tool-execution",
                },
            },
        )

        self.assertTrue(evidence["passed"])
        self.assertTrue(evidence["checks"]["gateway_runtime_fingerprint_valid"])

    def test_gateway_contract_accepts_managed_initial_request_hash(self) -> None:
        evidence = _gateway_contract_evidence(
            status=200,
            request_hash="a" * 64,
            response_payload={
                "choices": [{"message": {"role": "assistant", "content": "done"}}],
                "agent_supervisor": {
                    "decision": "询问",
                    "gateway_evidence_fingerprint": gateway_evidence_fingerprint(),
                    "provider_called": True,
                    "evidence_scope": "gateway-contract",
                    "request_hash": "b" * 64,
                    "initial_request_hash": "a" * 64,
                    "provider_request_hash": "c" * 64,
                    "provider_response_hash": "d" * 64,
                    "audit_id": "audit-managed",
                    "execution_boundary": "managed-round-limit",
                    "decision_enforced_before_tool_execution": True,
                },
            },
        )

        self.assertTrue(evidence["passed"])

    def test_probe_sends_real_payload_and_writes_redacted_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            payload_path = Path(tmp) / "payload.json"
            output_path = Path(tmp) / "probe.json"
            payload_path.write_text(
                json.dumps(
                    {"model": "fixture-model", "messages": [{"role": "user", "content": "hello"}]},
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            args = argparse.Namespace(
                payload_file=str(payload_path),
                json="",
                url="http://127.0.0.1:8012/v1/chat/completions",
                api_token="probe-token",
                session_id="probe-session",
                timeout=3.0,
                output=str(output_path),
            )
            with (
                patch(
                    "apps.api.agent_supervisor.commands.cli.urllib.request.urlopen",
                    return_value=_FakeResponse(),
                ) as urlopen,
                redirect_stdout(io.StringIO()),
            ):
                cmd_gateway_probe(args)

            request = urlopen.call_args.args[0]
            self.assertEqual(request.full_url, args.url)
            self.assertEqual(request.get_header("Authorization"), "Bearer probe-token")
            self.assertEqual(request.get_header("X-agent-session-id"), "probe-session")
            evidence = json.loads(output_path.read_text(encoding="utf-8"))
            dumped = json.dumps(evidence, ensure_ascii=False)
            self.assertEqual(evidence["http_status"], 200)
            self.assertEqual(evidence["gateway"]["decision"], "允许")
            self.assertNotIn("sk-live-secret-123456", dumped)
            self.assertEqual(len(evidence["request_hash"]), 64)
            self.assertEqual(evidence["probe_source"], "agent-supervisor-cli.gateway-probe")
            self.assertEqual(len(evidence["gateway_evidence_fingerprint"]), 64)

    def test_gateway_probe_strict_mode_turns_transport_failure_into_nonzero_result(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output_path = Path(tmp) / "strict-probe.json"
            args = argparse.Namespace(
                payload_file="",
                json=json.dumps({"model": "fixture-model", "messages": [{"role": "user", "content": "ping"}]}),
                url="http://127.0.0.1:9/v1/chat/completions",
                api_token="",
                session_id="strict-probe",
                timeout=0.1,
                output=str(output_path),
                strict=True,
            )
            with (
                patch(
                    "apps.api.agent_supervisor.commands.cli.urllib.request.urlopen",
                    side_effect=URLError("fixture gateway offline"),
                ),
                redirect_stdout(io.StringIO()),
            ):
                with self.assertRaises(SystemExit) as raised:
                    cmd_gateway_probe(args)

            self.assertEqual(raised.exception.code, "gateway-probe contract did not pass")
            report = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertFalse(report["contract"]["passed"])

    def test_mcp_probe_strict_mode_turns_partial_contract_into_nonzero_result(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output_path = Path(tmp) / "strict-mcp.json"
            args = argparse.Namespace(
                url="http://127.0.0.1:9/api/mcp",
                api_token="",
                session_id="strict-mcp",
                tool="file.read",
                arguments='{"path":"public/readme.md"}',
                expected_decision="允许",
                timeout=0.1,
                output=str(output_path),
                strict=True,
            )
            unavailable = {
                "http_status": 0,
                "response_payload": None,
                "transport_error": "fixture gateway offline",
                "duration_ms": 0.0,
                "request_hash": "",
            }
            with (
                patch(
                    "apps.api.agent_supervisor.commands.cli._send_mcp_http_json",
                    return_value=unavailable,
                ),
                redirect_stdout(io.StringIO()),
            ):
                with self.assertRaises(SystemExit) as raised:
                    cmd_mcp_probe(args)

            self.assertEqual(raised.exception.code, "mcp-probe contract did not pass")
            report = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertFalse(report["contract"]["passed"])

    def test_readiness_ignores_legacy_and_stale_gateway_probe_artifacts(self) -> None:
        def payload(*, fingerprint: str, generated_at: str, source: str = "agent-supervisor-cli.gateway-probe") -> dict:
            return {
                "schema_version": "agent-supervisor.gateway-probe.v1",
                "generated_at": generated_at,
                "probe_source": source,
                "gateway_evidence_fingerprint": fingerprint,
                "endpoint": "http://127.0.0.1:8013/v1/chat/completions",
                "contract": {"passed": True},
            }

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            current = root / "LLM网关当前代码攻击探针.json"
            legacy = root / "LLM网关探针-legacy.json"
            stale = root / "LLM网关真实正常探针.json"
            now = datetime.now(timezone.utc)
            current.write_text(
                json.dumps(payload(fingerprint=gateway_evidence_fingerprint(), generated_at=now.isoformat()), ensure_ascii=False),
                encoding="utf-8",
            )
            # A newer file name must not win merely because it exists.
            legacy.write_text(
                json.dumps(payload(fingerprint="0" * 64, generated_at=now.isoformat()), ensure_ascii=False),
                encoding="utf-8",
            )
            stale.write_text(
                json.dumps(
                    payload(
                        fingerprint=gateway_evidence_fingerprint(),
                        generated_at=(now - timedelta(days=2)).isoformat(),
                    ),
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            with patch("apps.api.agent_supervisor.domains.reports.readiness_checks.SANDBOX_REPORTS_DIR", root):
                selected = _latest_gateway_probe()

        self.assertEqual(selected["artifact_path"], str(current))
        self.assertEqual(selected["gateway_evidence_fingerprint"], gateway_evidence_fingerprint())

    def test_readiness_accepts_current_batch_agent_gateway_evidence(self) -> None:
        now = datetime.now(timezone.utc)
        payload = {
            "schema_version": "agent-supervisor.gateway-agent-run.v1",
            "generated_at": now.isoformat(),
            "source": "agent-supervisor-cli.gateway-agent-run",
            "gateway_evidence_fingerprint": gateway_evidence_fingerprint(),
            "gateway_path_exercised": True,
            "endpoint": "http://127.0.0.1:8013/v1/chat/completions",
            "summary": {
                "case_count": 2,
                "gateway_contract_passed_count": 2,
                "evidence_verdict": "complete",
            },
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            current = root / "真实Agent网关运行证据-20260817-000000.json"
            current.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
            with patch("apps.api.agent_supervisor.domains.reports.readiness_checks.SANDBOX_REPORTS_DIR", root):
                selected = _latest_gateway_agent_run()

        self.assertEqual(selected["artifact_path"], str(current))
        self.assertEqual(selected["summary"]["evidence_verdict"], "complete")

    def test_readiness_accepts_fixed_name_gateway_probe_evidence(self) -> None:
        now = datetime.now(timezone.utc)
        payload = {
            "schema_version": "agent-supervisor.gateway-probe.v1",
            "generated_at": now.isoformat(),
            "probe_source": "agent-supervisor-cli.gateway-probe",
            "gateway_evidence_fingerprint": gateway_evidence_fingerprint(),
            "endpoint": "http://127.0.0.1:8013/v1/chat/completions",
            "contract": {"passed": True},
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            current = root / "current-gateway-probe.json"
            current.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
            with patch("apps.api.agent_supervisor.domains.reports.readiness_checks.SANDBOX_REPORTS_DIR", root):
                selected = _latest_gateway_probe()

        self.assertEqual(selected["artifact_path"], str(current))
        self.assertTrue(selected["contract"]["passed"])

    def test_readiness_accepts_fixed_name_batch_agent_gateway_evidence(self) -> None:
        now = datetime.now(timezone.utc)
        payload = {
            "schema_version": "agent-supervisor.gateway-agent-run.v1",
            "generated_at": now.isoformat(),
            "source": "agent-supervisor-cli.gateway-agent-run",
            "gateway_evidence_fingerprint": gateway_evidence_fingerprint(),
            "gateway_path_exercised": True,
            "endpoint": "http://127.0.0.1:8013/v1/chat/completions",
            "summary": {"case_count": 1, "gateway_contract_passed_count": 1, "evidence_verdict": "complete"},
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            current = root / "current-gateway-agent-run.json"
            current.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
            with patch("apps.api.agent_supervisor.domains.reports.readiness_checks.SANDBOX_REPORTS_DIR", root):
                selected = _latest_gateway_agent_run()

        self.assertEqual(selected["artifact_path"], str(current))
        self.assertEqual(selected["summary"]["evidence_verdict"], "complete")

    def test_readiness_does_not_hide_newer_failed_batch_with_older_passing_report(self) -> None:
        now = datetime.now(timezone.utc)
        base = {
            "schema_version": "agent-supervisor.gateway-agent-run.v1",
            "source": "agent-supervisor-cli.gateway-agent-run",
            "gateway_evidence_fingerprint": gateway_evidence_fingerprint(),
            "gateway_path_exercised": True,
            "endpoint": "http://127.0.0.1:8012/v1/chat/completions",
        }
        passing = {
            **base,
            "generated_at": (now - timedelta(minutes=2)).isoformat(),
            "summary": {
                "case_count": 4,
                "gateway_contract_passed_count": 4,
                "evidence_verdict": "complete",
            },
        }
        failed = {
            **base,
            "generated_at": now.isoformat(),
            "summary": {
                "case_count": 4,
                "gateway_contract_passed_count": 0,
                "evidence_verdict": "partial",
            },
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old_path = root / "真实Agent网关运行证据-older.json"
            new_path = root / "真实Agent网关运行证据-newer.json"
            old_path.write_text(json.dumps(passing, ensure_ascii=False), encoding="utf-8")
            new_path.write_text(json.dumps(failed, ensure_ascii=False), encoding="utf-8")
            old_mtime = os.path.getmtime(old_path)
            os.utime(new_path, (old_mtime + 2, old_mtime + 2))
            with patch("apps.api.agent_supervisor.domains.reports.readiness_checks.SANDBOX_REPORTS_DIR", root):
                selected = _latest_gateway_agent_run()

        self.assertEqual(selected["artifact_path"], str(new_path))
        self.assertEqual(selected["summary"]["evidence_verdict"], "partial")

    def test_mcp_probe_records_real_json_rpc_contract_without_tool_text(self) -> None:
        def fake_urlopen(request: object, timeout: float) -> _JsonResponse:
            del timeout
            url = str(request.full_url)  # type: ignore[attr-defined]
            if url.endswith("/api/mcp/info"):
                return _JsonResponse({"enabled": True, "guard_enabled": True, "routes": ["default"]})
            if url.endswith("/api/runtime_status"):
                return _JsonResponse(
                    {
                        "gateway_evidence": {
                            "fingerprint": gateway_evidence_fingerprint(),
                            "source_fingerprint": gateway_source_fingerprint(),
                        },
                        "mcp": {"configured": True, "enabled": True},
                    }
                )
            body = json.loads(request.data.decode("utf-8"))  # type: ignore[attr-defined]
            if body["method"] == "initialize":
                return _JsonResponse({"jsonrpc": "2.0", "id": body["id"], "result": {"protocolVersion": "2025-06-18"}})
            if body["method"] == "tools/list":
                return _JsonResponse(
                    {
                        "jsonrpc": "2.0",
                        "id": body["id"],
                        "result": {
                            "tools": [{"name": "file.read", "description": "clean"}],
                            "zhiAnSentinel": {
                                "filtered_tool_count": 2,
                                "quarantined_tool_count": 1,
                                "scanSummary": {
                                    "scanned_tool_count": 4,
                                    "quarantined_tool_count": 1,
                                    "warning_tool_count": 1,
                                },
                            },
                        },
                    }
                )
            return _JsonResponse(
                {
                    "jsonrpc": "2.0",
                    "id": body["id"],
                    "result": {
                        "isError": False,
                        "content": [{"type": "text", "text": "secret-token must not be persisted"}],
                        "zhiAnSentinel": {
                            "audit_id": "mcp-audit-1",
                            "contextScan": {"verdict": "clean"},
                        },
                    },
                }
            )

        with tempfile.TemporaryDirectory() as tmp:
            output_path = Path(tmp) / "mcp-probe.json"
            args = argparse.Namespace(
                url="http://example.test/api/mcp",
                api_token="mcp-secret-token",
                session_id="probe-session",
                tool="file.read",
                arguments='{"path":"public/readme.md"}',
                expected_decision="允许",
                timeout=3.0,
                output=str(output_path),
            )
            with patch("apps.api.agent_supervisor.commands.cli.urllib.request.urlopen", side_effect=fake_urlopen):
                cmd_mcp_probe(args)

            report = json.loads(output_path.read_text(encoding="utf-8"))
            dumped = json.dumps(report, ensure_ascii=False)
            self.assertEqual(report["schema_version"], "agent-supervisor.mcp-probe.v1")
            self.assertEqual(report["summary"]["evidence_verdict"], "complete")
            self.assertEqual(report["summary"]["filtered_tool_count"], 2)
            self.assertEqual(report["summary"]["quarantined_tool_count"], 1)
            self.assertEqual(report["tool_inventory"]["filtered_count"], 2)
            self.assertEqual(report["tool_inventory"]["quarantined_count"], 1)
            self.assertTrue(report["summary"]["audit_id_present"])
            self.assertNotIn("mcp-secret-token", dumped)
            self.assertNotIn("secret-token must not be persisted", dumped)

    def test_mcp_probe_records_operator_evidence_as_scoped_summaries(self) -> None:
        def fake_urlopen(request: object, timeout: float) -> _JsonResponse:
            del timeout
            parsed = urllib.parse.urlsplit(str(request.full_url))  # type: ignore[attr-defined]
            if parsed.path.endswith("/api/mcp/info"):
                return _JsonResponse({"enabled": True, "guard_enabled": True, "routes": ["default"]})
            if parsed.path.endswith("/api/runtime_status"):
                return _JsonResponse(
                    {
                        "gateway_evidence": {
                            "fingerprint": gateway_evidence_fingerprint(),
                            "source_fingerprint": gateway_source_fingerprint(),
                        },
                        "mcp": {"configured": True, "enabled": True},
                    }
                )
            if parsed.path.endswith("/api/mcp/tools/evidence"):
                return _JsonResponse(
                    {
                        "schema_version": "mcp-tools-operator-inventory.v1",
                        "agent": "fixture-agent",
                        "session_scope": "agent+session",
                        "session_hash": "a" * 64,
                        "summary": {
                            "active": True,
                            "catalog_tool_count": 2,
                            "visible_tool_count": 1,
                            "filtered_tool_count": 1,
                            "quarantined_tool_count": 0,
                            "projection_blocked_tool_count": 0,
                            "conflict_count": 0,
                        },
                        "visible_tools": [{"name": "safe.tool", "route": "default"}],
                        "filtered_tools": [{"name": "secret.tool"}],
                    }
                )
            if parsed.path.endswith("/api/mcp/context/evidence"):
                return _JsonResponse(
                    {
                        "schema_version": "mcp-context-operator-inventory.v1",
                        "agent": "fixture-agent",
                        "session_scope": "agent+session",
                        "session_hash": "b" * 64,
                        "summary": {
                            "active": True,
                            "catalog_entry_count": 3,
                            "visible_context_count": 2,
                            "filtered_context_count": 1,
                            "conflict_count": 0,
                            "failed_route_count": 0,
                        },
                        "visible_context": [{"identifier": "file://safe"}],
                    }
                )
            body = json.loads(request.data.decode("utf-8"))  # type: ignore[attr-defined]
            if body["method"] == "initialize":
                return _JsonResponse(
                    {"jsonrpc": "2.0", "id": body["id"], "result": {"protocolVersion": "2025-06-18"}}
                )
            if body["method"] == "tools/list":
                return _JsonResponse(
                    {
                        "jsonrpc": "2.0",
                        "id": body["id"],
                        "result": {
                            "tools": [{"name": "safe.tool", "description": "clean"}],
                            "zhiAnSentinel": {},
                        },
                    }
                )
            return _JsonResponse(
                {
                    "jsonrpc": "2.0",
                    "id": body["id"],
                    "result": {"isError": False, "zhiAnSentinel": {"audit_id": "operator-probe-audit"}},
                }
            )

        with tempfile.TemporaryDirectory() as tmp:
            output_path = Path(tmp) / "mcp-operator-probe.json"
            args = argparse.Namespace(
                url="http://example.test/api/mcp",
                api_token="agent-secret",
                operator_api_token="operator-secret",
                operator_agent_id="fixture-agent",
                session_id="operator-session",
                tool="safe.tool",
                arguments="{}",
                expected_decision="允许",
                timeout=3.0,
                output=str(output_path),
            )
            with patch("apps.api.agent_supervisor.commands.cli.urllib.request.urlopen", side_effect=fake_urlopen):
                cmd_mcp_probe(args)

            report = json.loads(output_path.read_text(encoding="utf-8"))
            dumped = json.dumps(report, ensure_ascii=False)
            self.assertTrue(report["contract"]["operator_evidence_passed"])
            self.assertTrue(report["summary"]["operator_evidence_passed"])
            self.assertEqual(report["operator_evidence"]["tools"]["summary"]["filtered_tool_count"], 1)
            self.assertEqual(report["operator_evidence"]["context"]["summary"]["visible_context_count"], 2)
            self.assertNotIn("operator-secret", dumped)
            self.assertNotIn("secret.tool", dumped)

    def test_mcp_call_contract_reads_blocked_context_from_json_rpc_error_data(self) -> None:
        contract = _mcp_call_contract(
            {
                "http_status": 200,
                "transport_error": "",
                "response_payload": {
                    "jsonrpc": "2.0",
                    "id": "poison-result-call",
                    "error": {
                        "code": -32001,
                        "message": "MCP Gateway 已隔离包含可疑指令的上下文响应。",
                        "data": {
                            "decision": "隔离",
                            "audit_id": "audit-context-1",
                            "context_scan_blocked": True,
                            "zhiAnSentinel": {"context_audit_id": "audit-context-1"},
                        },
                    },
                },
            },
            expected_decision="隔离",
        )

        self.assertTrue(contract["passed"])
        self.assertEqual(contract["decision"], "隔离")
        self.assertTrue(contract["is_error"])
        self.assertTrue(contract["audit_id_present"])

    def test_latest_mcp_probe_requires_current_source_and_contract(self) -> None:
        now = datetime.now(timezone.utc)
        payload = {
            "schema_version": "agent-supervisor.mcp-probe.v1",
            "source": "agent-supervisor-cli.mcp-probe",
            "generated_at": now.isoformat(),
            "endpoint": "http://127.0.0.1:8012/api/mcp",
            "gateway_source_fingerprint": gateway_source_fingerprint(),
            "summary": {
                "evidence_verdict": "complete",
                "initialize_ok": True,
                "tools_list_ok": True,
                "tool_call_passed": True,
                "audit_id_present": True,
            },
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "MCP网关当前代码探针.json"
            path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
            with patch("apps.api.agent_supervisor.domains.reports.readiness_checks.SANDBOX_REPORTS_DIR", root):
                selected = _latest_mcp_probe()

        self.assertEqual(selected["artifact_path"], str(path))
        self.assertEqual(selected["summary"]["evidence_verdict"], "complete")

    def test_latest_mcp_probe_accepts_stable_ascii_artifact_name(self) -> None:
        now = datetime.now(timezone.utc)
        payload = {
            "schema_version": "agent-supervisor.mcp-probe.v1",
            "source": "agent-supervisor-cli.mcp-probe",
            "generated_at": now.isoformat(),
            "endpoint": "http://127.0.0.1:8034/api/mcp",
            "gateway_source_fingerprint": gateway_source_fingerprint(),
            "summary": {
                "evidence_verdict": "complete",
                "initialize_ok": True,
                "tools_list_ok": True,
                "tool_call_passed": True,
                "audit_id_present": True,
            },
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "current-mcp-probe-8034.json"
            path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
            with patch("apps.api.agent_supervisor.domains.reports.readiness_checks.SANDBOX_REPORTS_DIR", root):
                selected = _latest_mcp_probe()

        self.assertEqual(selected["artifact_path"], str(path))
        self.assertEqual(selected["summary"]["evidence_verdict"], "complete")


if __name__ == "__main__":
    unittest.main()
