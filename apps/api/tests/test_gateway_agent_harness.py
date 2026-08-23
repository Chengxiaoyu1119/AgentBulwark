from __future__ import annotations

import argparse
import hashlib
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any
from unittest.mock import patch

from apps.api.agent_supervisor.commands.cli import (
    _canonical_payload_hash,
    _gateway_comparison_payload,
    _gateway_contract_evidence,
    cmd_gateway_agent_run,
)
from apps.api.agent_supervisor.domains.reports.gateway_evidence import gateway_evidence_fingerprint
from apps.api.agent_supervisor.domains.reports.readiness_checks import (
    _gateway_causal_control_check,
    _real_gateway_agent_evidence_check,
)
from apps.api.sandbox.fixtures.openai_gateway_provider import _response as fixture_provider_response


class _Response:
    def __init__(self, payload: dict, status: int = 200) -> None:
        self.status = status
        self._body = json.dumps(payload, ensure_ascii=False).encode("utf-8")

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self) -> bytes:
        return self._body


def _request_hash(request_payload: dict) -> str:
    canonical = json.dumps(request_payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class GatewayAgentHarnessTests(unittest.TestCase):
    def test_fixture_provider_recognizes_hyphenated_causal_marker_requests(self) -> None:
        response = fixture_provider_response(
            {
                "model": "fixture-model",
                "messages": [
                    {
                        "role": "user",
                        "content": "Call file_write with path causal-marker.txt and content CAUSAL_MARKER.",
                    }
                ],
            }
        )

        message = response["choices"][0]["message"]
        self.assertEqual(message["tool_calls"][0]["function"]["name"], "file_write")

    def test_readiness_promotes_complete_real_gateway_batch_to_p0_pass(self) -> None:
        from datetime import datetime, timezone

        payload = {
            "schema_version": "agent-supervisor.gateway-agent-run.v1",
            "source": "agent-supervisor-cli.gateway-agent-run",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "gateway_evidence_fingerprint": gateway_evidence_fingerprint(),
            "gateway_path_exercised": True,
            "endpoint": "http://127.0.0.1:8012/v1/chat/completions",
            "summary": {
                "case_count": 4,
                "gateway_contract_passed_count": 4,
                "evidence_verdict": "complete",
                "attack_case_count": 1,
                "attack_blocked_count": 1,
                "benign_case_count": 3,
                "benign_false_positive_count": 0,
                "provider_called_count": 3,
                "public_ip_provider_evidence_count": 3,
                "external_provider_evidence_count": 3,
                # Managed mode consumes the Provider tool call and must not
                # leak it to the Agent; readiness uses the separate
                # provider_tool_call_count evidence field.
                "returned_tool_call_count": 0,
                "provider_tool_call_count": 1,
                "managed_execution_count": 1,
                "server_observed_receipt_count": 1,
                "blocked_tool_call_leak_count": 0,
                "gateway_contract_pass_rate": 100,
                "post_provider_tool_call_control_count": 1,
            },
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "真实Agent网关运行证据-20260817-000000.json").write_text(
                json.dumps(payload, ensure_ascii=False), encoding="utf-8"
            )
            with patch("apps.api.agent_supervisor.domains.reports.readiness_checks.SANDBOX_REPORTS_DIR", root):
                check = _real_gateway_agent_evidence_check()

        self.assertEqual(check["status"], "passed")
        self.assertEqual(check["severity"], "P0")

    def test_readiness_does_not_promote_local_fixture_as_external_gateway_evidence(self) -> None:
        from datetime import datetime, timezone

        payload = {
            "schema_version": "agent-supervisor.gateway-agent-run.v1",
            "source": "agent-supervisor-cli.gateway-agent-run",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "gateway_evidence_fingerprint": gateway_evidence_fingerprint(),
            "gateway_path_exercised": True,
            "endpoint": "http://127.0.0.1:8012/v1/chat/completions",
            "summary": {
                "case_count": 4,
                "gateway_contract_passed_count": 4,
                "evidence_verdict": "complete",
                "attack_case_count": 1,
                "attack_blocked_count": 1,
                "benign_case_count": 3,
                "benign_false_positive_count": 0,
                "provider_called_count": 3,
                "public_ip_provider_evidence_count": 0,
                "external_provider_evidence_count": 0,
                "returned_tool_call_count": 1,
                "managed_execution_count": 1,
                "server_observed_receipt_count": 1,
                "blocked_tool_call_leak_count": 0,
                "gateway_contract_pass_rate": 100,
                "post_provider_tool_call_control_count": 1,
            },
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "真实Agent网关运行证据-20260817-000000.json").write_text(
                json.dumps(payload, ensure_ascii=False), encoding="utf-8"
            )
            with patch("apps.api.agent_supervisor.domains.reports.readiness_checks.SANDBOX_REPORTS_DIR", root):
                check = _real_gateway_agent_evidence_check()

        self.assertEqual(check["status"], "blocked")

    def test_causal_readiness_requires_baseline_and_hash_aligned_comparison(self) -> None:
        from datetime import datetime, timezone

        base: dict[str, Any] = {
            "schema_version": "agent-supervisor.gateway-agent-run.v1",
            "source": "agent-supervisor-cli.gateway-agent-run",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "gateway_evidence_fingerprint": gateway_evidence_fingerprint(),
            "gateway_path_exercised": True,
            "endpoint": "http://127.0.0.1:8012/v1/chat/completions",
            "baseline_endpoint": "",
            "baseline_path_exercised": False,
            "summary": {
                "case_count": 1,
                "attack_case_count": 1,
                "baseline_case_count": 0,
                "causal_attack_comparison_count": 0,
                "causal_tool_call_control_count": 0,
                "evidence_verdict": "complete",
            },
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / "真实Agent网关运行证据-20260817-000001.json"
            artifact.write_text(json.dumps(base, ensure_ascii=False), encoding="utf-8")
            with patch("apps.api.agent_supervisor.domains.reports.readiness_checks.SANDBOX_REPORTS_DIR", root):
                missing_baseline = _gateway_causal_control_check()
            self.assertEqual(missing_baseline["status"], "blocked")

            base["baseline_endpoint"] = "http://provider.example/v1/chat/completions"
            base["baseline_path_exercised"] = True
            base["summary"]["baseline_case_count"] = 1
            base["summary"]["causal_attack_comparison_count"] = 1
            base["summary"]["causal_tool_call_control_count"] = 1
            base["summary"]["post_provider_tool_call_control_count"] = 1
            base["summary"]["public_ip_provider_evidence_count"] = 0
            base["summary"]["network_verified_external_provider_evidence_count"] = 1
            artifact.write_text(json.dumps(base, ensure_ascii=False), encoding="utf-8")
            with (
                patch("apps.api.agent_supervisor.domains.reports.readiness_checks.SANDBOX_REPORTS_DIR", root),
                patch(
                    "apps.api.agent_supervisor.domains.reports.readiness_checks._latest_side_effect_comparison",
                    return_value={"side_effect_suppressed": True},
                ),
            ):
                aligned = _gateway_causal_control_check()
            self.assertEqual(aligned["status"], "passed")

    def test_causal_readiness_does_not_promote_hostname_only_provider_route(self) -> None:
        from datetime import datetime, timezone

        payload = {
            "schema_version": "agent-supervisor.gateway-agent-run.v1",
            "source": "agent-supervisor-cli.gateway-agent-run",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "gateway_evidence_fingerprint": gateway_evidence_fingerprint(),
            "gateway_path_exercised": True,
            "endpoint": "http://127.0.0.1:8012/v1/chat/completions",
            "baseline_endpoint": "https://provider.example/v1/chat/completions",
            "baseline_path_exercised": True,
            "summary": {
                "case_count": 1,
                "attack_case_count": 1,
                "baseline_case_count": 1,
                "causal_attack_comparison_count": 1,
                "causal_tool_call_control_count": 1,
                "post_provider_tool_call_control_count": 1,
                "remote_hostname_provider_route_count": 1,
                # Deliberately omit the strict public-IP count. A hostname
                # route alone is not proof of a public Provider.
                "evidence_verdict": "complete",
            },
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / "真实Agent网关运行证据-20260817-000002.json"
            artifact.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
            with patch("apps.api.agent_supervisor.domains.reports.readiness_checks.SANDBOX_REPORTS_DIR", root):
                check = _gateway_causal_control_check()

        self.assertEqual(check["status"], "blocked")
        self.assertEqual(check["details"]["public_ip_provider_evidence_count"], 0)
        self.assertEqual(check["details"]["remote_hostname_provider_route_count"], 1)

    def test_causal_readiness_accepts_persisted_causal_facts_from_agent_run_artifact(self) -> None:
        from datetime import datetime, timezone

        payload = {
            "schema_version": "agent-supervisor.gateway-agent-run.v1",
            "source": "agent-supervisor-cli.gateway-agent-run",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "gateway_evidence_fingerprint": gateway_evidence_fingerprint(),
            "gateway_path_exercised": True,
            "baseline_path_exercised": False,
            "causal_path_exercised": True,
            "endpoint": "http://127.0.0.1:8012/v1/chat/completions",
            "summary": {
                "case_count": 1,
                "gateway_contract_passed_count": 1,
                "evidence_verdict": "complete",
                "attack_case_count": 1,
                "attack_blocked_count": 1,
                "benign_case_count": 0,
                "benign_false_positive_count": 0,
                "provider_called_count": 1,
                "network_verified_external_provider_evidence_count": 1,
                "causal_attack_comparison_count": 1,
                "causal_tool_call_control_count": 1,
                "post_provider_tool_call_control_count": 1,
            },
            "cases": [
                {
                    "id": "artifact-causal-1",
                    "label": "attack",
                    "causal_runtime": {
                        "available": True,
                        "passed": True,
                        "comparison_id": "comparison-artifact-1",
                        "request_hash": "a" * 64,
                        "baseline_state_changed": True,
                        "guarded_state_changed": False,
                        "side_effect_suppressed": True,
                        "evidence_persisted": True,
                        "event_id": 99,
                    },
                }
            ],
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / "current-gateway-agent-run-artifact.json"
            artifact.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
            with patch("apps.api.agent_supervisor.domains.reports.readiness_checks.SANDBOX_REPORTS_DIR", root):
                check = _gateway_causal_control_check()

        self.assertEqual(check["status"], "passed")
        self.assertEqual(check["details"]["side_effect_suppression_count"], 1)
        self.assertEqual(check["details"]["side_effect_comparison"]["source"], "gateway-agent-run-artifact")

    def test_readiness_accepts_gateway_verified_public_dns_route(self) -> None:
        from datetime import datetime, timezone

        payload = {
            "schema_version": "agent-supervisor.gateway-agent-run.v1",
            "source": "agent-supervisor-cli.gateway-agent-run",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "gateway_evidence_fingerprint": gateway_evidence_fingerprint(),
            "gateway_path_exercised": True,
            "endpoint": "http://127.0.0.1:8012/v1/chat/completions",
            "summary": {
                "case_count": 4,
                "gateway_contract_passed_count": 4,
                "evidence_verdict": "complete",
                "attack_case_count": 1,
                "attack_blocked_count": 1,
                "benign_case_count": 3,
                "benign_false_positive_count": 0,
                "provider_called_count": 3,
                "public_ip_provider_evidence_count": 0,
                "network_verified_external_provider_evidence_count": 3,
                "remote_hostname_provider_route_count": 3,
                "provider_tool_call_count": 1,
                "managed_execution_count": 1,
                "server_observed_receipt_count": 1,
                "blocked_tool_call_leak_count": 0,
                "gateway_contract_pass_rate": 100,
            },
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "真实Agent网关运行证据-20260817-000003.json").write_text(
                json.dumps(payload, ensure_ascii=False), encoding="utf-8"
            )
            with patch("apps.api.agent_supervisor.domains.reports.readiness_checks.SANDBOX_REPORTS_DIR", root):
                check = _real_gateway_agent_evidence_check()

        self.assertEqual(check["status"], "passed")
        self.assertEqual(check["details"]["network_verified_external_provider_evidence_count"], 3)

    def test_tool_definition_block_is_a_valid_pre_provider_contract(self) -> None:
        request_hash = "a" * 64
        evidence = _gateway_contract_evidence(
            status=200,
            request_hash=request_hash,
            response_payload={
                "choices": [{"message": {"role": "assistant", "content": "quarantined"}}],
                "agent_supervisor": {
                    "decision": "隔离",
                    "provider_called": False,
                    "request_stage": "tool-definition",
                    "request_hash": request_hash,
                    "gateway_evidence_fingerprint": gateway_evidence_fingerprint(),
                    "evidence_scope": "gateway-contract",
                    "audit_id": "audit-tool-definition",
                    "decision_enforced_before_tool_execution": True,
                },
            },
        )

        self.assertTrue(evidence["passed"])
        self.assertTrue(evidence["provider_not_called_proof"])

    def test_harness_sends_each_payload_and_aggregates_real_gateway_contract(self) -> None:
        def fake_urlopen(request: object, timeout: float) -> _Response:
            del timeout
            body = json.loads(request.data.decode("utf-8"))  # type: ignore[attr-defined]
            request_hash = _request_hash(body)
            message = str(body["messages"][0].get("content") or "")
            if "attack" in message:
                metadata = {
                    "decision": "拒绝",
                    "provider_called": False,
                    "request_stage": "pre-provider-input",
                    "request_hash": request_hash,
                    "gateway_evidence_fingerprint": gateway_evidence_fingerprint(),
                    "evidence_scope": "gateway-contract",
                    "audit_id": "audit-attack",
                    "decision_enforced_before_tool_execution": True,
                    "execution_boundary": "gateway-blocked-before-provider",
                }
                response: dict[str, object] = {
                    "choices": [{"message": {"role": "assistant", "content": "blocked"}}],
                    "agent_supervisor": metadata,
                }
            else:
                metadata = {
                    "decision": "允许",
                    "provider_called": True,
                    "request_hash": request_hash,
                    "provider_request_hash": "b" * 64,
                    "provider_response_hash": "c" * 64,
                    "provider_endpoint_scope": "external-or-hostname-provider",
                    "provider_network_observation": {
                        "schema_version": "agent-supervisor.provider-network-observation.v1",
                        "checked": True,
                        "address_classification": "public",
                        "verified_public_route": True,
                        "resolved_address_count": 1,
                        "public_address_count": 1,
                        "private_address_count": 0,
                    },
                    "gateway_evidence_fingerprint": gateway_evidence_fingerprint(),
                    "evidence_scope": "gateway-contract",
                    "audit_id": "audit-normal",
                    "execution_boundary": "caller-owned-tool-execution",
                }
                response = {
                    "choices": [{"message": {"role": "assistant", "content": "ok"}}],
                    "agent_supervisor": metadata,
                }
            return _Response(response)

        with tempfile.TemporaryDirectory() as tmp:
            input_path = Path(tmp) / "cases.json"
            output_path = Path(tmp) / "evidence.json"
            input_path.write_text(
                json.dumps(
                    {
                        "cases": [
                            {
                                "id": "attack-1",
                                "label": "attack",
                                "expected_control": True,
                                "payload": {
                                    "model": "fixture-model",
                                    "messages": [{"role": "user", "content": "attack"}],
                                },
                            },
                            {
                                "id": "normal-1",
                                "label": "benign",
                                "expected_control": False,
                                "payload": {
                                    "model": "fixture-model",
                                    "messages": [{"role": "user", "content": "normal"}],
                                },
                            },
                        ]
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            args = argparse.Namespace(
                input=str(input_path),
                json="",
                url="http://example.test/v1/chat/completions?token=secret",
                api_token="Bearer-secret",
                session_id="harness",
                timeout=3.0,
                output=str(output_path),
            )
            with patch(
                "apps.api.agent_supervisor.commands.cli.urllib.request.urlopen",
                side_effect=fake_urlopen,
            ) as urlopen, redirect_stdout(io.StringIO()):
                cmd_gateway_agent_run(args)

            report = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(urlopen.call_count, 2)
            self.assertEqual(report["summary"]["case_count"], 2)
            self.assertEqual(report["summary"]["gateway_contract_passed_count"], 2)
            self.assertEqual(report["summary"]["attack_blocked_count"], 1)
            self.assertEqual(report["summary"]["benign_false_positive_count"], 0)
            self.assertEqual(report["summary"]["evidence_verdict"], "complete")
            self.assertEqual(report["summary"]["remote_hostname_provider_route_count"], 1)
            self.assertEqual(report["summary"]["external_hostname_provider_case_count"], 1)
            self.assertEqual(report["summary"]["public_ip_provider_evidence_count"], 0)
            self.assertEqual(report["summary"]["external_provider_evidence_count"], 0)
            self.assertEqual(report["summary"]["network_verified_external_provider_evidence_count"], 1)
            self.assertNotIn("secret", json.dumps(report, ensure_ascii=False))
            self.assertNotIn("Bearer-secret", json.dumps(report, ensure_ascii=False))
            self.assertNotIn("token=", report["endpoint"])
            self.assertEqual(report["cases"][0]["gateway_contract"]["provider_not_called_proof"], True)

    def test_harness_can_run_explicit_sandbox_causal_gateway_comparison(self) -> None:
        captured: list[dict[str, Any]] = []

        def fake_urlopen(request: object, timeout: float) -> _Response:
            del timeout
            body = json.loads(request.data.decode("utf-8"))  # type: ignore[attr-defined]
            captured.append(body)
            if "/api/gateway/compare" in str(request.full_url):  # type: ignore[attr-defined]
                return _Response(
                    {
                        "schema_version": "agent-supervisor.gateway-comparison.v1",
                        "comparison_id": "comparison-1",
                        "request_hash": _request_hash(
                            {key: value for key, value in body.items() if key != "agent_supervisor"}
                        ),
                        "verdict": {
                            "causal_control_observed": True,
                            "causal_execution_complete": True,
                            "baseline_state_changed": True,
                            "guarded_state_changed": False,
                            "side_effect_suppressed": True,
                            "evidence_complete": True,
                        },
                        "evidence": {"event_id": 9, "persisted": True, "signature": "sig"},
                    }
                )
            request_hash = _request_hash(body)
            return _Response(
                {
                    "model": "fixture-model",
                    "choices": [{"message": {"role": "assistant", "content": "blocked"}}],
                    "agent_supervisor": {
                        "decision": "拒绝",
                        "provider_called": False,
                        "request_stage": "pre-provider-input",
                        "request_hash": request_hash,
                        "gateway_evidence_fingerprint": gateway_evidence_fingerprint(),
                        "evidence_scope": "gateway-contract",
                        "audit_id": "audit-causal-attack",
                        "decision_enforced_before_tool_execution": True,
                    },
                }
            )

        with tempfile.TemporaryDirectory() as tmp:
            output_path = Path(tmp) / "causal-evidence.json"
            args = argparse.Namespace(
                input="",
                json=json.dumps(
                    {
                        "cases": [
                            {
                                "id": "causal-attack",
                                "label": "attack",
                                "expected_control": True,
                                "payload": {
                                    "model": "fixture-model",
                                    "messages": [{"role": "user", "content": "attack"}],
                                    "agent_supervisor": {"agent_id": "caller-controlled"},
                                },
                            }
                        ]
                    },
                    ensure_ascii=False,
                ),
                url="http://gateway.example/v1/chat/completions",
                api_token="gateway-secret",
                causal_url="http://gateway.example/api/gateway/compare",
                session_id="causal-harness",
                timeout=3.0,
                output=str(output_path),
            )
            with patch(
                "apps.api.agent_supervisor.commands.cli.urllib.request.urlopen",
                side_effect=fake_urlopen,
            ), redirect_stdout(io.StringIO()):
                cmd_gateway_agent_run(args)

            report = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(len(captured), 2)
            self.assertEqual(captured[1]["agent_supervisor"], {"comparison_mode": "sandbox-causal"})
            self.assertEqual(report["causal_path_exercised"], True)
            self.assertEqual(report["summary"]["causal_runtime_case_count"], 1)
            self.assertEqual(report["summary"]["causal_runtime_passed_count"], 1)
            self.assertEqual(report["summary"]["causal_side_effect_suppressed_count"], 1)
            self.assertEqual(report["summary"]["causal_attack_comparison_count"], 1)
            self.assertEqual(report["summary"]["causal_tool_call_control_count"], 1)
            self.assertEqual(report["summary"]["post_provider_tool_call_control_count"], 0)
            self.assertTrue(report["cases"][0]["verdict"]["causal_runtime_comparison"])
            self.assertTrue(report["cases"][0]["causal_runtime"]["baseline_state_changed"])
            self.assertFalse(report["cases"][0]["causal_runtime"]["guarded_state_changed"])
            self.assertNotIn("gateway-secret", json.dumps(report, ensure_ascii=False))

    def test_harness_records_http_failure_as_partial_evidence(self) -> None:
        def fake_urlopen(*_args: object, **_kwargs: object) -> _Response:
            return _Response({"detail": "provider unavailable"}, status=502)

        with tempfile.TemporaryDirectory() as tmp:
            output_path = Path(tmp) / "evidence.json"
            args = argparse.Namespace(
                input="",
                json=json.dumps(
                    {
                        "cases": [
                            {
                                "id": "provider-failure",
                                "label": "normal",
                                "payload": {
                                    "model": "fixture-model",
                                    "messages": [{"role": "user", "content": "hello"}],
                                },
                            }
                        ]
                    },
                    ensure_ascii=False,
                ),
                url="http://127.0.0.1:8012/v1/chat/completions",
                api_token="",
                session_id="",
                timeout=3.0,
                output=str(output_path),
            )
            with patch(
                "apps.api.agent_supervisor.commands.cli.urllib.request.urlopen",
                side_effect=fake_urlopen,
            ), redirect_stdout(io.StringIO()):
                cmd_gateway_agent_run(args)

            report = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(report["summary"]["http_success_count"], 0)
            self.assertEqual(report["summary"]["response_error_count"], 1)
            self.assertEqual(report["summary"]["evidence_verdict"], "partial")
            self.assertFalse(report["cases"][0]["gateway_contract"]["passed"])
            self.assertEqual(report["cases"][0]["response_error"], "provider unavailable")

    def test_harness_strict_mode_turns_partial_evidence_into_nonzero_result(self) -> None:
        def fake_urlopen(*_args: object, **_kwargs: object) -> _Response:
            return _Response({"detail": "provider unavailable"}, status=502)

        with tempfile.TemporaryDirectory() as tmp:
            output_path = Path(tmp) / "strict-evidence.json"
            args = argparse.Namespace(
                input="",
                json=json.dumps(
                    {
                        "cases": [
                            {
                                "id": "strict-provider-failure",
                                "label": "normal",
                                "payload": {
                                    "model": "fixture-model",
                                    "messages": [{"role": "user", "content": "hello"}],
                                },
                            }
                        ]
                    },
                    ensure_ascii=False,
                ),
                url="http://127.0.0.1:8012/v1/chat/completions",
                api_token="",
                session_id="",
                timeout=3.0,
                output=str(output_path),
                strict=True,
            )
            with (
                patch(
                    "apps.api.agent_supervisor.commands.cli.urllib.request.urlopen",
                    side_effect=fake_urlopen,
                ),
                redirect_stdout(io.StringIO()),
            ):
                with self.assertRaises(SystemExit) as raised:
                    cmd_gateway_agent_run(args)

            self.assertEqual(raised.exception.code, "gateway-agent-run contract did not pass")
            report = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(report["summary"]["evidence_verdict"], "partial")

    def test_harness_strict_mode_rejects_contract_clean_but_unexpected_decision(self) -> None:
        """A healthy HTTP envelope must not hide a failed expected outcome."""

        def fake_urlopen(request: object, timeout: float) -> _Response:
            del timeout
            body = json.loads(request.data.decode("utf-8"))  # type: ignore[attr-defined]
            request_hash = _request_hash(body)
            return _Response(
                {
                    "model": "fixture-model",
                    "choices": [{"message": {"role": "assistant", "content": "allowed"}}],
                    "agent_supervisor": {
                        "decision": "允许",
                        "provider_called": True,
                        "request_stage": "post-provider-output",
                        "request_hash": request_hash,
                        "provider_request_hash": "b" * 64,
                        "provider_response_hash": "c" * 64,
                        "provider_endpoint_scope": "external-provider",
                        "provider_network_observation": {
                            "verified_public_route": True,
                            "resolved_address_count": 1,
                            "public_address_count": 1,
                            "private_address_count": 0,
                        },
                        "gateway_evidence_fingerprint": gateway_evidence_fingerprint(),
                        "evidence_scope": "gateway-contract",
                        "audit_id": "audit-unexpected-allow",
                        "execution_boundary": "caller-owned-tool-execution",
                    },
                }
            )

        with tempfile.TemporaryDirectory() as tmp:
            output_path = Path(tmp) / "unexpected-decision.json"
            args = argparse.Namespace(
                input="",
                json=json.dumps(
                    {
                        "cases": [
                            {
                                "id": "expected-block",
                                "label": "attack",
                                "expected_control": True,
                                "payload": {
                                    "model": "fixture-model",
                                    "messages": [{"role": "user", "content": "attack"}],
                                },
                            }
                        ]
                    },
                    ensure_ascii=False,
                ),
                url="http://127.0.0.1:8012/v1/chat/completions",
                api_token="",
                session_id="strict-expectation",
                timeout=3.0,
                output=str(output_path),
                strict=True,
            )
            with (
                patch(
                    "apps.api.agent_supervisor.commands.cli.urllib.request.urlopen",
                    side_effect=fake_urlopen,
                ),
                redirect_stdout(io.StringIO()),
            ):
                with self.assertRaises(SystemExit) as raised:
                    cmd_gateway_agent_run(args)

            self.assertEqual(raised.exception.code, "gateway-agent-run contract did not pass")
            report = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(report["summary"]["gateway_contract_pass_rate"], 100)
            self.assertEqual(report["summary"]["expected_match_rate"], 0)
            self.assertEqual(report["summary"]["evidence_verdict"], "partial")
            self.assertFalse(report["strict_gate"]["passed"])
            self.assertIn("预期结果仅匹配 0/1", report["strict_gate"]["reasons"])

    def test_harness_can_record_unprotected_provider_baseline_for_causal_comparison(self) -> None:
        def fake_urlopen(request: object, timeout: float) -> _Response:
            del timeout
            body = json.loads(request.data.decode("utf-8"))  # type: ignore[attr-defined]
            if "provider.example" in str(request.full_url):  # type: ignore[attr-defined]
                response: dict[str, object] = {
                    "model": "fixture-model",
                    "id": "provider-direct",
                    "choices": [
                        {
                            "message": {
                                "role": "assistant",
                                "tool_calls": [
                                    {
                                        "id": "direct-call-1",
                                        "type": "function",
                                        "function": {"name": "file_read", "arguments": "{}"},
                                    }
                                ],
                            },
                            "finish_reason": "tool_calls",
                        }
                    ],
                }
                return _Response(response)
            request_hash = _request_hash(body)
            response = {
                "model": "fixture-model",
                "choices": [{"message": {"role": "assistant", "content": "blocked"}}],
                "agent_supervisor": {
                    "decision": "拒绝",
                    "provider_called": True,
                    "request_stage": "post-provider-output",
                    "request_hash": request_hash,
                    "provider_request_hash": "b" * 64,
                    "provider_response_hash": "c" * 64,
                    "gateway_evidence_fingerprint": gateway_evidence_fingerprint(),
                    "evidence_scope": "gateway-contract",
                    "audit_id": "audit-attack",
                    "tool_decisions": [
                        {
                            "call_id": "provider-call-1",
                            "decision": "拒绝",
                            "audit_id": "audit-attack",
                        }
                    ],
                    "decision_enforced_before_tool_execution": True,
                    "execution_boundary": "gateway-blocked-before-tool-execution",
                },
            }
            return _Response(response)

        with tempfile.TemporaryDirectory() as tmp:
            output_path = Path(tmp) / "causal.json"
            args = argparse.Namespace(
                input="",
                json=json.dumps(
                    {
                        "cases": [
                            {
                                "id": "attack-1",
                                "label": "attack",
                                "expected_control": True,
                                "payload": {
                                    "model": "fixture-model",
                                    "messages": [{"role": "user", "content": "attack"}],
                                },
                            }
                        ]
                    },
                    ensure_ascii=False,
                ),
                url="http://gateway.example/v1/chat/completions",
                api_token="",
                baseline_url="http://provider.example/v1/chat/completions",
                baseline_api_token="provider-secret",
                session_id="causal",
                timeout=3.0,
                output=str(output_path),
            )
            with patch(
                "apps.api.agent_supervisor.commands.cli.urllib.request.urlopen",
                side_effect=fake_urlopen,
            ), redirect_stdout(io.StringIO()):
                cmd_gateway_agent_run(args)

            report = json.loads(output_path.read_text(encoding="utf-8"))
            row = report["cases"][0]
            self.assertEqual(report["summary"]["baseline_case_count"], 1)
            self.assertEqual(report["summary"]["baseline_attack_tool_call_count"], 1)
            self.assertEqual(report["summary"]["causal_attack_comparison_count"], 1)
            self.assertEqual(report["summary"]["post_provider_tool_call_control_count"], 1)
            self.assertTrue(row["baseline"]["tool_call_returned"])
            self.assertTrue(row["baseline"]["request_hash_matches_comparison"])
            self.assertEqual(row["comparison_request_hash"], row["baseline"]["comparison_request_hash"])
            self.assertTrue(row["causal_comparison"]["passed"])
            self.assertTrue(row["verdict"]["attack_blocked"])
            dumped = json.dumps(report, ensure_ascii=False)
            self.assertNotIn("provider-secret", dumped)

    def test_comparison_payload_removes_only_gateway_control_envelope(self) -> None:
        payload = {
            "model": "fixture-model",
            "messages": [{"role": "user", "content": "same input"}],
            "tools": [{"type": "function", "function": {"name": "file_read"}}],
            "metadata": {"caller": "agent-a"},
            "agent_supervisor": {"mode": "managed", "session_id": "session-a"},
        }

        comparison = _gateway_comparison_payload(payload)

        self.assertNotIn("agent_supervisor", comparison)
        self.assertEqual(comparison["messages"], payload["messages"])
        self.assertEqual(comparison["tools"], payload["tools"])
        self.assertEqual(comparison["metadata"], payload["metadata"])
        self.assertEqual(_canonical_payload_hash(comparison), _request_hash(comparison))

    def test_causal_comparison_accepts_pre_provider_quarantine_after_baseline_tool_call(self) -> None:
        """A poisoned schema can be stopped before the Provider sees it.

        The baseline still proves the same payload would have produced a tool
        call.  Requiring a post-Provider ``tool_decisions`` row would erase
        this stronger early-control evidence.
        """

        def fake_urlopen(request: object, timeout: float) -> _Response:
            del timeout
            body = json.loads(request.data.decode("utf-8"))  # type: ignore[attr-defined]
            if "provider.example" in str(request.full_url):  # type: ignore[attr-defined]
                return _Response(
                    {
                        "model": "fixture-model",
                        "choices": [
                            {
                                "message": {
                                    "role": "assistant",
                                    "tool_calls": [
                                        {
                                            "id": "direct-call-early",
                                            "type": "function",
                                            "function": {"name": "file_read", "arguments": "{}"},
                                        }
                                    ],
                                }
                            }
                        ],
                    }
                )
            request_hash = _request_hash(body)
            return _Response(
                {
                    "model": "fixture-model",
                    "choices": [{"message": {"role": "assistant", "content": "blocked"}}],
                    "agent_supervisor": {
                        "decision": "隔离",
                        "provider_called": False,
                        "request_stage": "tool-definition",
                        "request_hash": request_hash,
                        "gateway_evidence_fingerprint": gateway_evidence_fingerprint(),
                        "evidence_scope": "gateway-contract",
                        "audit_id": "audit-early",
                        "decision_enforced_before_tool_execution": True,
                        "execution_boundary": "gateway-blocked-before-provider",
                    },
                }
            )

        with tempfile.TemporaryDirectory() as tmp:
            output_path = Path(tmp) / "early-causal.json"
            args = argparse.Namespace(
                input="",
                json=json.dumps(
                    {
                        "cases": [
                            {
                                "id": "attack-early",
                                "label": "attack",
                                "expected_control": True,
                                "payload": {
                                    "model": "fixture-model",
                                    "messages": [{"role": "user", "content": "attack"}],
                                },
                            }
                        ]
                    },
                    ensure_ascii=False,
                ),
                url="http://gateway.example/v1/chat/completions",
                api_token="",
                baseline_url="http://provider.example/v1/chat/completions",
                baseline_api_token="provider-secret",
                session_id="early-causal",
                timeout=3.0,
                output=str(output_path),
            )
            with patch(
                "apps.api.agent_supervisor.commands.cli.urllib.request.urlopen",
                side_effect=fake_urlopen,
            ), redirect_stdout(io.StringIO()):
                cmd_gateway_agent_run(args)

            report = json.loads(output_path.read_text(encoding="utf-8"))
            row = report["cases"][0]
            self.assertEqual(report["summary"]["causal_attack_comparison_count"], 1)
            self.assertEqual(report["summary"]["causal_tool_call_control_count"], 1)
            self.assertTrue(row["causal_comparison"]["gateway_tool_call_control"])
            self.assertFalse(row["causal_comparison"]["post_provider_tool_call_block"])

    def test_causal_comparison_rejects_baseline_model_mismatch(self) -> None:
        def fake_urlopen(request: object, timeout: float) -> _Response:
            del timeout
            body = json.loads(request.data.decode("utf-8"))  # type: ignore[attr-defined]
            if "provider.example" in str(request.full_url):  # type: ignore[attr-defined]
                return _Response(
                    {
                        "model": "different-model",
                        "choices": [
                            {
                                "message": {
                                    "role": "assistant",
                                    "tool_calls": [
                                        {
                                            "id": "direct-call-mismatch",
                                            "type": "function",
                                            "function": {"name": "file_read", "arguments": "{}"},
                                        }
                                    ],
                                }
                            }
                        ],
                    }
                )
            request_hash = _request_hash(body)
            return _Response(
                {
                    "model": "fixture-model",
                    "choices": [{"message": {"role": "assistant", "content": "blocked"}}],
                    "agent_supervisor": {
                        "decision": "拒绝",
                        "provider_called": False,
                        "request_stage": "pre-provider-input",
                        "request_hash": request_hash,
                        "gateway_evidence_fingerprint": gateway_evidence_fingerprint(),
                        "evidence_scope": "gateway-contract",
                        "audit_id": "audit-model-mismatch",
                        "decision_enforced_before_tool_execution": True,
                        "execution_boundary": "gateway-blocked-before-provider",
                    },
                }
            )

        with tempfile.TemporaryDirectory() as tmp:
            output_path = Path(tmp) / "mismatch.json"
            args = argparse.Namespace(
                input="",
                json=json.dumps(
                    {
                        "cases": [
                            {
                                "id": "attack-mismatch",
                                "label": "attack",
                                "expected_control": True,
                                "payload": {
                                    "model": "fixture-model",
                                    "messages": [{"role": "user", "content": "attack"}],
                                },
                            }
                        ]
                    },
                    ensure_ascii=False,
                ),
                url="http://gateway.example/v1/chat/completions",
                api_token="",
                baseline_url="http://provider.example/v1/chat/completions",
                baseline_api_token="provider-secret",
                session_id="model-mismatch",
                timeout=3.0,
                output=str(output_path),
            )
            with patch(
                "apps.api.agent_supervisor.commands.cli.urllib.request.urlopen",
                side_effect=fake_urlopen,
            ), redirect_stdout(io.StringIO()):
                cmd_gateway_agent_run(args)

            report = json.loads(output_path.read_text(encoding="utf-8"))
            row = report["cases"][0]
            self.assertFalse(row["causal_comparison"]["baseline_model_matches_request"])
            self.assertFalse(row["causal_comparison"]["passed"])
            self.assertEqual(report["summary"]["causal_attack_comparison_count"], 0)


if __name__ == "__main__":
    unittest.main()
