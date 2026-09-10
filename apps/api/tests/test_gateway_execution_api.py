from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from apps.api.agent_supervisor.domains.governance.integrity import audit_hash
from apps.api.agent_supervisor.domains.runtime.gateway_execution import GatewayExecutionUncertainError
from apps.api.agent_supervisor.main import app


class GatewayExecutionApiTests(unittest.TestCase):
    _REQUEST = {
        "agent_id": "gateway-agent",
        "session_id": "gateway-session",
        "provider_call_id": "provider-call-1",
    }

    def test_admin_executes_audited_call_without_client_tool_arguments(self) -> None:
        expected = {
            "audit_id": "audit-1",
            "idempotent": False,
            "provider_call_id": "provider-call-1",
            "execution_evidence": "server-observed",
            "execution_observed_by_server": True,
            "execution_result": {"executed": True},
            "tool_result": "public result",
            "tool_result_hash": "result-hash",
            "receipt": {"status": "completed", "receipt_hash": "receipt-hash"},
        }
        with (
            patch.dict(os.environ, {"AGENT_SUPERVISOR_AUTH_DISABLED": "true"}, clear=False),
            patch(
                "apps.api.agent_supervisor.routers.proxy.execute_gateway_tool_call",
                return_value=expected,
            ) as execute,
            TestClient(app) as client,
        ):
            response = client.post(
                "/api/gateway/tool_calls/audit-1/execute",
                json=self._REQUEST,
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), expected)
        execute.assert_called_once_with(
            "audit-1",
            agent_id="gateway-agent",
            session_id="gateway-session",
            provider_call_id="provider-call-1",
        )

    def test_unknown_extra_tool_payload_is_rejected(self) -> None:
        with (
            patch.dict(os.environ, {"AGENT_SUPERVISOR_AUTH_DISABLED": "true"}, clear=False),
            patch("apps.api.agent_supervisor.routers.proxy.execute_gateway_tool_call") as execute,
            TestClient(app) as client,
        ):
            response = client.post(
                "/api/gateway/tool_calls/audit-1/execute",
                json={**self._REQUEST, "tool": "file.write", "arguments": {"path": "secret.txt"}},
            )

        self.assertEqual(response.status_code, 422)
        execute.assert_not_called()

    def test_executor_identity_can_use_the_new_route(self) -> None:
        expected = {"audit_id": "audit-2", "idempotent": True}
        with (
            patch.dict(
                os.environ,
                {
                    "AGENT_SUPERVISOR_AUTH_DISABLED": "false",
                    "AGENT_SUPERVISOR_API_TOKEN": "",
                    "AGENT_SUPERVISOR_AGENT_TOKENS_JSON": '{"gateway-agent":"agent-token"}',
                    "AGENT_SUPERVISOR_DEFAULT_ROLE": "observer",
                },
                clear=False,
            ),
            patch(
                "apps.api.agent_supervisor.routers.proxy.execute_gateway_tool_call",
                return_value=expected,
            ) as execute,
            TestClient(app) as client,
        ):
            response = client.post(
                "/api/gateway/tool_calls/audit-2/execute",
                headers={"Authorization": "Bearer agent-token"},
                json=self._REQUEST,
            )

        self.assertEqual(response.status_code, 200)
        execute.assert_called_once()

    def test_execution_conflicts_return_reconciliation_contract(self) -> None:
        with (
            patch.dict(os.environ, {"AGENT_SUPERVISOR_AUTH_DISABLED": "true"}, clear=False),
            patch(
                "apps.api.agent_supervisor.routers.proxy.execute_gateway_tool_call",
                side_effect=GatewayExecutionUncertainError("执行状态不确定"),
            ),
            TestClient(app) as client,
        ):
            response = client.post(
                "/api/gateway/tool_calls/audit-3/execute",
                json=self._REQUEST,
            )

        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json()["detail"]["code"], "gateway_execution_uncertain")
        self.assertEqual(response.json()["detail"]["execution_status"], "unknown")
        self.assertEqual(response.json()["detail"]["retry"], "reconciliation-required")

    def test_evidence_detail_is_redacted_and_verified(self) -> None:
        audit = {
            "id": "audit-evidence-1",
            "source_app": "openai-compatible-proxy",
            "agent_id": "evidence-agent",
            "conversation_id": "evidence-session",
            "tool": "file.read",
            "arguments": {"path": "secret.txt"},
            "model_input": "secret prompt",
            "model_output": "secret provider output",
            "decision": "允许",
            "risk_level": "低",
            "risk_score": 8,
            "policy_id": "default-allow",
            "tool_call_hash": "a" * 64,
            "previous_hash": "b" * 64,
            "stage_context": {
                "request_id": "chatcmpl-evidence-1",
                "session_id": "evidence-session",
                "provider": "fixture",
                "provider_profile": "target",
                "provider_model": "fixture-model",
                "provider_response_id": "provider-evidence-1",
                "request_hash": "c" * 64,
                "provider_request_hash": "d" * 64,
                "provider_response_hash": "e" * 64,
                "provider_called": True,
            },
        }
        audit["audit_hash"] = audit_hash(audit)
        receipt = {
            "audit_id": "audit-evidence-1",
            "receipt_id": "receipt-evidence-1",
            "audit_hash": audit["audit_hash"],
            "result_content": "secret tool result",
            "receipt_hash": "f" * 64,
        }
        claim = {
            "audit_id": "audit-evidence-1",
            "claim_id": "claim-evidence-1",
            "agent_id": "evidence-agent",
            "session_id": "evidence-session",
            "tool_call_hash": "a" * 64,
            "status": "completed",
        }
        with (
            patch.dict(
                os.environ,
                {"AGENT_SUPERVISOR_AUTH_DISABLED": "true", "AGENT_SUPERVISOR_AUDIT_HMAC_KEY": ""},
                clear=False,
            ),
            patch("apps.api.agent_supervisor.routers.integrations.load_audit_log", return_value=audit),
            patch(
                "apps.api.agent_supervisor.routers.integrations.load_gateway_request_audit_events",
                return_value=[audit],
            ),
            patch("apps.api.agent_supervisor.routers.integrations.load_execution_receipt", return_value=receipt),
            patch("apps.api.agent_supervisor.routers.integrations.load_gateway_execution_claim", return_value=claim),
            patch("apps.api.agent_supervisor.routers.integrations.verify_execution_receipt", return_value=True),
            TestClient(app) as client,
        ):
            response = client.get("/api/evidence/audit-evidence-1")
            verification = client.post("/api/evidence/audit-evidence-1/verify")

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["evidence_status"], "verified")
        self.assertTrue(payload["verification"]["valid"])
        self.assertTrue(payload["verification"]["trace_available"])
        self.assertEqual(payload["gateway_execution_claim"]["claim_id"], "claim-evidence-1")
        dumped = response.text
        self.assertNotIn("secret.txt", dumped)
        self.assertNotIn("secret prompt", dumped)
        self.assertNotIn("secret provider output", dumped)
        self.assertNotIn("secret tool result", dumped)
        self.assertNotIn("result_content", dumped)
        self.assertEqual(verification.status_code, 200)
        self.assertTrue(verification.json()["verification"]["valid"])

    def test_evidence_hides_legacy_audits_and_reports_invalid_receipt(self) -> None:
        legacy_audit = {"id": "audit-legacy", "source_app": "legacy-report", "audit_hash": "a" * 64}
        with (
            patch.dict(
                os.environ,
                {"AGENT_SUPERVISOR_AUTH_DISABLED": "true", "AGENT_SUPERVISOR_AUDIT_HMAC_KEY": ""},
                clear=False,
            ),
            patch("apps.api.agent_supervisor.routers.integrations.load_audit_log", return_value=legacy_audit),
            TestClient(app) as client,
        ):
            hidden = client.get("/api/evidence/audit-legacy")

        self.assertEqual(hidden.status_code, 404)

        audit = {
            "id": "audit-evidence-invalid",
            "source_app": "mcp-gateway",
            "agent_id": "evidence-agent",
            "conversation_id": "mcp-session",
            "decision": "拒绝",
            "previous_hash": "b" * 64,
        }
        audit["audit_hash"] = audit_hash(audit)
        with (
            patch.dict(
                os.environ,
                {"AGENT_SUPERVISOR_AUTH_DISABLED": "true", "AGENT_SUPERVISOR_AUDIT_HMAC_KEY": ""},
                clear=False,
            ),
            patch("apps.api.agent_supervisor.routers.integrations.load_audit_log", return_value=audit),
            patch("apps.api.agent_supervisor.routers.integrations.load_execution_receipt", return_value={"bad": True}),
            patch("apps.api.agent_supervisor.routers.integrations.load_gateway_execution_claim", return_value=None),
            patch("apps.api.agent_supervisor.routers.integrations.verify_execution_receipt", return_value=False),
            TestClient(app) as client,
        ):
            response = client.post("/api/evidence/audit-evidence-invalid/verify")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["evidence_status"], "invalid")
        self.assertFalse(response.json()["verification"]["valid"])
        self.assertFalse(response.json()["verification"]["trace_available"])

    def test_evidence_requires_trace_and_receipt_chain_bindings(self) -> None:
        audit = {
            "id": "audit-evidence-chain",
            "source_app": "openai-compatible-proxy",
            "agent_id": "evidence-agent",
            "decision": "允许",
            "stage_context": {"request_id": "chatcmpl-chain", "session_id": "chain-session"},
        }
        audit["audit_hash"] = audit_hash(audit)
        wrong_receipt = {"audit_id": "another-audit", "audit_hash": audit["audit_hash"]}
        with (
            patch.dict(
                os.environ,
                {"AGENT_SUPERVISOR_AUTH_DISABLED": "true", "AGENT_SUPERVISOR_AUDIT_HMAC_KEY": ""},
                clear=False,
            ),
            patch("apps.api.agent_supervisor.routers.integrations.load_audit_log", return_value=audit),
            patch("apps.api.agent_supervisor.routers.integrations.load_execution_receipt", return_value=wrong_receipt),
            patch("apps.api.agent_supervisor.routers.integrations.load_gateway_execution_claim", return_value=None),
            patch("apps.api.agent_supervisor.routers.integrations.load_gateway_request_audit_events", return_value=[]),
            patch("apps.api.agent_supervisor.routers.integrations.verify_execution_receipt", return_value=True),
            TestClient(app) as client,
        ):
            response = client.post("/api/evidence/audit-evidence-chain/verify")

        self.assertEqual(response.status_code, 200)
        verification = response.json()["verification"]
        self.assertFalse(verification["valid"])
        self.assertFalse(verification["receipt_binding_valid"])
        self.assertFalse(verification["trace_valid"])

    def test_observer_cannot_read_evidence_details(self) -> None:
        with (
            patch.dict(
                os.environ,
                {
                    "AGENT_SUPERVISOR_AUTH_DISABLED": "false",
                    "AGENT_SUPERVISOR_API_TOKEN": "",
                    "AGENT_SUPERVISOR_API_TOKEN_OBSERVER": "observer-token",
                    "AGENT_SUPERVISOR_API_TOKEN_ANALYST": "analyst-token",
                    "AGENT_SUPERVISOR_AGENT_TOKENS_JSON": "",
                },
                clear=False,
            ),
            patch("apps.api.agent_supervisor.routers.integrations.load_audit_log") as load_audit,
            TestClient(app) as client,
        ):
            response = client.get(
                "/api/evidence/audit-evidence-1",
                headers={"Authorization": "Bearer observer-token"},
            )

        self.assertEqual(response.status_code, 403)
        load_audit.assert_not_called()


if __name__ == "__main__":
    unittest.main()
