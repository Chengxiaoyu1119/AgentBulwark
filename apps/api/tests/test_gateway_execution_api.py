from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

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


if __name__ == "__main__":
    unittest.main()
