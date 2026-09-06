from __future__ import annotations

import json
import os
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from apps.api.agent_supervisor.domains.runtime.tools import execute_tool
from apps.api.agent_supervisor.main import app


class ApiBoundaryTests(unittest.TestCase):
    def test_removed_experiment_routes_return_404(self) -> None:
        with patch.dict(
            os.environ,
            {"AGENT_SUPERVISOR_AUTH_DISABLED": "true", "AGENT_SUPERVISOR_API_HOST": "127.0.0.1"},
            clear=False,
        ), TestClient(app) as client:
            for path in (
                "/api/scenarios",
                "/api/attack_lab/modules",
                "/api/redteam_lab/modules",
                "/api/integrations/openclaw/status",
                "/api/runtime/execute",
                "/api/gateway/compare",
            ):
                with self.subTest(path=path):
                    self.assertEqual(client.get(path).status_code, 404)

    def test_public_status_is_available_but_protected_health_requires_bearer(self) -> None:
        with patch.dict(
            os.environ,
            {
                "AGENT_SUPERVISOR_AUTH_DISABLED": "false",
                "AGENT_SUPERVISOR_API_TOKEN": "operator-token",
                "AGENT_SUPERVISOR_API_HOST": "127.0.0.1",
            },
            clear=False,
        ), TestClient(app) as client:
            self.assertEqual(client.get("/api/public/status").status_code, 200)
            self.assertEqual(client.get("/api/health").status_code, 401)
            self.assertEqual(client.get("/api/health", headers={"Authorization": "Bearer operator-token"}).status_code, 200)

    def test_unknown_execution_capability_is_not_performed(self) -> None:
        result = execute_tool(
            {"tool": "runtime.exec", "arguments": {"command": "echo should-not-run"}},
            "允许",
        )
        self.assertFalse(result["executed"])
        self.assertEqual(result["execution_target"], "none")

    def test_protected_status_does_not_expose_secret_environment_values(self) -> None:
        with patch.dict(
            os.environ,
            {
                "AGENT_SUPERVISOR_AUTH_DISABLED": "false",
                "AGENT_SUPERVISOR_API_TOKEN": "operator-token",
                "AGENT_SUPERVISOR_AUDIT_HMAC_KEY": "private-hmac-value",
            },
            clear=False,
        ), TestClient(app) as client:
            response = client.get("/api/runtime_status", headers={"Authorization": "Bearer operator-token"})
            body = json.dumps(response.json(), ensure_ascii=False)
            self.assertNotIn("private-hmac-value", body)
            self.assertNotIn("operator-token", body)


if __name__ == "__main__":
    unittest.main()
