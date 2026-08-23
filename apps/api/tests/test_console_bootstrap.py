import os
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from apps.api.agent_supervisor.main import app


class ConsoleBootstrapTest(unittest.TestCase):
    def test_public_status_distinguishes_online_backend_from_authentication(self) -> None:
        with patch.dict(
            os.environ,
            {
                "AGENT_SUPERVISOR_AUTH_DISABLED": "false",
                "AGENT_SUPERVISOR_API_TOKEN": "operator-token",
                "AGENT_SUPERVISOR_API_HOST": "127.0.0.1",
            },
            clear=False,
        ):
            with TestClient(app) as client:
                public_response = client.get("/api/public/status")
                protected_response = client.get("/api/health")
                authenticated_response = client.get(
                    "/api/auth/context",
                    headers={"Authorization": "Bearer operator-token"},
                )

        self.assertEqual(public_response.status_code, 200)
        self.assertEqual(public_response.json()["console_auth"]["required"], True)
        self.assertEqual(protected_response.status_code, 401)
        self.assertEqual(authenticated_response.status_code, 200)
        self.assertEqual(authenticated_response.json()["role"], "admin")
        self.assertEqual(authenticated_response.json()["permissions"]["can_generate"], True)


if __name__ == "__main__":
    unittest.main()
