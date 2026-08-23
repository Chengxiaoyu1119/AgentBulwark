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

    def test_operational_instance_hides_experiment_routes(self) -> None:
        with patch.dict(
            os.environ,
            {
                "AGENT_SUPERVISOR_AUTH_DISABLED": "false",
                "AGENT_SUPERVISOR_API_TOKEN": "operator-token",
                "AGENT_SUPERVISOR_API_HOST": "127.0.0.1",
                "AGENT_SUPERVISOR_LABS_ENABLED": "false",
            },
            clear=False,
        ):
            with TestClient(app) as client:
                headers = {"Authorization": "Bearer operator-token"}
                lab_response = client.get("/api/scenarios", headers=headers)
                runtime_response = client.get("/api/runtime_status", headers=headers)

        self.assertEqual(lab_response.status_code, 404)
        self.assertEqual(runtime_response.status_code, 200)
        self.assertEqual(runtime_response.json()["backend"]["data_plane"], "operational")
        self.assertEqual(runtime_response.json()["backend"]["labs_enabled"], False)

    def test_dedicated_lab_instance_can_enable_experiment_routes(self) -> None:
        with patch.dict(
            os.environ,
            {
                "AGENT_SUPERVISOR_AUTH_DISABLED": "false",
                "AGENT_SUPERVISOR_API_TOKEN": "operator-token",
                "AGENT_SUPERVISOR_API_HOST": "127.0.0.1",
                "AGENT_SUPERVISOR_LABS_ENABLED": "true",
            },
            clear=False,
        ):
            with TestClient(app) as client:
                response = client.get(
                    "/api/scenarios",
                    headers={"Authorization": "Bearer operator-token"},
                )

        self.assertEqual(response.status_code, 200)
        self.assertGreater(len(response.json()), 0)


if __name__ == "__main__":
    unittest.main()
