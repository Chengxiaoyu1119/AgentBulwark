from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from apps.api.agent_supervisor.main import app


class AgentRegistryApiTests(unittest.TestCase):
    def test_create_list_rotate_and_revoke_token(self) -> None:
        with patch.dict(
            os.environ,
            {
                "AGENT_SUPERVISOR_AUTH_DISABLED": "false",
                "AGENT_SUPERVISOR_API_TOKEN": "operator-token",
            },
            clear=False,
        ):
            with TestClient(app) as client:
                admin = {"Authorization": "Bearer operator-token"}
                created = client.post(
                    "/api/agents",
                    headers=admin,
                    json={"agent_id": "registry-test-agent", "display_name": "Registry Test"},
                )
                self.assertEqual(created.status_code, 200)
                body = created.json()
                first_token = body["token"]
                self.assertNotIn("token_hash", body)
                self.assertEqual(body["status"], "active")

                listed = client.get("/api/agents", headers=admin)
                self.assertEqual(listed.status_code, 200)
                row = next(item for item in listed.json() if item["agent_id"] == "registry-test-agent")
                self.assertNotIn("token", row)
                self.assertEqual(row["token_prefix"], first_token[:8])

                self.assertEqual(
                    client.get("/api/auth/context", headers={"Authorization": f"Bearer {first_token}"}).json()["agent_id"],
                    "registry-test-agent",
                )
                rotated = client.post("/api/agents/registry-test-agent/rotate-token", headers=admin)
                self.assertEqual(rotated.status_code, 200)
                second_token = rotated.json()["token"]
                self.assertNotEqual(first_token, second_token)
                self.assertEqual(client.get("/api/health", headers={"Authorization": f"Bearer {first_token}"}).status_code, 401)
                self.assertEqual(client.get("/api/health", headers={"Authorization": f"Bearer {second_token}"}).status_code, 200)

                revoked = client.post("/api/agents/registry-test-agent/revoke", headers=admin)
                self.assertEqual(revoked.status_code, 200)
                self.assertEqual(client.get("/api/health", headers={"Authorization": f"Bearer {second_token}"}).status_code, 401)

    def test_policy_validate_publish_and_rollback_are_versioned(self) -> None:
        with patch.dict(
            os.environ,
            {
                "AGENT_SUPERVISOR_AUTH_DISABLED": "false",
                "AGENT_SUPERVISOR_API_TOKEN": "operator-token",
            },
            clear=False,
        ):
            with TestClient(app) as client:
                headers = {"Authorization": "Bearer operator-token"}
                before = client.get("/api/policy_config", headers=headers).json()
                original = int(before["settings"]["approval_sla_minutes"])
                candidate = original + 1 if original < 1440 else original - 1

                validated = client.post(
                    "/api/policies/validate",
                    headers=headers,
                    json={"settings": {"approval_sla_minutes": candidate}},
                )
                self.assertEqual(validated.status_code, 200)
                self.assertTrue(validated.json()["valid"])
                self.assertEqual(
                    client.get("/api/policy_config", headers=headers).json()["settings"]["approval_sla_minutes"],
                    original,
                )

                published = client.post(
                    "/api/policies/publish",
                    headers=headers,
                    json={"settings": {"approval_sla_minutes": candidate}, "comment": "注册测试发布"},
                )
                self.assertEqual(published.status_code, 200)
                first_version = client.get("/api/policy_config", headers=headers).json()["versions"][0]["id"]

                second = candidate + 1 if candidate < 1440 else candidate - 1
                self.assertEqual(
                    client.post(
                        "/api/policies/publish",
                        headers=headers,
                        json={"settings": {"approval_sla_minutes": second}, "comment": "注册测试第二次发布"},
                    ).status_code,
                    200,
                )
                rolled_back = client.post(f"/api/policies/{first_version}/rollback", headers=headers)
                self.assertEqual(rolled_back.status_code, 200)
                self.assertEqual(
                    client.get("/api/policy_config", headers=headers).json()["settings"]["approval_sla_minutes"],
                    candidate,
                )


if __name__ == "__main__":
    unittest.main()
