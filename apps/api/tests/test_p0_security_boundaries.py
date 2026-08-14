from __future__ import annotations

import json
import os
import socket
from unittest import TestCase
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient
from pydantic import ValidationError

from apps.api.agent_supervisor.domains.attacks import redteam_lab
from apps.api.agent_supervisor.main import MAX_REQUEST_BODY_BYTES, app
from apps.api.agent_supervisor.schemas.main_models import AgentToolEvent, BatchAgentToolEvents


class RuntimeEndpointBoundaryTests(TestCase):
    def setUp(self) -> None:
        self.payload = {
            "conversation_id": "runtime-boundary",
            "agent_id": "runtime-agent",
            "agent_role": "executor",
            "source_app": "test-agent",
            "model_input": "read fixture",
            "model_output": "tool call",
            "tool_call": {"tool": "file.read", "arguments": {"path": "public/readme.md"}},
            "guard_enabled": False,
            "execute_in_sandbox": False,
        }
        self.security_env = {
            "AGENT_SUPERVISOR_AUTH_DISABLED": "false",
            "AGENT_SUPERVISOR_API_TOKEN_OBSERVER": "observer-token",
            "AGENT_SUPERVISOR_AGENT_TOKENS_JSON": json.dumps({"runtime-agent": "executor-token"}),
            "AGENT_SUPERVISOR_API_TOKEN_ANALYST": "analyst-token",
            "AGENT_SUPERVISOR_API_TOKEN_ADMIN": "admin-token",
        }

    def test_runtime_and_lab_roles_are_separated(self) -> None:
        fake_result = {"decision": "允许", "policy_id": "test", "reason": "test"}
        with (
            patch.dict(os.environ, self.security_env, clear=False),
            patch(
                "apps.api.agent_supervisor.routers.integrations.evaluate_agent_event",
                return_value=fake_result,
            ),
            TestClient(app) as client,
        ):
            runtime_statuses = {
                role: client.post(
                    "/api/runtime/evaluate",
                    json=self.payload,
                    headers={"Authorization": f"Bearer {role}-token"},
                ).status_code
                for role in ("observer", "executor", "analyst", "admin")
            }
            lab_statuses = {
                role: client.post(
                    "/api/lab/evaluate",
                    json=self.payload,
                    headers={"Authorization": f"Bearer {role}-token"},
                ).status_code
                for role in ("observer", "executor", "analyst", "admin")
            }

        self.assertEqual(runtime_statuses, {"observer": 403, "executor": 200, "analyst": 403, "admin": 200})
        self.assertEqual(lab_statuses, {"observer": 403, "executor": 403, "analyst": 200, "admin": 200})

    def test_runtime_forces_guard_on_while_lab_preserves_experiment_switch(self) -> None:
        fake_result = {"decision": "允许", "policy_id": "test", "reason": "test"}
        with (
            patch.dict(os.environ, self.security_env, clear=False),
            patch(
                "apps.api.agent_supervisor.routers.integrations.evaluate_agent_event",
                return_value=fake_result,
            ) as evaluate,
            TestClient(app) as client,
        ):
            runtime_response = client.post(
                "/api/runtime/evaluate",
                json=self.payload,
                headers={"Authorization": "Bearer executor-token"},
            )
            lab_response = client.post(
                "/api/lab/evaluate",
                json=self.payload,
                headers={"Authorization": "Bearer analyst-token"},
            )

        self.assertEqual(runtime_response.status_code, 200)
        self.assertEqual(lab_response.status_code, 200)
        self.assertTrue(evaluate.call_args_list[0].kwargs["guard_enabled"])
        self.assertFalse(evaluate.call_args_list[1].kwargs["guard_enabled"])

    def test_agent_token_cannot_spoof_another_agent_id(self) -> None:
        spoofed_payload = {**self.payload, "agent_id": "different-agent"}
        with (
            patch.dict(os.environ, self.security_env, clear=False),
            patch("apps.api.agent_supervisor.routers.integrations.evaluate_agent_event") as evaluate,
            TestClient(app) as client,
        ):
            response = client.post(
                "/api/runtime/evaluate",
                json=spoofed_payload,
                headers={"Authorization": "Bearer executor-token"},
            )

        self.assertEqual(response.status_code, 403)
        evaluate.assert_not_called()

    def test_agent_token_rejects_mixed_identity_batch_before_any_evaluation(self) -> None:
        mixed_events = [self.payload, {**self.payload, "agent_id": "different-agent"}]
        with (
            patch.dict(os.environ, self.security_env, clear=False),
            patch("apps.api.agent_supervisor.routers.integrations.evaluate_agent_event") as evaluate,
            TestClient(app) as client,
        ):
            response = client.post(
                "/api/runtime/batch_evaluate",
                json={"events": mixed_events},
                headers={"Authorization": "Bearer executor-token"},
            )

        self.assertEqual(response.status_code, 403)
        evaluate.assert_not_called()

    def test_verified_agent_identity_is_written_into_audit_evidence(self) -> None:
        with patch.dict(os.environ, self.security_env, clear=False), TestClient(app) as client:
            response = client.post(
                "/api/runtime/evaluate",
                json=self.payload,
                headers={"Authorization": "Bearer executor-token"},
            )

        self.assertEqual(response.status_code, 200)
        audit_log = response.json()["audit_log"]
        self.assertEqual(audit_log["authenticated_agent_id"], "runtime-agent")
        self.assertTrue(audit_log["agent_identity_verified"])
        self.assertTrue(audit_log["audit_hash"])

    def test_admin_override_is_explicit_in_audit_evidence(self) -> None:
        with patch.dict(os.environ, self.security_env, clear=False), TestClient(app) as client:
            response = client.post(
                "/api/runtime/evaluate",
                json=self.payload,
                headers={"Authorization": "Bearer admin-token"},
            )

        self.assertEqual(response.status_code, 200)
        audit_log = response.json()["audit_log"]
        self.assertEqual(audit_log["authenticated_agent_id"], "")
        self.assertTrue(audit_log["agent_identity_admin_override"])

    def test_auth_context_exposes_bound_agent_and_executor_scope(self) -> None:
        with patch.dict(os.environ, self.security_env, clear=False), TestClient(app) as client:
            context_response = client.get(
                "/api/auth/context",
                headers={"Authorization": "Bearer executor-token"},
            )
            overview_response = client.get(
                "/api/overview",
                headers={"Authorization": "Bearer executor-token"},
            )

        self.assertEqual(context_response.status_code, 200)
        self.assertEqual(context_response.json()["role"], "executor")
        self.assertEqual(context_response.json()["agent_id"], "runtime-agent")
        self.assertTrue(context_response.json()["permissions"]["can_execute_runtime"])
        self.assertEqual(overview_response.status_code, 403)

    def test_shared_executor_token_is_rejected_without_explicit_compatibility_switch(self) -> None:
        shared_security_env = {
            **self.security_env,
            "AGENT_SUPERVISOR_AGENT_TOKENS_JSON": "{}",
            "AGENT_SUPERVISOR_API_TOKEN_EXECUTOR": "shared-executor-token",
            "AGENT_SUPERVISOR_ALLOW_SHARED_EXECUTOR_TOKEN": "false",
        }
        with patch.dict(os.environ, shared_security_env, clear=False), TestClient(app) as client:
            response = client.post(
                "/api/runtime/evaluate",
                json=self.payload,
                headers={"Authorization": "Bearer shared-executor-token"},
            )

        self.assertEqual(response.status_code, 403)

    def test_explicit_shared_executor_compatibility_is_visible_in_audit(self) -> None:
        shared_security_env = {
            **self.security_env,
            "AGENT_SUPERVISOR_AGENT_TOKENS_JSON": "{}",
            "AGENT_SUPERVISOR_API_TOKEN_EXECUTOR": "shared-executor-token",
            "AGENT_SUPERVISOR_ALLOW_SHARED_EXECUTOR_TOKEN": "true",
        }
        with patch.dict(os.environ, shared_security_env, clear=False), TestClient(app) as client:
            response = client.post(
                "/api/runtime/evaluate",
                json=self.payload,
                headers={"Authorization": "Bearer shared-executor-token"},
            )

        self.assertEqual(response.status_code, 200)
        audit_log = response.json()["audit_log"]
        self.assertFalse(audit_log["agent_identity_verified"])
        self.assertTrue(audit_log["agent_identity_shared_compatibility"])

    def test_approval_role_matrix_separates_agent_execution_from_human_decision(self) -> None:
        claim_payload = {
            "agent_id": "runtime-agent",
            "tool_call": {"tool": "file.read", "arguments": {"path": "public/readme.md"}},
        }
        decision_payload = {"action": "approve", "operator": "tester", "comment": "role matrix"}
        with patch.dict(os.environ, self.security_env, clear=False), TestClient(app) as client:
            claim_statuses = {
                role: client.post(
                    "/api/approvals/missing-review/claim",
                    json=claim_payload,
                    headers={"Authorization": f"Bearer {role}-token"},
                ).status_code
                for role in ("observer", "executor", "analyst", "admin")
            }
            decision_statuses = {
                role: client.post(
                    "/api/approvals/missing-review/decision",
                    json=decision_payload,
                    headers={"Authorization": f"Bearer {role}-token"},
                ).status_code
                for role in ("observer", "executor", "analyst", "admin")
            }

        self.assertEqual(claim_statuses, {"observer": 403, "executor": 404, "analyst": 403, "admin": 404})
        self.assertEqual(decision_statuses, {"observer": 403, "executor": 403, "analyst": 404, "admin": 404})

    def test_approval_recovery_rejects_spoofed_agent_identity(self) -> None:
        headers = {"Authorization": "Bearer executor-token"}
        with patch.dict(os.environ, self.security_env, clear=False), TestClient(app) as client:
            claim_response = client.post(
                "/api/approvals/missing-review/claim",
                json={
                    "agent_id": "different-agent",
                    "tool_call": {"tool": "file.read", "arguments": {"path": "public/readme.md"}},
                },
                headers=headers,
            )
            complete_response = client.post(
                "/api/approvals/missing-review/complete",
                json={
                    "agent_id": "different-agent",
                    "claim_id": "missing-claim",
                    "succeeded": True,
                    "result_hash": "fixture-hash",
                },
                headers=headers,
            )

        self.assertEqual(claim_response.status_code, 403)
        self.assertEqual(complete_response.status_code, 403)

    def test_request_body_over_one_megabyte_is_rejected_before_parsing(self) -> None:
        with TestClient(app) as client:
            response = client.post(
                "/api/runtime/evaluate",
                content=b"x" * (MAX_REQUEST_BODY_BYTES + 1),
                headers={"Content-Type": "application/json"},
            )

        self.assertEqual(response.status_code, 413)

    def test_batch_returns_validation_error_for_oversized_tool_call(self) -> None:
        oversized_event = {
            **self.payload,
            "tool_call": {"tool": "model.respond", "arguments": {"content": "x" * 70_000}},
        }
        with patch.dict(os.environ, self.security_env, clear=False), TestClient(app) as client:
            response = client.post(
                "/api/runtime/batch_evaluate",
                json={"events": [oversized_event]},
                headers={"Authorization": "Bearer executor-token"},
            )

        self.assertEqual(response.status_code, 422)


class ToolCallResourceBoundaryTests(TestCase):
    def test_tool_call_rejects_oversized_payload(self) -> None:
        with self.assertRaisesRegex(ValidationError, "65536"):
            AgentToolEvent(tool_call={"tool": "model.respond", "arguments": {"content": "x" * 70_000}})

    def test_tool_call_rejects_excessive_depth_fields_and_array_items(self) -> None:
        nested: object = "leaf"
        for _ in range(9):
            nested = {"next": nested}
        invalid_calls = (
            {"tool": "model.respond", "arguments": nested},
            {"tool": "model.respond", "arguments": {f"field-{index}": index for index in range(101)}},
            {"tool": "model.respond", "arguments": {"items": list(range(101))}},
        )

        for tool_call in invalid_calls:
            with self.subTest(tool_call=list(tool_call)):
                with self.assertRaises(ValidationError):
                    AgentToolEvent(tool_call=tool_call)

    def test_batch_accepts_documented_fifty_event_boundary(self) -> None:
        event = AgentToolEvent(tool_call={"tool": "file.read", "arguments": {"path": "public/readme.md"}})
        batch = BatchAgentToolEvents(events=[event] * 50)
        self.assertEqual(len(batch.events), 50)


class ExternalTargetRedirectBoundaryTests(TestCase):
    def test_external_target_redirect_is_returned_without_following_location(self) -> None:
        target_url = "https://example.com/api/chat"
        response = Mock(status=302)
        response.read.return_value = b"redirect blocked"
        connection = Mock()
        connection.getresponse.return_value = response

        with (
            patch.object(redteam_lab, "_resolve_public_addresses", return_value=["93.184.216.34"]) as resolve,
            patch.object(redteam_lab, "_build_pinned_connection", return_value=connection) as build_connection,
        ):
            result = redteam_lab._post_authorized_target(target_url, {"prompt": "fixture"}, "")

        resolve.assert_called_once_with("example.com", 443)
        self.assertEqual(build_connection.call_args.args[1], "93.184.216.34")
        connection.request.assert_called_once()
        request_call = connection.request.call_args
        self.assertEqual(request_call.args[:2], ("POST", "/api/chat"))
        self.assertEqual(request_call.kwargs["headers"]["Host"], "example.com")
        connection.close.assert_called_once()
        self.assertEqual(result["status"], 302)
        self.assertEqual(result["body"], "redirect blocked")
        self.assertEqual(result["resolved_ip"], "93.184.216.34")

    def test_dns_resolution_rejects_any_private_destination(self) -> None:
        private_result = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]
        with patch.object(redteam_lab.socket, "getaddrinfo", return_value=private_result):
            with self.assertRaisesRegex(ValueError, "内网"):
                redteam_lab._resolve_public_addresses("rebind.example", 443)

    def test_https_connection_uses_pinned_ip_and_original_hostname_for_sni(self) -> None:
        raw_socket = Mock()
        tls_socket = Mock()
        context = Mock()
        context.wrap_socket.return_value = tls_socket
        connection = redteam_lab._PinnedHTTPSConnection(
            "example.com",
            "93.184.216.34",
            port=443,
            timeout=8,
            context=context,
        )

        with patch.object(redteam_lab.socket, "create_connection", return_value=raw_socket) as create_connection:
            connection.connect()

        create_connection.assert_called_once_with(("93.184.216.34", 443), 8, None)
        context.wrap_socket.assert_called_once_with(raw_socket, server_hostname="example.com")
        self.assertIs(connection.sock, tls_socket)
