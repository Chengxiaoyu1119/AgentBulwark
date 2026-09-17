from __future__ import annotations

import copy
import json
import unittest
from dataclasses import replace
from unittest.mock import Mock, patch

from apps.api.agent_supervisor.adapters.proxy import openai_proxy
from apps.api.agent_supervisor.domains.governance.task_profiles import (
    evaluate_task_scope,
    resolve_task_profile,
    task_audit_context,
    task_binding_mismatch_reason,
    validate_task_profiles_config,
)
from apps.api.agent_supervisor.mcp_gateway.gateway import McpGateway
from apps.api.agent_supervisor.mcp_gateway.router import UpstreamRouter


def _settings() -> dict:
    return {
        "policy_revision": "revision-one",
        "agent_tool_allowlists": {
            "agent-a": ["file.read", "file.write", "api.call", "mail.send"],
        },
        "agent_api_allowlists": {
            "agent-a": ["https://api.example.com"],
        },
        "task_profiles": {
            "public-read": {
                "agent_id": "agent-a",
                "name": "Public read",
                "enabled": True,
                "allowed_capabilities": ["file.read", "api.call", "mail.send"],
                "allowed_file_paths": ["public/*"],
                "allowed_api_origins": ["https://api.example.com"],
                "allowed_email_domains": ["example.net"],
                "require_approval": False,
                "expires_at": "",
            },
        },
    }


class TaskProfilePolicyTest(unittest.TestCase):
    def test_resolves_valid_profile_and_enforces_targets(self) -> None:
        settings = _settings()
        binding = resolve_task_profile("agent-a", "public-read", settings=settings)

        self.assertTrue(binding.valid)
        self.assertEqual(binding.policy_revision, "revision-one")
        self.assertTrue(evaluate_task_scope(binding, {"tool": "file.read", "arguments": {"path": "public/readme.md"}}, agent_id="agent-a").allowed)
        self.assertFalse(evaluate_task_scope(binding, {"tool": "file.read", "arguments": {"path": "../../secret.txt"}}, agent_id="agent-a").allowed)
        self.assertTrue(evaluate_task_scope(binding, {"tool": "api.call", "arguments": {"endpoint": "https://api.example.com/v1"}}, agent_id="agent-a").allowed)
        self.assertFalse(evaluate_task_scope(binding, {"tool": "api.call", "arguments": {"endpoint": "https://other.example"}}, agent_id="agent-a").allowed)
        self.assertTrue(evaluate_task_scope(binding, {"tool": "mail.send", "arguments": {"to": "review@example.net"}}, agent_id="agent-a").allowed)
        self.assertFalse(evaluate_task_scope(binding, {"tool": "mail.send", "arguments": {"to": "review@other.example"}}, agent_id="agent-a").allowed)

    def test_agent_with_profiles_requires_valid_enabled_unexpired_task(self) -> None:
        settings = _settings()
        self.assertFalse(resolve_task_profile("agent-a", "", settings=settings).valid)
        self.assertFalse(resolve_task_profile("agent-a", "missing", settings=settings).valid)
        self.assertFalse(resolve_task_profile("other-agent", "public-read", settings=settings).valid)

        disabled = copy.deepcopy(settings)
        disabled["task_profiles"]["public-read"]["enabled"] = False
        self.assertFalse(resolve_task_profile("agent-a", "public-read", settings=disabled).valid)

        expired = copy.deepcopy(settings)
        expired["task_profiles"]["public-read"]["expires_at"] = "2020-01-01T00:00:00+00:00"
        self.assertFalse(resolve_task_profile("agent-a", "public-read", settings=expired).valid)

    def test_published_profile_cannot_expand_agent_capability_or_api_scope(self) -> None:
        settings = _settings()
        widened_capability = copy.deepcopy(settings)
        widened_capability["task_profiles"]["public-read"]["allowed_capabilities"] = ["env.read"]
        with self.assertRaisesRegex(ValueError, "不能扩大"):
            validate_task_profiles_config(widened_capability)

        widened_origin = copy.deepcopy(settings)
        widened_origin["task_profiles"]["public-read"]["allowed_api_origins"] = ["https://other.example"]
        with self.assertRaisesRegex(ValueError, "不能扩大"):
            validate_task_profiles_config(widened_origin)

    def test_post_approval_recheck_rejects_changed_profile_fingerprint(self) -> None:
        settings = _settings()
        binding = resolve_task_profile("agent-a", "public-read", settings=settings)
        context = task_audit_context(binding, "allowed")
        changed = replace(binding, fingerprint="changed-fingerprint")
        with patch(
            "apps.api.agent_supervisor.domains.governance.task_profiles.resolve_task_profile",
            return_value=changed,
        ):
            reason = task_binding_mismatch_reason(
                context,
                agent_id="agent-a",
                raw_tool_call={"tool": "file.read", "arguments": {"path": "public/readme.md"}},
            )
        self.assertIn("变更", reason or "")

    def test_required_task_binding_cannot_be_rechecked_without_task_id(self) -> None:
        reason = task_binding_mismatch_reason(
            {"task_profile_required": True},
            agent_id="agent-a",
            raw_tool_call={"tool": "file.read", "arguments": {"path": "public/readme.md"}},
        )
        self.assertEqual(reason, "执行上下文缺少任务授权绑定。")


class TaskProfileGatewayBoundaryTest(unittest.TestCase):
    def test_openai_missing_task_blocks_before_provider(self) -> None:
        settings = _settings()
        request = {
            "model": "fixture-model",
            "messages": [{"role": "user", "content": "read the public note"}],
        }
        with (
            patch.object(openai_proxy, "get_policy_settings", return_value=settings),
            patch.object(openai_proxy, "forward_openai_chat_completion") as forward,
            patch.object(openai_proxy, "_record_proxy_task_profile_audit", return_value={"audit_id": "task-deny"}),
        ):
            with self.assertRaises(openai_proxy.ProxyPolicyRejectionError):
                openai_proxy.run_openai_proxy_completion(
                    request,
                    security_context={"agent_id": "agent-a", "role": "executor", "session_id": "session-a"},
                )
        forward.assert_not_called()

    def test_openai_task_filters_tool_definitions_before_provider(self) -> None:
        settings = _settings()
        settings["task_profiles"]["public-read"]["allowed_capabilities"] = ["file.read"]
        request = {
            "model": "fixture-model",
            "messages": [{"role": "user", "content": "send the report"}],
            "tools": [
                {
                    "type": "function",
                    "function": {"name": "mail_send", "parameters": {"type": "object"}},
                }
            ],
            "agent_supervisor": {"task_id": "public-read", "session_id": "session-a"},
        }
        with (
            patch.object(openai_proxy, "get_policy_settings", return_value=settings),
            patch.object(openai_proxy, "forward_openai_chat_completion") as forward,
            patch.object(
                openai_proxy,
                "_record_proxy_tool_allowlist_audit",
                return_value={"audit_id": "task-tool-deny", "decision": "拒绝", "risk_score": 90},
            ),
        ):
            result = openai_proxy.run_openai_proxy_completion(
                request,
                security_context={"agent_id": "agent-a", "role": "executor", "session_id": "session-a"},
            )
        forward.assert_not_called()
        self.assertFalse(result["agent_supervisor"]["provider_called"])
        self.assertEqual(result["agent_supervisor"]["decision"], "拒绝")

    def test_openai_valid_task_is_bound_and_not_forwarded_to_provider(self) -> None:
        settings = _settings()
        provider_result = {
            "response": {
                "id": "task-provider-response",
                "object": "chat.completion",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}],
            },
            "provider": "fixture-provider",
            "model": "fixture-model",
            "request_hash": "a" * 64,
            "provider_response_hash": "b" * 64,
            "provider_response_id": "task-provider-response",
            "provider_failures": [],
        }
        with (
            patch.object(openai_proxy, "get_policy_settings", return_value=settings),
            patch.object(openai_proxy, "forward_openai_chat_completion", return_value=provider_result) as forward,
            patch.object(openai_proxy, "_record_gateway_response_audit", return_value={"audit_id": "task-response"}),
        ):
            result = openai_proxy.run_openai_proxy_completion(
                {
                    "model": "fixture-model",
                    "messages": [{"role": "user", "content": "read the public note"}],
                    "agent_supervisor": {"task_id": "public-read", "session_id": "session-a"},
                },
                security_context={"agent_id": "agent-a", "role": "executor", "session_id": "session-a"},
            )
        metadata = result["agent_supervisor"]
        self.assertEqual(metadata["task_id"], "public-read")
        self.assertEqual(metadata["policy_revision"], "revision-one")
        self.assertTrue(metadata["task_profile_fingerprint"])
        forwarded = forward.call_args.args[0]
        self.assertNotIn("agent_supervisor", forwarded)
        self.assertNotIn("task_id", json.dumps(forwarded, ensure_ascii=False))

    def test_mcp_task_call_is_rejected_without_upstream_io(self) -> None:
        settings = _settings()
        binding = resolve_task_profile("agent-a", "public-read", settings=settings)
        upstream = Mock()
        gateway = McpGateway(
            router=UpstreamRouter({"default": upstream}),
            audit_enabled=False,
            session_isolation=False,
        )
        with patch(
            "apps.api.agent_supervisor.mcp_gateway.gateway.resolve_task_profile",
            return_value=binding,
        ):
            response = gateway.handle(
                {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "file.read", "arguments": {"path": "../../secret.txt"}}},
                agent_id="agent-a",
                task_id="public-read",
            )
        self.assertIsInstance(response, dict)
        if not isinstance(response, dict):
            return
        self.assertTrue("error" in response or response.get("result", {}).get("isError") is True)
        upstream.request.assert_not_called()

    def test_mcp_tools_list_hides_task_outside_capabilities(self) -> None:
        settings = _settings()
        binding = resolve_task_profile("agent-a", "public-read", settings=settings)
        upstream = Mock()
        upstream.request.return_value = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "tools": [
                    {"name": "file.read", "description": "read", "inputSchema": {"type": "object"}},
                    {"name": "file.write", "description": "write", "inputSchema": {"type": "object"}},
                ],
            },
        }
        gateway = McpGateway(
            router=UpstreamRouter({"default": upstream}),
            audit_enabled=False,
            session_isolation=False,
        )
        with patch(
            "apps.api.agent_supervisor.mcp_gateway.gateway.resolve_task_profile",
            return_value=binding,
        ):
            response = gateway.handle(
                {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
                agent_id="agent-a",
                task_id="public-read",
            )
        self.assertIsInstance(response, dict)
        if not isinstance(response, dict):
            return
        self.assertEqual([item["name"] for item in response["result"]["tools"]], ["file.read"])


if __name__ == "__main__":
    unittest.main()
