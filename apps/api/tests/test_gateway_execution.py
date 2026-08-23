from __future__ import annotations

import hashlib
import json
import os
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
from uuid import uuid4

from fastapi.testclient import TestClient

from apps.api.agent_supervisor.domains.runtime.gateway_execution import GatewayExecutionUncertainError
from apps.api.agent_supervisor.domains.runtime.tools import SandboxPaths
from apps.api.agent_supervisor.main import app
from apps.api.agent_supervisor.storage.database import (
    list_runtime_events,
    load_gateway_execution_claim,
)
from apps.api.agent_supervisor.storage.database import (
    write_run as persist_run,
)


class GatewayExecutionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.env = patch.dict(
            os.environ,
            {
                "AGENT_SUPERVISOR_AUTH_DISABLED": "true",
                "AGENT_SUPERVISOR_PROXY_ALLOW_UNAUTHENTICATED_PUBLIC": "true",
                "AGENT_SUPERVISOR_PROXY_RATE_LIMIT_PER_MINUTE": "0",
                "AGENT_SUPERVISOR_AUDIT_HMAC_KEY": "",
            },
            clear=False,
        )
        self.env.start()
        self.client = TestClient(app)

    def tearDown(self) -> None:
        self.client.close()
        self.env.stop()

    def _create_allowed_gateway_audit(
        self,
        *,
        agent_id: str,
        session_id: str,
        provider_call_id: str,
        path: str = "public/项目说明.md",
    ) -> dict[str, str]:
        provider_response = {
            "id": f"provider-{provider_call_id}",
            "object": "chat.completion",
            "created": 123,
            "model": "fixture-model",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": provider_call_id,
                                "type": "function",
                                "function": {
                                    "name": "file_read",
                                    "arguments": f'{{"path":"{path}"}}',
                                },
                            }
                        ],
                    },
                    "finish_reason": "tool_calls",
                }
            ],
        }
        with patch(
            "apps.api.agent_supervisor.adapters.proxy.openai_proxy.forward_openai_chat_completion",
            return_value={
                "response": provider_response,
                "provider": "fixture-provider",
                "model": "fixture-model",
                "mode": "real-api",
                "request_hash": "a" * 64,
                "provider_response_hash": "b" * 64,
                "provider_response_id": provider_response["id"],
                "provider_failures": [],
            },
        ):
            response = self.client.post(
                "/v1/chat/completions",
                headers={"X-Agent-Session-ID": session_id},
                json={
                    "model": "fixture-model",
                    "messages": [{"role": "user", "content": "读取公开说明"}],
                    "tools": [{"type": "function", "function": {"name": "file_read"}}],
                    "agent_supervisor": {"agent_id": agent_id},
                },
            )
        self.assertEqual(response.status_code, 200, response.text)
        decision = response.json()["agent_supervisor"]["tool_decisions"][0]
        self.assertEqual(decision["decision"], "允许")
        return decision

    def test_gateway_tool_call_can_be_executed_from_immutable_audit(self) -> None:
        provider_response = {
            "id": "provider-gateway-exec",
            "object": "chat.completion",
            "created": 123,
            "model": "fixture-model",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "call-gateway-exec",
                                "type": "function",
                                "function": {
                                    "name": "file_read",
                                    "arguments": '{"path":"public/项目说明.md"}',
                                },
                            }
                        ],
                    },
                    "finish_reason": "tool_calls",
                }
            ],
        }
        with patch(
            "apps.api.agent_supervisor.adapters.proxy.openai_proxy.forward_openai_chat_completion",
            return_value={
                "response": provider_response,
                "provider": "fixture-provider",
                "model": "fixture-model",
                "mode": "real-api",
                "request_hash": "a" * 64,
                "provider_response_hash": "b" * 64,
                "provider_response_id": "provider-gateway-exec",
                "provider_failures": [],
            },
        ):
            first = self.client.post(
                "/v1/chat/completions",
                headers={"X-Agent-Session-ID": "gateway-exec-session"},
                json={
                    "model": "fixture-model",
                    "messages": [{"role": "user", "content": "读取公开项目说明"}],
                    "tools": [{"type": "function", "function": {"name": "file_read"}}],
                    "agent_supervisor": {"agent_id": "gateway-exec-agent"},
                },
            )

        self.assertEqual(first.status_code, 200)
        metadata = first.json()["agent_supervisor"]
        self.assertEqual(metadata["decision"], "允许")
        decision = metadata["tool_decisions"][0]
        execute = self.client.post(
            f"/api/gateway/tool_calls/{decision['audit_id']}/execute",
            json={
                "agent_id": "gateway-exec-agent",
                "session_id": "gateway-exec-session",
                "provider_call_id": "call-gateway-exec",
            },
        )
        self.assertEqual(execute.status_code, 200, execute.text)
        body = execute.json()
        self.assertTrue(body["execution_observed_by_server"])
        self.assertEqual(body["receipt"]["status"], "completed")
        self.assertIn("公开项目说明", body["tool_result"])

        replay = self.client.post(
            f"/api/gateway/tool_calls/{decision['audit_id']}/execute",
            json={"agent_id": "gateway-exec-agent", "session_id": "gateway-exec-session"},
        )
        self.assertEqual(replay.status_code, 200)
        self.assertTrue(replay.json()["idempotent"])

    def test_gateway_execution_rejects_allowed_sibling_when_response_is_blocked_atomically(self) -> None:
        provider_response = {
            "id": "provider-gateway-mixed",
            "object": "chat.completion",
            "created": 123,
            "model": "fixture-model",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "call-gateway-mixed-allow",
                                "type": "function",
                                "function": {
                                    "name": "file_read",
                                    "arguments": '{"path":"public/项目说明.md"}',
                                },
                            },
                            {
                                "id": "call-gateway-mixed-block",
                                "type": "function",
                                "function": {
                                    "name": "file_read",
                                    "arguments": '{"path":"confidential/competition-teams.csv"}',
                                },
                            },
                        ],
                    },
                    "finish_reason": "tool_calls",
                }
            ],
        }
        with patch(
            "apps.api.agent_supervisor.adapters.proxy.openai_proxy.forward_openai_chat_completion",
            return_value={
                "response": provider_response,
                "provider": "fixture-provider",
                "model": "fixture-model",
                "mode": "real-api",
                "request_hash": "m" * 64,
                "provider_response_hash": "n" * 64,
                "provider_response_id": "provider-gateway-mixed",
                "provider_failures": [],
            },
        ):
            first = self.client.post(
                "/v1/chat/completions",
                headers={"X-Agent-Session-ID": "gateway-mixed-session"},
                json={
                    "model": "fixture-model",
                    "messages": [{"role": "user", "content": "同时读取两份文件"}],
                    "tools": [{"type": "function", "function": {"name": "file_read"}}],
                    "agent_supervisor": {"agent_id": "gateway-mixed-agent"},
                },
            )

        self.assertEqual(first.status_code, 200, first.text)
        body = first.json()
        metadata = body["agent_supervisor"]
        self.assertEqual(metadata["decision"], "拒绝")
        allowed = next(item for item in metadata["tool_decisions"] if item["decision"] == "允许")
        blocked = next(item for item in metadata["tool_decisions"] if item["decision"] != "允许")
        self.assertTrue(allowed["audit_id"])
        self.assertTrue(blocked["audit_id"])

        execute = self.client.post(
            f"/api/gateway/tool_calls/{allowed['audit_id']}/execute",
            json={
                "agent_id": "gateway-mixed-agent",
                "session_id": "gateway-mixed-session",
                "provider_call_id": allowed["call_id"],
            },
        )
        self.assertEqual(execute.status_code, 409, execute.text)
        self.assertIn("受控工具调用", execute.text)

    def test_gateway_execution_rejects_allowed_sibling_when_other_call_is_malformed(self) -> None:
        """Malformed Provider calls must remain in the atomic sibling set.

        The malformed call has no provider_call_id.  A query that only loads
        call-id-bearing rows would omit it and let the valid sibling execute
        through the standalone endpoint after the gateway had blocked the
        response as a whole.
        """
        provider_response = {
            "id": "provider-gateway-malformed-mixed",
            "object": "chat.completion",
            "created": 123,
            "model": "fixture-model",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "call-gateway-malformed-allow",
                                "type": "function",
                                "function": {
                                    "name": "file_read",
                                    "arguments": '{"path":"public/项目说明.md"}',
                                },
                            },
                            {"id": "call-gateway-malformed-invalid", "type": "function"},
                        ],
                    },
                    "finish_reason": "tool_calls",
                }
            ],
        }
        with patch(
            "apps.api.agent_supervisor.adapters.proxy.openai_proxy.forward_openai_chat_completion",
            return_value={
                "response": provider_response,
                "provider": "fixture-provider",
                "model": "fixture-model",
                "mode": "real-api",
                "request_hash": "q" * 64,
                "provider_response_hash": "r" * 64,
                "provider_response_id": "provider-gateway-malformed-mixed",
                "provider_failures": [],
            },
        ):
            first = self.client.post(
                "/v1/chat/completions",
                headers={"X-Agent-Session-ID": "gateway-malformed-mixed-session"},
                json={
                    "model": "fixture-model",
                    "messages": [{"role": "user", "content": "同时处理工具调用"}],
                    "tools": [{"type": "function", "function": {"name": "file_read"}}],
                    "agent_supervisor": {"agent_id": "gateway-malformed-mixed-agent"},
                },
            )

        self.assertEqual(first.status_code, 200, first.text)
        metadata = first.json()["agent_supervisor"]
        self.assertEqual(metadata["decision"], "拒绝")
        allowed = next(item for item in metadata["tool_decisions"] if item["decision"] == "允许")
        self.assertTrue(allowed["audit_id"])
        execute = self.client.post(
            f"/api/gateway/tool_calls/{allowed['audit_id']}/execute",
            json={
                "agent_id": "gateway-malformed-mixed-agent",
                "session_id": "gateway-malformed-mixed-session",
                "provider_call_id": allowed["call_id"],
            },
        )
        self.assertEqual(execute.status_code, 409, execute.text)
        self.assertIn("受控工具调用", execute.text)

    def test_http_managed_gateway_owns_tool_execution_and_provider_followup(self) -> None:
        provider_responses = [
            {
                "response": {
                    "id": "http-managed-provider-1",
                    "object": "chat.completion",
                    "created": 123,
                    "model": "fixture-model",
                    "choices": [
                        {
                            "index": 0,
                            "message": {
                                "role": "assistant",
                                "content": None,
                                "tool_calls": [
                                    {
                                        "id": "http-managed-call",
                                        "type": "function",
                                        "function": {
                                            "name": "file_read",
                                            "arguments": '{"path":"public/项目说明.md"}',
                                        },
                                    }
                                ],
                            },
                            "finish_reason": "tool_calls",
                        }
                    ],
                },
                "provider": "fixture-provider",
                "model": "fixture-model",
                "mode": "real-api",
                "request_hash": "a" * 64,
                "provider_response_hash": "b" * 64,
                "provider_response_id": "http-managed-provider-1",
                "provider_failures": [],
            },
            {
                "response": {
                    "id": "http-managed-provider-2",
                    "object": "chat.completion",
                    "created": 124,
                    "model": "fixture-model",
                    "choices": [
                        {
                            "index": 0,
                            "message": {"role": "assistant", "content": "已完成。"},
                            "finish_reason": "stop",
                        }
                    ],
                },
                "provider": "fixture-provider",
                "model": "fixture-model",
                "mode": "real-api",
                "request_hash": "c" * 64,
                "provider_response_hash": "d" * 64,
                "provider_response_id": "http-managed-provider-2",
                "provider_failures": [],
            },
        ]
        with patch(
            "apps.api.agent_supervisor.adapters.proxy.openai_proxy.forward_openai_chat_completion",
            side_effect=provider_responses,
        ) as forward:
            response = self.client.post(
                "/v1/chat/completions",
                headers={"X-Agent-Session-ID": "http-managed-session"},
                json={
                    "model": "fixture-model",
                    "messages": [{"role": "user", "content": "读取公开说明"}],
                    "tools": [
                        {
                            "type": "function",
                            "function": {
                                "name": "file_read",
                                "parameters": {
                                    "type": "object",
                                    "properties": {"path": {"type": "string"}},
                                    "required": ["path"],
                                    "additionalProperties": False,
                                },
                            },
                        }
                    ],
                    "agent_supervisor": {
                        "mode": "managed",
                        "agent_id": "http-managed-agent",
                        "max_tool_rounds": 1,
                    },
                },
            )

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(forward.call_count, 2)
        body = response.json()
        self.assertEqual(body["choices"][0]["message"]["content"], "已完成。")
        self.assertEqual(body["agent_supervisor"]["execution_mode"], "managed")
        self.assertEqual(body["agent_supervisor"]["managed_status"], "completed")
        self.assertTrue(body["agent_supervisor"]["managed_tool_executions"][0]["execution_observed_by_server"])

    def test_http_managed_gateway_does_not_replay_incomplete_tool_result_to_provider(self) -> None:
        provider_response = {
            "id": "http-managed-incomplete-provider",
            "object": "chat.completion",
            "created": 123,
            "model": "fixture-model",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "http-managed-incomplete-call",
                                "type": "function",
                                "function": {
                                    "name": "file_read",
                                    "arguments": '{"path":"public/项目说明.md"}',
                                },
                            }
                        ],
                    },
                    "finish_reason": "tool_calls",
                }
            ],
        }
        with patch(
            "apps.api.agent_supervisor.adapters.proxy.openai_proxy.forward_openai_chat_completion",
            return_value={
                "response": provider_response,
                "provider": "fixture-provider",
                "model": "fixture-model",
                "mode": "real-api",
                "request_hash": "i" * 64,
                "provider_response_hash": "j" * 64,
                "provider_response_id": "http-managed-incomplete-provider",
                "provider_failures": [],
            },
        ) as forward, patch(
            "apps.api.agent_supervisor.domains.runtime.gateway_execution.execute_tool",
            return_value={
                "executed": False,
                "execution_target": "none",
                "output": "执行器未产生结果",
            },
        ):
            response = self.client.post(
                "/v1/chat/completions",
                headers={"X-Agent-Session-ID": "http-managed-incomplete-session"},
                json={
                    "model": "fixture-model",
                    "messages": [{"role": "user", "content": "读取公开说明"}],
                    "tools": [
                        {
                            "type": "function",
                            "function": {
                                "name": "file_read",
                                "parameters": {
                                    "type": "object",
                                    "properties": {"path": {"type": "string"}},
                                    "required": ["path"],
                                    "additionalProperties": False,
                                },
                            },
                        }
                    ],
                    "agent_supervisor": {
                        "mode": "managed",
                        "agent_id": "http-managed-incomplete-agent",
                        "max_tool_rounds": 1,
                    },
                },
            )

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(forward.call_count, 1)
        body = response.json()
        metadata = body["agent_supervisor"]
        self.assertEqual(metadata["managed_status"], "execution-incomplete")
        self.assertEqual(metadata["decision"], "隔离")
        self.assertEqual(body["choices"][0]["finish_reason"], "content_filter")
        self.assertNotIn("tool_calls", body["choices"][0]["message"])

    def test_http_managed_gateway_surfaces_unknown_execution_as_conflict(self) -> None:
        provider_response = {
            "id": "http-managed-unknown-provider",
            "object": "chat.completion",
            "created": 123,
            "model": "fixture-model",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "http-managed-unknown-call",
                                "type": "function",
                                "function": {
                                    "name": "file_read",
                                    "arguments": '{"path":"public/项目说明.md"}',
                                },
                            }
                        ],
                    },
                    "finish_reason": "tool_calls",
                }
            ],
        }
        with patch(
            "apps.api.agent_supervisor.adapters.proxy.openai_proxy.forward_openai_chat_completion",
            return_value={
                "response": provider_response,
                "provider": "fixture-provider",
                "model": "fixture-model",
                "mode": "real-api",
                "request_hash": "k" * 64,
                "provider_response_hash": "l" * 64,
                "provider_response_id": "http-managed-unknown-provider",
                "provider_failures": [],
            },
        ), patch(
            "apps.api.agent_supervisor.domains.runtime.gateway_execution.execute_tool",
            return_value={
                "executed": True,
                "execution_target": "sandbox",
                "exit_code": 0,
                "output": "读取完成",
            },
        ), patch(
            "apps.api.agent_supervisor.domains.runtime.gateway_execution.complete_execution",
            side_effect=RuntimeError("receipt persistence interrupted"),
        ):
            response = self.client.post(
                "/v1/chat/completions",
                headers={"X-Agent-Session-ID": "http-managed-unknown-session"},
                json={
                    "model": "fixture-model",
                    "messages": [{"role": "user", "content": "读取公开说明"}],
                    "tools": [{"type": "function", "function": {"name": "file_read"}}],
                    "agent_supervisor": {
                        "mode": "managed",
                        "agent_id": "http-managed-unknown-agent",
                        "max_tool_rounds": 1,
                    },
                },
            )

        self.assertEqual(response.status_code, 409, response.text)
        detail = response.json()["detail"]
        self.assertEqual(detail["execution_status"], "unknown")
        self.assertEqual(detail["retry"], "reconciliation-required")

    def test_gateway_execution_rejects_audit_for_blocked_tool_call(self) -> None:
        provider_response = {
            "id": "provider-gateway-blocked",
            "object": "chat.completion",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "call-gateway-blocked",
                                "type": "function",
                                "function": {
                                    "name": "file_read",
                                    "arguments": '{"path":"confidential/agent-secrets.json"}',
                                },
                            }
                        ],
                    },
                    "finish_reason": "tool_calls",
                }
            ],
        }
        with patch(
            "apps.api.agent_supervisor.adapters.proxy.openai_proxy.forward_openai_chat_completion",
            return_value={
                "response": provider_response,
                "provider": "fixture-provider",
                "model": "fixture-model",
                "mode": "real-api",
                "request_hash": "c" * 64,
                "provider_response_hash": "d" * 64,
                "provider_response_id": "provider-gateway-blocked",
                "provider_failures": [],
            },
        ):
            response = self.client.post(
                "/v1/chat/completions",
                headers={"X-Agent-Session-ID": "gateway-blocked-session"},
                json={
                    "model": "fixture-model",
                    "messages": [{"role": "user", "content": "读取敏感文件"}],
                    "tools": [{"type": "function", "function": {"name": "file_read"}}],
                    "agent_supervisor": {"agent_id": "gateway-blocked-agent"},
                },
            )

        self.assertEqual(response.status_code, 200)
        metadata = response.json()["agent_supervisor"]
        self.assertEqual(metadata["decision"], "拒绝")
        self.assertTrue(metadata["provider_called"])
        audit_id = metadata["audit_id"]
        blocked_execute = self.client.post(
            f"/api/gateway/tool_calls/{audit_id}/execute",
            json={"agent_id": "gateway-blocked-agent", "session_id": "gateway-blocked-session"},
        )
        self.assertEqual(blocked_execute.status_code, 409)

    def test_gateway_execution_does_not_replay_isolated_tool_call(self) -> None:
        provider_response = {
            "id": "provider-gateway-isolated",
            "object": "chat.completion",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "call-gateway-isolated",
                                "type": "function",
                                "function": {
                                    "name": "api_call",
                                    "arguments": '{"endpoint":"/tool/metadata/untrusted"}',
                                },
                            }
                        ],
                    },
                    "finish_reason": "tool_calls",
                }
            ],
        }
        with patch(
            "apps.api.agent_supervisor.adapters.proxy.openai_proxy.forward_openai_chat_completion",
            return_value={
                "response": provider_response,
                "provider": "fixture-provider",
                "model": "fixture-model",
                "mode": "real-api",
                "request_hash": "1" * 64,
                "provider_response_hash": "2" * 64,
                "provider_response_id": "provider-gateway-isolated",
                "provider_failures": [],
            },
        ):
            first = self.client.post(
                "/v1/chat/completions",
                headers={"X-Agent-Session-ID": "gateway-isolated-session"},
                json={
                    "model": "fixture-model",
                    "messages": [{"role": "user", "content": "读取不可信工具结果"}],
                    "tools": [{"type": "function", "function": {"name": "api_call"}}],
                    "agent_supervisor": {"agent_id": "gateway-isolated-agent"},
                },
            )

        self.assertEqual(first.status_code, 200, first.text)
        metadata = first.json()["agent_supervisor"]
        self.assertEqual(metadata["decision"], "隔离")
        audit_id = metadata["tool_decisions"][0]["audit_id"]
        blocked = self.client.post(
            f"/api/gateway/tool_calls/{audit_id}/execute",
            json={
                "agent_id": "gateway-isolated-agent",
                "session_id": "gateway-isolated-session",
                "provider_call_id": "call-gateway-isolated",
            },
        )
        self.assertEqual(blocked.status_code, 409)
        self.assertIn("仅接受允许", blocked.text)

    def test_gateway_execution_freezes_claim_when_receipt_persistence_fails(self) -> None:
        decision = self._create_allowed_gateway_audit(
            agent_id="gateway-uncertain-agent",
            session_id="gateway-uncertain-session",
            provider_call_id="call-gateway-uncertain",
        )
        from apps.api.agent_supervisor.domains.runtime.gateway_execution import execute_gateway_tool_call

        with patch(
            "apps.api.agent_supervisor.domains.runtime.gateway_execution.execute_tool",
            return_value={
                "executed": True,
                "execution_target": "sandbox",
                "exit_code": 0,
                "output": "读取完成",
            },
        ) as execute_tool_mock, patch(
            "apps.api.agent_supervisor.domains.runtime.gateway_execution.complete_execution",
            side_effect=RuntimeError("receipt store unavailable"),
        ):
            with self.assertRaises(GatewayExecutionUncertainError):
                execute_gateway_tool_call(
                    decision["audit_id"],
                    agent_id="gateway-uncertain-agent",
                    session_id="gateway-uncertain-session",
                    provider_call_id="call-gateway-uncertain",
                )

            claim = load_gateway_execution_claim(decision["audit_id"])
            self.assertIsNotNone(claim)
            assert claim is not None
            self.assertEqual(claim["status"], "unknown")
            self.assertEqual(execute_tool_mock.call_count, 1)

            with self.assertRaises(GatewayExecutionUncertainError):
                execute_gateway_tool_call(
                    decision["audit_id"],
                    agent_id="gateway-uncertain-agent",
                    session_id="gateway-uncertain-session",
                    provider_call_id="call-gateway-uncertain",
                )
            self.assertEqual(execute_tool_mock.call_count, 1)

        events = list_runtime_events(event_type="gateway-execution-uncertain", limit=20)
        matching = [event for event in events if event.get("payload", {}).get("audit_id") == decision["audit_id"]]
        self.assertTrue(matching)
        self.assertEqual(matching[0]["payload"]["status"], "unknown")
        self.assertEqual(matching[0]["payload"]["phase"], "receipt-persistence")
        detail = self.client.get(f"/api/runtime/executions/{decision['audit_id']}")
        self.assertEqual(detail.status_code, 200, detail.text)
        self.assertEqual(detail.json()["gateway_execution_claim"]["status"], "unknown")
        listing = self.client.get("/api/runtime/executions")
        self.assertEqual(listing.status_code, 200, listing.text)
        self.assertGreaterEqual(listing.json()["summary"]["gateway_unknown"], 1)

    def test_gateway_execution_freezes_claim_when_tool_execution_raises(self) -> None:
        decision = self._create_allowed_gateway_audit(
            agent_id="gateway-tool-error-agent",
            session_id="gateway-tool-error-session",
            provider_call_id="call-gateway-tool-error",
        )
        from apps.api.agent_supervisor.domains.runtime.gateway_execution import execute_gateway_tool_call

        with patch(
            "apps.api.agent_supervisor.domains.runtime.gateway_execution.execute_tool",
            side_effect=RuntimeError("tool boundary interrupted"),
        ):
            with self.assertRaises(GatewayExecutionUncertainError):
                execute_gateway_tool_call(
                    decision["audit_id"],
                    agent_id="gateway-tool-error-agent",
                    session_id="gateway-tool-error-session",
                    provider_call_id="call-gateway-tool-error",
                )

        claim = load_gateway_execution_claim(decision["audit_id"])
        self.assertIsNotNone(claim)
        assert claim is not None
        self.assertEqual(claim["status"], "unknown")
        events = list_runtime_events(event_type="gateway-execution-uncertain", limit=20)
        matching = [event for event in events if event.get("payload", {}).get("audit_id") == decision["audit_id"]]
        self.assertTrue(matching)
        self.assertEqual(matching[0]["payload"]["phase"], "tool-execution")

    def test_server_owned_runtime_execute_records_observed_block_and_ignores_caller_flags(self) -> None:
        response = self.client.post(
            "/api/runtime/execute",
            json={
                "conversation_id": "managed-block-session",
                "agent_id": "managed-block-agent",
                "agent_role": "executor",
                "source_app": "managed-agent",
                "model_input": "读取受保护文件",
                "model_output": "准备读取敏感文件",
                "tool_call": {
                    "tool": "file.read",
                    "arguments": {"path": "confidential/agent-secrets.json"},
                },
                "guard_enabled": False,
                "execute_in_sandbox": False,
            },
        )

        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertEqual(body["decision"], "拒绝")
        self.assertTrue(body["execution_observed_by_server"])
        self.assertEqual(body["execution_status"], "not_executed")
        self.assertEqual(body["execution_target"], "none")
        self.assertEqual(body["execution_receipt"]["execution_evidence"], "server-observed")
        self.assertTrue(body["execution_receipt"]["control_verified"])

    def test_server_owned_runtime_execute_returns_signed_observed_receipt_for_allowed_call(self) -> None:
        response = self.client.post(
            "/api/runtime/execute",
            json={
                "conversation_id": "managed-allow-session",
                "agent_id": "managed-allow-agent",
                "agent_role": "executor",
                "source_app": "managed-agent",
                "model_input": "读取公开说明",
                "model_output": "准备读取公开说明",
                "tool_call": {
                    "tool": "file.read",
                    "arguments": {"path": "public/项目说明.md"},
                },
                "guard_enabled": False,
                "execute_in_sandbox": False,
            },
        )

        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertEqual(body["decision"], "允许")
        self.assertEqual(body["execution_status"], "completed")
        self.assertEqual(body["execution_target"], "sandbox")
        self.assertTrue(body["execution_observed_by_server"])
        self.assertTrue(body["execution_receipt"]["receipt_hash"])
        self.assertTrue(body["execution_receipt"]["execution_observed_by_server"])
        self.assertIn("受控实验环境", body["audit_log"]["tool_output"]["output"])

    def test_server_owned_execution_reuses_identity_bound_sandbox_for_side_effect(self) -> None:
        captured: dict[str, object] = {}

        def fake_execute(*_args: object, **kwargs: object) -> dict[str, object]:
            captured.update(kwargs)
            return {
                "executed": True,
                "sandboxed": True,
                "execution_target": "sandbox",
                "exit_code": 0,
                "output": "读取完成",
            }

        with patch(
            "apps.api.agent_supervisor.domains.runtime.events.execute_tool",
            side_effect=fake_execute,
        ):
            response = self.client.post(
                "/api/runtime/execute",
                json={
                    "conversation_id": "managed-isolated-session",
                    "agent_id": "managed-isolated-agent",
                    "agent_role": "executor",
                    "source_app": "managed-agent",
                    "model_input": "读取公开说明",
                    "tool_call": {
                        "tool": "file.read",
                        "arguments": {"path": "public/项目说明.md"},
                    },
                },
            )

        self.assertEqual(response.status_code, 200, response.text)
        sandbox = captured.get("sandbox")
        self.assertIsInstance(sandbox, SandboxPaths)
        assert isinstance(sandbox, SandboxPaths)
        self.assertIn("agents", str(sandbox.workspace))
        self.assertFalse(sandbox.seed_fixtures)

    def test_server_owned_runtime_execute_exact_retry_is_idempotent(self) -> None:
        calls = 0
        nonce = uuid4().hex

        def fake_execute(*_args: object, **_kwargs: object) -> dict[str, object]:
            nonlocal calls
            calls += 1
            return {
                "executed": True,
                "sandboxed": True,
                "execution_target": "sandbox",
                "exit_code": 0,
                "output": "读取完成",
            }

        payload = {
            "conversation_id": f"managed-idempotency-session-{nonce}",
            "agent_id": f"managed-idempotency-agent-{nonce}",
            "agent_role": "executor",
            "source_app": "managed-agent",
            "model_input": "读取公开说明",
            "model_output": "准备读取公开说明",
            "tool_call": {
                "tool": "file.read",
                "arguments": {"path": "public/项目说明.md"},
            },
        }
        with patch(
            "apps.api.agent_supervisor.domains.runtime.events.execute_tool",
            side_effect=fake_execute,
        ):
            first = self.client.post("/api/runtime/execute", json=payload)
            second = self.client.post("/api/runtime/execute", json=payload)

        self.assertEqual(first.status_code, 200, first.text)
        self.assertEqual(second.status_code, 200, second.text)
        self.assertEqual(calls, 1)
        self.assertEqual(first.json()["audit_id"], second.json()["audit_id"])
        self.assertEqual(second.json()["idempotent"], True)
        self.assertEqual(second.json()["execution_status"], "completed")
        self.assertEqual(
            second.json()["execution_receipt"]["receipt_hash"],
            first.json()["execution_receipt"]["receipt_hash"],
        )

    def test_server_owned_runtime_execute_freezes_unknown_after_result_persistence_failure(self) -> None:
        calls = 0
        nonce = uuid4().hex

        def fake_execute(*_args: object, **_kwargs: object) -> dict[str, object]:
            nonlocal calls
            calls += 1
            return {
                "executed": True,
                "sandboxed": True,
                "execution_target": "sandbox",
                "exit_code": 0,
                "output": "写入完成",
            }

        def persist_with_final_failure(result: dict[str, object], *, append_runtime_event: bool = True) -> None:
            if append_runtime_event:
                raise RuntimeError("simulated final audit persistence outage")
            persist_run(result, append_runtime_event=False)

        payload = {
            "conversation_id": f"managed-unknown-session-{nonce}",
            "agent_id": f"managed-unknown-agent-{nonce}",
            "agent_role": "executor",
            "source_app": "managed-agent",
            "model_input": "读取公开说明",
            "model_output": "准备读取公开说明",
            "tool_call": {
                "tool": "file.read",
                "arguments": {"path": "public/项目说明.md"},
            },
        }
        with (
            patch(
                "apps.api.agent_supervisor.domains.runtime.events.execute_tool",
                side_effect=fake_execute,
            ),
            patch(
                "apps.api.agent_supervisor.domains.runtime.events.write_run",
                side_effect=persist_with_final_failure,
            ),
        ):
            first = self.client.post("/api/runtime/execute", json=payload)
            second = self.client.post("/api/runtime/execute", json=payload)

        self.assertEqual(first.status_code, 409, first.text)
        self.assertEqual(second.status_code, 409, second.text)
        self.assertEqual(calls, 1)
        detail = first.json()["detail"]
        self.assertEqual(detail["execution_status"], "unknown")
        audit_id = "runtime-" + hashlib.sha256(
            json.dumps(
                {
                    "conversation_id": payload["conversation_id"],
                    "agent_id": payload["agent_id"],
                    "agent_role": payload["agent_role"],
                    "source_app": payload["source_app"],
                    "model_input": payload["model_input"],
                    "model_output": payload["model_output"],
                    "tool_call": payload["tool_call"],
                    "context_sources": [],
                },
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        claim = load_gateway_execution_claim(audit_id)
        self.assertIsNotNone(claim)
        assert claim is not None
        self.assertEqual(claim["status"], "unknown")
        events = list_runtime_events(event_type="server-execution-uncertain", limit=20)
        self.assertTrue(any(item.get("payload", {}).get("audit_id") == audit_id for item in events))

    def test_gateway_execution_claim_prevents_concurrent_duplicate_side_effect(self) -> None:
        provider_response = {
            "id": "provider-gateway-race",
            "object": "chat.completion",
            "created": 123,
            "model": "fixture-model",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "call-gateway-race",
                                "type": "function",
                                "function": {
                                    "name": "file_write",
                                    "arguments": '{"path":"reports/race.txt","content":"x"}',
                                },
                            }
                        ],
                    },
                    "finish_reason": "tool_calls",
                }
            ],
        }
        with patch(
            "apps.api.agent_supervisor.adapters.proxy.openai_proxy.forward_openai_chat_completion",
            return_value={
                "response": provider_response,
                "provider": "fixture-provider",
                "model": "fixture-model",
                "mode": "real-api",
                "request_hash": "e" * 64,
                "provider_response_hash": "f" * 64,
                "provider_response_id": "provider-gateway-race",
                "provider_failures": [],
            },
        ):
            first = self.client.post(
                "/v1/chat/completions",
                headers={"X-Agent-Session-ID": "gateway-race-session"},
                json={
                    "model": "fixture-model",
                    "messages": [{"role": "user", "content": "写入测试文件"}],
                    "tools": [
                        {
                            "type": "function",
                            "function": {
                                "name": "file_write",
                                "parameters": {
                                    "type": "object",
                                    "properties": {
                                        "path": {"type": "string"},
                                        "content": {"type": "string"},
                                    },
                                    "required": ["path", "content"],
                                    "additionalProperties": False,
                                },
                            },
                        }
                    ],
                    "agent_supervisor": {"agent_id": "gateway-race-agent"},
                },
            )

        self.assertEqual(first.status_code, 200, first.text)
        decision = first.json()["agent_supervisor"]["tool_decisions"][0]
        from apps.api.agent_supervisor.domains.runtime.gateway_execution import execute_gateway_tool_call

        calls = 0
        calls_lock = threading.Lock()
        execution_started = threading.Event()
        allow_execution_completion = threading.Event()

        def fake_execute(*_args: object, **_kwargs: object) -> dict[str, object]:
            nonlocal calls
            with calls_lock:
                calls += 1
            execution_started.set()
            if not allow_execution_completion.wait(timeout=5):
                raise TimeoutError("并发测试未释放首个工具执行")
            return {
                "executed": True,
                "sandboxed": True,
                "execution_target": "sandbox",
                "exit_code": 0,
                "output": "写入完成",
            }

        def invoke() -> dict[str, object]:
            try:
                return execute_gateway_tool_call(
                    decision["audit_id"],
                    agent_id="gateway-race-agent",
                    session_id="gateway-race-session",
                    provider_call_id="call-gateway-race",
                )
            except ValueError as exc:
                return {"error": str(exc)}

        with patch(
            "apps.api.agent_supervisor.domains.runtime.gateway_execution.execute_tool",
            side_effect=fake_execute,
        ):
            with ThreadPoolExecutor(max_workers=2) as pool:
                first_future = pool.submit(invoke)
                self.assertTrue(execution_started.wait(timeout=2), "首个工具执行未进入副作用边界")
                second_future = pool.submit(invoke)
                try:
                    second_result = second_future.result(timeout=2)
                finally:
                    allow_execution_completion.set()
                first_result = first_future.result(timeout=2)
                results = [first_result, second_result]

        self.assertEqual(calls, 1)
        self.assertEqual(sum(1 for item in results if "receipt" in item), 1)
        self.assertEqual(sum(1 for item in results if "error" in item), 1)
        self.assertIn("占用", str(next(item["error"] for item in results if "error" in item)))
