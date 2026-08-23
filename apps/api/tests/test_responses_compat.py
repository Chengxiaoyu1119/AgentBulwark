from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from apps.api.agent_supervisor.adapters.proxy.responses_compat import (
    ResponsesCompatibilityError,
    chat_response_to_responses,
    responses_request_to_chat,
)
from apps.api.agent_supervisor.main import app


class ResponsesCompatibilityTests(unittest.TestCase):
    def test_text_and_function_request_maps_to_chat_security_contract(self) -> None:
        chat = responses_request_to_chat(
            {
                "model": "fixture-model",
                "instructions": "You are a bounded assistant.",
                "input": "Read the public file.",
                "max_output_tokens": 128,
                "tools": [
                    {
                        "type": "function",
                        "name": "file_read",
                        "description": "Read an approved file.",
                        "parameters": {"type": "object", "properties": {"path": {"type": "string"}}},
                    }
                ],
                "tool_choice": {"type": "function", "name": "file_read"},
                "agent_supervisor": {"session_id": "responses-session"},
            }
        )

        self.assertEqual(chat["model"], "fixture-model")
        self.assertEqual(chat["max_tokens"], 128)
        self.assertEqual(chat["messages"][0], {"role": "system", "content": "You are a bounded assistant."})
        self.assertEqual(chat["messages"][1], {"role": "user", "content": "Read the public file."})
        self.assertEqual(chat["tools"][0]["function"]["name"], "file_read")
        self.assertEqual(chat["tool_choice"], {"type": "function", "function": {"name": "file_read"}})

    def test_function_call_items_round_trip_to_receipt_bound_chat_history(self) -> None:
        chat = responses_request_to_chat(
            {
                "model": "fixture-model",
                "input": [
                    {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "Read it."}]},
                    {
                        "type": "function_call",
                        "call_id": "call-1",
                        "name": "file_read",
                        "arguments": '{"path":"public/readme.md"}',
                    },
                    {"type": "function_call_output", "call_id": "call-1", "output": {"ok": True}},
                ],
            }
        )

        self.assertEqual(chat["messages"][0]["content"], [{"type": "text", "text": "Read it."}])
        self.assertEqual(chat["messages"][1]["tool_calls"][0]["id"], "call-1")
        self.assertEqual(chat["messages"][2], {"role": "tool", "tool_call_id": "call-1", "content": '{"ok":true}'})

    def test_unknown_responses_features_fail_closed(self) -> None:
        unsupported = (
            ({"model": "fixture-model", "input": "x", "previous_response_id": "resp-1"}, "不支持字段"),
            ({"model": "fixture-model", "input": "x", "stream": True}, "流式请求"),
            ({"model": "fixture-model", "input": "x", "tools": [{"type": "web_search"}]}, "内置工具"),
            ({"model": "fixture-model", "input": [{"type": "reasoning", "summary": []}]}, "未纳入"),
        )
        for payload, message in unsupported:
            with self.subTest(payload=payload), self.assertRaisesRegex(ResponsesCompatibilityError, message):
                responses_request_to_chat(payload)

    def test_chat_response_projects_only_sanitized_message_and_function_call(self) -> None:
        result = chat_response_to_responses(
            {
                "id": "chatcmpl-fixture",
                "created": 123,
                "model": "fixture-model",
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": None,
                            "tool_calls": [
                                {
                                    "id": "call-1",
                                    "type": "function",
                                    "function": {"name": "file_read", "arguments": '{"path":"public/a"}'},
                                }
                            ],
                        }
                    }
                ],
                "usage": {"prompt_tokens": 4, "completion_tokens": 6, "total_tokens": 10},
                "agent_supervisor": {"decision": "允许", "audit_id": "audit-1"},
                "provider_secret": "must not cross projection",
            },
            {"model": "fixture-model", "input": "x"},
        )

        self.assertEqual(result["object"], "response")
        self.assertEqual(result["output"][0]["type"], "function_call")
        self.assertEqual(result["output"][0]["call_id"], "call-1")
        self.assertEqual(result["usage"], {"input_tokens": 4, "output_tokens": 6, "total_tokens": 10})
        self.assertNotIn("provider_secret", result)

    def test_http_responses_route_reuses_gateway_boundary(self) -> None:
        provider_response = {
            "id": "chatcmpl-fixture",
            "created": 123,
            "model": "fixture-model",
            "choices": [{"message": {"role": "assistant", "content": "checked"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
            "agent_supervisor": {"decision": "允许", "audit_id": "audit-1"},
        }
        with patch.dict(
            os.environ,
            {
                "AGENT_SUPERVISOR_AUTH_DISABLED": "true",
                "AGENT_SUPERVISOR_PROXY_ALLOW_UNAUTHENTICATED_PUBLIC": "true",
            },
            clear=False,
        ), patch(
            "apps.api.agent_supervisor.routers.proxy.run_openai_proxy_completion",
            return_value=provider_response,
        ) as run, TestClient(app) as client:
            response = client.post(
                "/v1/responses",
                json={"model": "fixture-model", "input": "hello", "max_output_tokens": 32},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["output_text"], "checked")
        translated_payload = run.call_args.args[0]
        self.assertEqual(translated_payload["messages"], [{"role": "user", "content": "hello"}])
        self.assertEqual(translated_payload["max_tokens"], 32)
