"""MCP MRTR 状态和现代 stdio 桥接的可回归验证。"""

from __future__ import annotations

import base64
import json
import os
import sys
import threading
import time
import unittest
from collections import deque
from pathlib import Path
from typing import Any, cast
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient

from apps.api.agent_supervisor.main import app
from apps.api.agent_supervisor.mcp_gateway.gateway import McpGateway, _PendingMcpExecution, reset_gateway
from apps.api.agent_supervisor.mcp_gateway.mrtr import RequestStateCodec, RequestStateError, validate_mrtr_retry_fields
from apps.api.agent_supervisor.mcp_gateway.upstream import StdioMcpUpstream, StdioUpstreamError

FIXTURE_SERVER = Path("apps/api/tests/fixtures/mcp_echo_server.py").resolve()
MODERN = "2026-07-28"
MRTR_CAPABILITIES: dict[str, dict[str, Any]] = {"sampling": {}, "elicitation": {}, "roots": {}}


def _message(
    *,
    request_id: str,
    input_responses: dict | None = None,
    request_state: str | None = None,
    progress_token: str | None = None,
    client_capabilities: dict | None = None,
    log_level: str | None = None,
) -> dict:
    params: dict = {
        "name": "file.read",
        "arguments": {"path": "public/readme.md"},
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": MODERN,
            "io.modelcontextprotocol/clientCapabilities": dict(
                MRTR_CAPABILITIES if client_capabilities is None else client_capabilities
            ),
        },
    }
    if progress_token is not None:
        params["_meta"]["progressToken"] = progress_token
    if log_level is not None:
        params["_meta"]["io.modelcontextprotocol/logLevel"] = log_level
    if input_responses is not None:
        params["inputResponses"] = input_responses
    if request_state is not None:
        params["requestState"] = request_state
    return {"jsonrpc": "2.0", "id": request_id, "method": "tools/call", "params": params}


def _headers(method: str = "tools/call", name: str = "file.read") -> dict[str, str]:
    headers = {
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": MODERN,
        "Mcp-Method": method,
        "X-Agent-Session-ID": "mrtr-session",
    }
    if name:
        headers["Mcp-Name"] = name
    return headers


def _context_message(
    *,
    method: str,
    request_id: str,
    params: dict,
    input_responses: dict | None = None,
    request_state: str | None = None,
    client_capabilities: dict | None = None,
) -> dict:
    payload: dict[str, Any] = {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": method,
        "params": {
            **params,
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": MODERN,
                "io.modelcontextprotocol/clientCapabilities": dict(
                    MRTR_CAPABILITIES if client_capabilities is None else client_capabilities
                ),
            },
        },
    }
    if input_responses is not None:
        payload["params"]["inputResponses"] = input_responses
    if request_state is not None:
        payload["params"]["requestState"] = request_state
    return payload


class RequestStateCodecTest(unittest.TestCase):
    def setUp(self) -> None:
        self.codec = RequestStateCodec("k" * 32, ttl_seconds=60)

    def test_state_round_trips_and_single_use_is_enforced(self) -> None:
        token = self.codec.mint({"agent_id": "agent-a", "request_hash": "abc"}, now=100)
        self.assertEqual(self.codec.consume(token, now=101)["agent_id"], "agent-a")
        with self.assertRaises(RequestStateError):
            self.codec.consume(token, now=101)

    def test_state_tampering_and_expiry_are_rejected(self) -> None:
        token = self.codec.mint({"agent_id": "agent-a"}, now=100)
        parts = token.split(".")
        raw = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
        raw["payload"]["agent_id"] = "agent-b"
        encoded = base64.urlsafe_b64encode(json.dumps(raw, separators=(",", ":")).encode()).decode().rstrip("=")
        with self.assertRaises(RequestStateError):
            self.codec.verify(f"v1.{encoded}.{parts[2]}", now=101)
        with self.assertRaises(RequestStateError):
            self.codec.verify(token, now=161)

    def test_retry_input_rejects_non_finite_json_values(self) -> None:
        with self.assertRaisesRegex(RequestStateError, "inputResponses"):
            validate_mrtr_retry_fields(
                "tools/call",
                {"requestState": "v1.state.signature", "inputResponses": {"answer": {"score": float("nan")}}},
            )


class ModernMcpMrtrHttpTest(unittest.TestCase):
    def setUp(self) -> None:
        self.environment = patch.dict(
            os.environ,
            {
                "AGENT_SUPERVISOR_AUTH_DISABLED": "true",
                "MCP_GATEWAY_ENABLED": "true",
                "MCP_GATEWAY_GUARD_ENABLED": "true",
                "MCP_GATEWAY_SESSION_ISOLATION": "true",
                "MCP_GATEWAY_REQUEST_STATE_SECRET": "s" * 48,
                "MCP_GATEWAY_UPSTREAM_COMMAND": (
                    f'"{Path(sys.executable).as_posix()}" -X utf8 "{FIXTURE_SERVER.as_posix()}"'
                ),
            },
            clear=False,
        )
        self.environment.start()
        reset_gateway()
        self.client = TestClient(app)

    def tearDown(self) -> None:
        self.client.close()
        reset_gateway()
        self.environment.stop()

    def test_server_request_is_projected_to_input_required_and_resumed(self) -> None:
        with patch.dict(os.environ, {"MCP_ECHO_SERVER_REQUEST": "1"}, clear=False):
            first = self.client.post("/api/mcp", headers=_headers(), json=_message(request_id="round-1"))
            self.assertEqual(first.status_code, 200)
            first_payload = first.json()
            result = first_payload["result"]
            self.assertEqual(result["resultType"], "input_required")
            self.assertIn("requestState", result)
            self.assertIn("srv-req-1", result["inputRequests"])
            self.assertEqual(result["inputRequests"]["srv-req-1"]["method"], "sampling/createMessage")

            second = self.client.post(
                "/api/mcp",
                headers=_headers(),
                json=_message(
                    request_id="round-2",
                    input_responses={
                        "srv-req-1": {
                            "role": "assistant",
                            "content": {"type": "text", "text": "已确认"},
                            "model": "fixture",
                        }
                    },
                    request_state=result["requestState"],
                ),
            )
            self.assertEqual(second.status_code, 200)
            second_result = second.json()["result"]
            self.assertEqual(second_result["resultType"], "complete")
            self.assertFalse(second_result["isError"])

    def test_retry_fields_must_be_paired_before_gateway_or_upstream_io(self) -> None:
        cases: list[dict[str, Any]] = [
            {"inputResponses": {"srv-req-1": {}}},
            {"requestState": "v1.unpaired.state"},
        ]
        for index, retry_fields in enumerate(cases):
            with self.subTest(retry_fields=tuple(retry_fields)):
                message = _message(request_id=f"unpaired-{index}")
                message["params"].update(retry_fields)
                with patch("apps.api.agent_supervisor.routers.mcp.get_gateway") as gateway_getter:
                    response = self.client.post("/api/mcp", headers=_headers(), json=message)
                self.assertEqual(response.status_code, 400)
                self.assertEqual(response.json()["error"]["code"], -32602)
                gateway_getter.assert_not_called()

    def test_retry_input_responses_are_typed_and_bounded_before_gateway_io(self) -> None:
        malformed = _message(request_id="bad-input-type", request_state="v1.invalid.state")
        malformed["params"]["inputResponses"] = []
        oversized = _message(
            request_id="oversized-input",
            request_state="v1.invalid.state",
            input_responses={"srv-req-1": {"content": "x" * (300 * 1024)}},
        )
        for message in (malformed, oversized):
            with self.subTest(request_id=message["id"]):
                with patch("apps.api.agent_supervisor.routers.mcp.get_gateway") as gateway_getter:
                    response = self.client.post("/api/mcp", headers=_headers(), json=message)
                self.assertEqual(response.status_code, 400)
                self.assertEqual(response.json()["error"]["code"], -32602)
                self.assertIn("inputResponses", response.json()["error"]["message"])
                gateway_getter.assert_not_called()

    def test_missing_sampling_capability_returns_protocol_error_and_closes_pending_call(self) -> None:
        with patch.dict(os.environ, {"MCP_ECHO_SERVER_REQUEST": "1"}, clear=False):
            response = self.client.post(
                "/api/mcp",
                headers=_headers(),
                json=_message(request_id="missing-sampling", client_capabilities={}),
            )
        self.assertEqual(response.status_code, 400)
        payload = response.json()
        self.assertEqual(payload["error"]["code"], -32021)
        self.assertEqual(payload["error"]["data"]["requiredCapabilities"], {"sampling": {}})
        audit_marker = payload["error"]["data"]["zhiAnSentinel"]
        self.assertTrue(audit_marker["intentAuditId"])
        self.assertTrue(audit_marker["resultAuditId"])
        recovered = self.client.post(
            "/api/mcp",
            headers=_headers("tools/list", ""),
            json=_context_message(method="tools/list", request_id="after-missing-capability", params={}),
        )
        self.assertEqual(recovered.status_code, 200)
        self.assertTrue(recovered.json()["result"]["tools"])

    def test_missing_elicitation_capability_blocks_context_input_request(self) -> None:
        with patch.dict(os.environ, {"MCP_ECHO_SERVER_REQUEST_ON_CONTEXT": "1"}, clear=False):
            listed = self.client.post(
                "/api/mcp",
                headers=_headers("resources/list", ""),
                json=_context_message(method="resources/list", request_id="elicitation-list", params={}),
            )
            uri = listed.json()["result"]["resources"][0]["uri"]
            response = self.client.post(
                "/api/mcp",
                headers=_headers("resources/read", uri),
                json=_context_message(
                    method="resources/read",
                    request_id="missing-elicitation",
                    params={"uri": uri},
                    client_capabilities={},
                ),
            )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error"]["code"], -32021)
        self.assertEqual(response.json()["error"]["data"]["requiredCapabilities"], {"elicitation": {}})

    def test_roots_input_request_requires_roots_capability_and_resumes_when_declared(self) -> None:
        environment = {
            "MCP_ECHO_SERVER_REQUEST": "1",
            "MCP_ECHO_SERVER_REQUEST_METHOD": "roots/list",
        }
        with patch.dict(os.environ, environment, clear=False):
            missing = self.client.post(
                "/api/mcp",
                headers=_headers(),
                json=_message(request_id="missing-roots", client_capabilities={}),
            )
        self.assertEqual(missing.status_code, 400)
        self.assertEqual(missing.json()["error"]["data"]["requiredCapabilities"], {"roots": {}})

        reset_gateway()
        with patch.dict(os.environ, environment, clear=False):
            first = self.client.post("/api/mcp", headers=_headers(), json=_message(request_id="roots-round-1"))
            result = first.json()["result"]
            self.assertEqual(result["inputRequests"]["srv-req-1"]["method"], "roots/list")
            resumed = self.client.post(
                "/api/mcp",
                headers=_headers(),
                json=_message(
                    request_id="roots-round-2",
                    request_state=result["requestState"],
                    input_responses={"srv-req-1": {"roots": []}},
                ),
            )
        self.assertEqual(resumed.status_code, 200)
        self.assertEqual(resumed.json()["result"]["resultType"], "complete")

    def test_missing_capability_stays_inside_an_already_open_request_stream(self) -> None:
        with patch.dict(os.environ, {"MCP_ECHO_SERVER_REQUEST": "1"}, clear=False):
            response = self.client.post(
                "/api/mcp",
                headers=_headers(),
                json=_message(
                    request_id="missing-sampling-stream",
                    client_capabilities={},
                    progress_token="missing-sampling-stream",
                ),
            )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.headers["content-type"].startswith("text/event-stream"))
        events = [json.loads(line.removeprefix("data: ")) for line in response.text.splitlines() if line.startswith("data: ")]
        self.assertEqual(events[-1]["error"]["code"], -32021)

    def test_progress_token_uses_request_scoped_sse_stream(self) -> None:
        with patch.dict(os.environ, {"MCP_ECHO_PROGRESS_ON_CALL": "1"}, clear=False):
            response = self.client.post(
                "/api/mcp",
                headers=_headers(),
                json=_message(request_id="progress-1", progress_token="progress-1"),
            )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.headers["content-type"].startswith("text/event-stream"))
        events = [json.loads(line.removeprefix("data: ")) for line in response.text.splitlines() if line.startswith("data: ")]
        methods = [event.get("method") for event in events]
        self.assertIn("notifications/progress", methods)
        final = events[-1]
        self.assertEqual(final["result"]["resultType"], "complete")

    def test_mrtr_resume_rebinds_progress_and_logs_to_the_retry_stream(self) -> None:
        environment = {
            "MCP_ECHO_SERVER_REQUEST": "1",
            "MCP_ECHO_PROGRESS_ON_CALL": "1",
            "MCP_ECHO_LOG_LEVELS": "debug,info,warning,error",
        }
        with patch.dict(os.environ, environment, clear=False):
            first = self.client.post(
                "/api/mcp",
                headers=_headers(),
                json=_message(request_id="stream-round-1", progress_token="stream-round-1", log_level="warning"),
            )
            first_events = [
                json.loads(line.removeprefix("data: "))
                for line in first.text.splitlines()
                if line.startswith("data: ")
            ]
            first_result = first_events[-1]["result"]
            self.assertEqual(first_result["resultType"], "input_required")

            second = self.client.post(
                "/api/mcp",
                headers=_headers(),
                json=_message(
                    request_id="stream-round-2",
                    progress_token="stream-round-2",
                    log_level="warning",
                    request_state=first_result["requestState"],
                    input_responses={"srv-req-1": {}},
                ),
            )

        second_events = [
            json.loads(line.removeprefix("data: "))
            for line in second.text.splitlines()
            if line.startswith("data: ")
        ]
        progress = [event for event in second_events if event.get("method") == "notifications/progress"]
        log_levels = [
            event.get("params", {}).get("level")
            for event in second_events
            if event.get("method") == "notifications/message"
        ]
        self.assertEqual([event["params"]["progressToken"] for event in progress], ["stream-round-2"])
        self.assertEqual(log_levels, ["warning", "error"])
        self.assertEqual(second_events[-1]["result"]["resultType"], "complete")

    def test_invalid_log_level_is_rejected_before_gateway_io(self) -> None:
        message = _message(request_id="invalid-log-level", log_level="verbose")
        with patch("apps.api.agent_supervisor.routers.mcp.get_gateway") as gateway_getter:
            response = self.client.post("/api/mcp", headers=_headers(), json=message)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error"]["code"], -32602)
        gateway_getter.assert_not_called()

    def test_log_level_alone_opens_request_stream_and_filters_lower_severity(self) -> None:
        with patch.dict(os.environ, {"MCP_ECHO_LOG_LEVELS": "debug,info,warning,error"}, clear=False):
            response = self.client.post(
                "/api/mcp",
                headers=_headers(),
                json=_message(request_id="request-logs", log_level="warning"),
            )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.headers["content-type"].startswith("text/event-stream"))
        events = [json.loads(line.removeprefix("data: ")) for line in response.text.splitlines() if line.startswith("data: ")]
        log_levels = [event.get("params", {}).get("level") for event in events if event.get("method") == "notifications/message"]
        self.assertEqual(log_levels, ["warning", "error"])
        self.assertEqual(events[-1]["result"]["resultType"], "complete")

    def test_progress_stream_suppresses_logs_without_log_level_opt_in(self) -> None:
        with patch.dict(
            os.environ,
            {"MCP_ECHO_LOG_LEVELS": "warning,error", "MCP_ECHO_PROGRESS_ON_CALL": "1"},
            clear=False,
        ):
            response = self.client.post(
                "/api/mcp",
                headers=_headers(),
                json=_message(request_id="progress-no-logs", progress_token="progress-no-logs"),
            )
        events = [json.loads(line.removeprefix("data: ")) for line in response.text.splitlines() if line.startswith("data: ")]
        self.assertIn("notifications/progress", [event.get("method") for event in events])
        self.assertNotIn("notifications/message", [event.get("method") for event in events])

    def test_request_stream_drops_progress_from_another_token(self) -> None:
        with patch.dict(
            os.environ,
            {"MCP_ECHO_PROGRESS_ON_CALL": "1", "MCP_ECHO_PROGRESS_OVERRIDE": "other-request"},
            clear=False,
        ):
            response = self.client.post(
                "/api/mcp",
                headers=_headers(),
                json=_message(request_id="progress-scope", progress_token="current-request"),
            )
        events = [json.loads(line.removeprefix("data: ")) for line in response.text.splitlines() if line.startswith("data: ")]
        self.assertNotIn("notifications/progress", [event.get("method") for event in events])
        self.assertEqual(events[-1]["result"]["resultType"], "complete")

    def test_request_state_binds_original_call_and_cannot_be_replayed(self) -> None:
        with patch.dict(os.environ, {"MCP_ECHO_SERVER_REQUEST": "1"}, clear=False):
            first = self.client.post("/api/mcp", headers=_headers(), json=_message(request_id="bind-1"))
            state = first.json()["result"]["requestState"]
            wrong_call = _message(request_id="bind-2", request_state=state, input_responses={"srv-req-1": {}})
            wrong_call["params"]["arguments"]["path"] = "public/other.md"
            rejected = self.client.post("/api/mcp", headers=_headers(), json=wrong_call)
            self.assertEqual(rejected.status_code, 200)
            self.assertEqual(rejected.json()["error"]["code"], -32602)
            self.assertEqual(rejected.json()["error"]["data"]["zhiAnSentinel"]["resultAuditId"], "")

            resumed = self.client.post(
                "/api/mcp",
                headers=_headers(),
                json=_message(request_id="bind-3", request_state=state, input_responses={"srv-req-1": {}}),
            )
            self.assertEqual(resumed.status_code, 200)
            self.assertEqual(resumed.json()["result"]["resultType"], "complete")
            replay = self.client.post(
                "/api/mcp",
                headers=_headers(),
                json=_message(request_id="bind-4", request_state=state, input_responses={"srv-req-1": {}}),
            )
            self.assertEqual(replay.status_code, 200)
            self.assertEqual(replay.json()["error"]["code"], -32602)

    def test_invalid_input_response_does_not_consume_a_valid_retry_state(self) -> None:
        with patch.dict(os.environ, {"MCP_ECHO_SERVER_REQUEST": "1"}, clear=False):
            first = self.client.post("/api/mcp", headers=_headers(), json=_message(request_id="validate-1"))
            state = first.json()["result"]["requestState"]
            invalid = self.client.post(
                "/api/mcp",
                headers=_headers(),
                json=_message(request_id="validate-2", request_state=state, input_responses={"srv-req-1": "bad"}),
            )
            self.assertEqual(invalid.status_code, 400)
            self.assertEqual(invalid.json()["error"]["code"], -32602)
            valid = self.client.post(
                "/api/mcp",
                headers=_headers(),
                json=_message(request_id="validate-3", request_state=state, input_responses={"srv-req-1": {}}),
            )
            self.assertEqual(valid.status_code, 200)
            self.assertEqual(valid.json()["result"]["resultType"], "complete")

    def test_invalid_stream_retry_does_not_cancel_pending_execution(self) -> None:
        """A rejected SSE retry must leave the MRTR hand-off resumable."""

        with patch.dict(os.environ, {"MCP_ECHO_SERVER_REQUEST": "1"}, clear=False):
            first = self.client.post(
                "/api/mcp",
                headers=_headers(),
                json=_message(request_id="validate-stream-1", progress_token="validate-stream-1"),
            )
            first_events = [
                json.loads(line.removeprefix("data: "))
                for line in first.text.splitlines()
                if line.startswith("data: ")
            ]
            first_result = first_events[-1]["result"]
            self.assertEqual(first_result["resultType"], "input_required")

            invalid = self.client.post(
                "/api/mcp",
                headers=_headers(),
                json=_message(
                    request_id="validate-stream-2",
                    progress_token="validate-stream-2",
                    request_state=first_result["requestState"],
                    input_responses={"wrong-key": {}},
                ),
            )
            invalid_events = [
                json.loads(line.removeprefix("data: "))
                for line in invalid.text.splitlines()
                if line.startswith("data: ")
            ]
            self.assertEqual(invalid.status_code, 200)
            self.assertEqual(invalid_events[-1]["error"]["code"], -32602)

            valid = self.client.post(
                "/api/mcp",
                headers=_headers(),
                json=_message(
                    request_id="validate-stream-3",
                    progress_token="validate-stream-3",
                    request_state=first_result["requestState"],
                    input_responses={"srv-req-1": {}},
                ),
            )
            valid_events = [
                json.loads(line.removeprefix("data: "))
                for line in valid.text.splitlines()
                if line.startswith("data: ")
            ]
            self.assertEqual(valid_events[-1]["result"]["resultType"], "complete")

    def test_poisoned_upstream_input_request_is_not_returned_to_client(self) -> None:
        with patch.dict(
            os.environ,
            {"MCP_ECHO_SERVER_REQUEST": "1", "MCP_ECHO_POISON_SERVER_REQUEST": "1"},
            clear=False,
        ):
            response = self.client.post("/api/mcp", headers=_headers(), json=_message(request_id="poison-input"))
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["error"]["code"], -32603)
        self.assertNotIn("collector.example", response.text)

    def test_context_request_uses_the_same_mrtr_bridge(self) -> None:
        with patch.dict(os.environ, {"MCP_ECHO_SERVER_REQUEST_ON_CONTEXT": "1"}, clear=False):
            listed = self.client.post(
                "/api/mcp",
                headers=_headers("resources/list", ""),
                json=_context_message(method="resources/list", request_id="context-list", params={}),
            )
            self.assertEqual(listed.status_code, 200)
            uri = listed.json()["result"]["resources"][0]["uri"]
            first = self.client.post(
                "/api/mcp",
                headers=_headers("resources/read", uri),
                json=_context_message(method="resources/read", request_id="context-read-1", params={"uri": uri}),
            )
            self.assertEqual(first.status_code, 200)
            result = first.json()["result"]
            self.assertEqual(result["resultType"], "input_required")
            self.assertIn("srv-context-1", result["inputRequests"])
            resumed = self.client.post(
                "/api/mcp",
                headers=_headers("resources/read", uri),
                json=_context_message(
                    method="resources/read",
                    request_id="context-read-2",
                    params={"uri": uri},
                    input_responses={"srv-context-1": {"action": "accept", "content": {}}},
                    request_state=result["requestState"],
                ),
            )
            self.assertEqual(resumed.status_code, 200)
            self.assertEqual(resumed.json()["result"]["resultType"], "complete")


class RequestScopedLogCorrelationTest(unittest.TestCase):
    def test_cancellation_during_server_request_handler_sends_cancelled_notification(self) -> None:
        upstream = StdioMcpUpstream(["fixture"], resource_limits_enabled=False)
        upstream._server_request_events[1] = deque(
            [{"jsonrpc": "2.0", "id": "srv-1", "method": "sampling/createMessage", "params": {}}]
        )
        cancelled = threading.Event()
        send_cancelled = Mock()
        upstream._send_cancelled = send_cancelled  # type: ignore[method-assign]

        def handler(_: dict[str, Any]) -> None:
            cancelled.set()
            return None

        with self.assertRaisesRegex(StdioUpstreamError, "已取消"):
            upstream._wait_response(1, 1.0, server_request_handler=handler, cancel_event=cancelled)
        send_cancelled.assert_called_once_with(1)

    def test_ambiguous_legacy_log_is_never_routed_across_concurrent_requests(self) -> None:
        upstream = StdioMcpUpstream(["fixture"], resource_limits_enabled=False)
        received: list[str] = []
        upstream._inflight_capture[1] = False
        upstream._inflight_capture[2] = False
        upstream._notification_sinks[1] = (lambda _: received.append("one"), None, "debug")
        upstream._notification_sinks[2] = (lambda _: received.append("two"), None, "debug")
        sink = upstream._request_notification_sink(
            {"jsonrpc": "2.0", "method": "notifications/message", "params": {"level": "error", "data": "x"}}
        )
        self.assertIsNone(sink)
        self.assertEqual(received, [])

    def test_duplicate_progress_tokens_are_dropped_instead_of_cross_routed(self) -> None:
        upstream = StdioMcpUpstream(["fixture"], resource_limits_enabled=False)
        upstream._inflight_capture[1] = False
        upstream._inflight_capture[2] = False
        upstream._notification_sinks[1] = (lambda _: None, "duplicate-token", None)
        upstream._notification_sinks[2] = (lambda _: None, "duplicate-token", None)
        sink = upstream._request_notification_sink(
            {
                "jsonrpc": "2.0",
                "method": "notifications/progress",
                "params": {"progressToken": "duplicate-token", "progress": 1},
            }
        )
        self.assertIsNone(sink)


class MrtrPendingLifecycleTest(unittest.TestCase):
    def test_legacy_adapter_signature_is_selected_before_execution(self) -> None:
        class LegacyUpstream:
            def __init__(self) -> None:
                self.execution_count = 0

            def request(
                self,
                method: str,
                params: dict[str, Any],
                *,
                client_id: Any = None,
            ) -> dict[str, Any]:
                del method, params
                self.execution_count += 1
                return {"jsonrpc": "2.0", "id": client_id, "result": {}}

            def close(self) -> None:
                return None

        upstream = LegacyUpstream()
        gateway = McpGateway(upstream=cast(Any, upstream), audit_enabled=False)
        try:
            exchange = gateway._modern_upstream_exchange(
                gateway.upstream,
                "tools/call",
                {"name": "file.read", "arguments": {}},
                client_id="legacy",
                agent_id="agent-a",
                session_id="session-a",
                request_state=None,
                input_responses=None,
                request_hash="request-hash",
                intent_audit_id="",
                client_capabilities={},
                progress_callback=None,
                cancel_event=None,
            )

            self.assertEqual(exchange["kind"], "complete")
            self.assertEqual(upstream.execution_count, 1)
        finally:
            gateway.close()

    def test_upstream_type_error_after_execution_is_not_retried(self) -> None:
        class TypeErrorAfterExecutionUpstream:
            def __init__(self) -> None:
                self.execution_count = 0

            def request(self, method: str, params: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
                del method, params, kwargs
                self.execution_count += 1
                raise TypeError("simulated adapter failure after side effect")

            def close(self) -> None:
                return None

        upstream = TypeErrorAfterExecutionUpstream()
        gateway = McpGateway(upstream=cast(Any, upstream), audit_enabled=False)
        try:
            exchange = gateway._modern_upstream_exchange(
                gateway.upstream,
                "tools/call",
                {"name": "file.read", "arguments": {}},
                client_id="type-error",
                agent_id="agent-a",
                session_id="session-a",
                request_state=None,
                input_responses=None,
                request_hash="request-hash",
                intent_audit_id="",
                client_capabilities={},
                progress_callback=None,
                cancel_event=None,
            )

            self.assertEqual(exchange["kind"], "error")
            self.assertEqual(upstream.execution_count, 1)
        finally:
            gateway.close()

    def test_timed_out_input_request_releases_pending_slot_for_next_call(self) -> None:
        class TimedOutUpstream:
            def request(self, method: str, params: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
                del method, params
                response = kwargs["server_request_handler"](
                    {
                        "jsonrpc": "2.0",
                        "id": "server-input-1",
                        "method": "elicitation/create",
                        "params": {},
                    }
                )
                if response is None:
                    raise RuntimeError("simulated upstream input timeout")
                return {"jsonrpc": "2.0", "id": kwargs.get("client_id"), "result": response}

            def close(self) -> None:
                return None

        gateway = McpGateway(upstream=cast(Any, TimedOutUpstream()), audit_enabled=False)
        gateway._mrtr_timeout = cast(Any, 0.05)
        try:
            first = gateway._modern_upstream_exchange(
                gateway.upstream,
                "tools/call",
                {"name": "file.read", "arguments": {}},
                client_id="first",
                agent_id="agent-a",
                session_id="session-a",
                request_state=None,
                input_responses=None,
                request_hash="request-hash",
                intent_audit_id="",
                client_capabilities={"elicitation": {}},
                progress_callback=None,
                cancel_event=None,
            )
            self.assertEqual(first["kind"], "input_required")
            end = time.monotonic() + 1.0
            while gateway._mrtr_pending and time.monotonic() < end:
                time.sleep(0.01)
            self.assertFalse(gateway._mrtr_pending)

            second = gateway._modern_upstream_exchange(
                gateway.upstream,
                "tools/call",
                {"name": "file.read", "arguments": {}},
                client_id="second",
                agent_id="agent-a",
                session_id="session-a",
                request_state=None,
                input_responses=None,
                request_hash="request-hash",
                intent_audit_id="",
                client_capabilities={"elicitation": {}},
                progress_callback=None,
                cancel_event=None,
            )
            self.assertEqual(second["kind"], "input_required")
        finally:
            gateway.close()

    def test_stale_worker_does_not_remove_replacement_pending(self) -> None:
        gateway = McpGateway(upstream=Mock(), audit_enabled=False)
        stale = _PendingMcpExecution(pending_id="reused", timeout=1.0)
        replacement = _PendingMcpExecution(pending_id="reused", timeout=1.0)
        try:
            with gateway._mrtr_lock:
                gateway._mrtr_pending[stale.pending_id] = replacement

            gateway._discard_mrtr_pending(stale.pending_id, expected=stale)

            self.assertIs(gateway._mrtr_pending[stale.pending_id], replacement)
            self.assertFalse(replacement.closed)
        finally:
            gateway._discard_mrtr_pending(replacement.pending_id, expected=replacement)
            gateway.close()
