from __future__ import annotations

import asyncio
import json
import os
import queue
import sys
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx
from fastapi.testclient import TestClient

from apps.api.agent_supervisor.main import app
from apps.api.agent_supervisor.mcp_gateway.gateway import get_gateway, reset_gateway
from apps.api.agent_supervisor.mcp_gateway.http_transport import (
    MODERN_PROTOCOL_VERSION,
    McpHttpTransportError,
    build_subscription_acknowledgement,
    project_modern_response,
    project_subscription_notification,
    validate_http_transport_request,
    validate_modern_tool_parameter_headers,
)
from apps.api.agent_supervisor.mcp_gateway.subscriptions import (
    SubscriptionBroker,
    SubscriptionCapacityError,
    reset_subscription_broker,
    stream_modern_subscription,
)

FIXTURE_SERVER = Path("apps/api/tests/fixtures/mcp_echo_server.py").resolve()


def _modern_message(method: str, *, request_id: str = "modern-1", params: dict | None = None) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": method,
        "params": {
            **(params or {}),
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": MODERN_PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientInfo": {"name": "transport-test", "version": "1.0.0"},
                "io.modelcontextprotocol/clientCapabilities": {},
            },
        },
    }


def _modern_headers(method: str, *, name: str = "") -> dict[str, str]:
    headers = {
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": MODERN_PROTOCOL_VERSION,
        "Mcp-Method": method,
        "X-Agent-Session-ID": "modern-http-session",
    }
    if name:
        headers["Mcp-Name"] = name
    return headers


class ModernMcpHttpTransportTest(unittest.TestCase):
    def setUp(self) -> None:
        self.environment = patch.dict(
            os.environ,
            {
                "AGENT_SUPERVISOR_AUTH_DISABLED": "true",
                "MCP_GATEWAY_ENABLED": "true",
                "MCP_GATEWAY_GUARD_ENABLED": "true",
                "MCP_GATEWAY_SESSION_ISOLATION": "true",
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

    def test_server_discover_exposes_dual_era_contract(self) -> None:
        message = _modern_message("server/discover", request_id="discover-1")

        response = self.client.post("/api/mcp", headers=_modern_headers("server/discover"), json=message)

        self.assertEqual(response.status_code, 200)
        result = response.json()["result"]
        self.assertEqual(result["resultType"], "complete")
        self.assertIn(MODERN_PROTOCOL_VERSION, result["supportedVersions"])
        self.assertIn("2025-06-18", result["supportedVersions"])
        self.assertIn("tools", result["capabilities"])
        self.assertEqual(result["cacheScope"], "private")

    def test_gateway_info_reports_modern_transport_without_legacy_get_claim(self) -> None:
        response = self.client.get("/api/mcp/info")

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["transport"], "streamable-http-dual-era")
        self.assertIn(MODERN_PROTOCOL_VERSION, payload["protocol"]["supported_versions"])
        self.assertTrue(payload["protocol"]["modern"]["subscriptions_listen"])
        self.assertFalse(payload["protocol"]["modern"]["standalone_get_stream"])
        self.assertTrue(payload["protocol"]["modern"]["mrtr"]["input_required"])
        self.assertEqual(payload["protocol"]["modern"]["request_logs"]["levels"][0], "debug")
        self.assertEqual(payload["protocol"]["legacy"]["upstream_server_requests"], "converted-to-modern-mrtr")
        self.assertGreaterEqual(payload["max_subscriptions"], 1)

    def test_disconnected_json_request_cancels_its_backend_execution(self) -> None:
        entered = threading.Event()
        cancelled = threading.Event()
        release = threading.Event()

        class DisconnectAwareGateway:
            server_name = "fixture"
            server_version = "1"

            @staticmethod
            def session_pool_status() -> dict[str, bool]:
                return {"enabled": False}

            @staticmethod
            def ensure_modern_bridge(**_kwargs: object) -> None:
                return None

            @staticmethod
            def modern_tool_definition(*_args: object, **_kwargs: object) -> dict:
                return {"name": "file.read", "inputSchema": {"type": "object"}}

            @staticmethod
            def handle(message: dict, **kwargs: object) -> dict | None:
                cancel_event = kwargs.get("cancel_event")
                entered.set()
                while not release.wait(timeout=0.01):
                    if isinstance(cancel_event, threading.Event) and cancel_event.is_set():
                        cancelled.set()
                        return None
                return {"jsonrpc": "2.0", "id": message.get("id"), "result": {}}

        async def exercise() -> bool:
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
                with patch(
                    "apps.api.agent_supervisor.routers.mcp._required_gateway",
                    return_value=DisconnectAwareGateway(),
                ):
                    task = asyncio.create_task(
                        client.post(
                            "/api/mcp",
                            headers=_modern_headers("tools/call", name="file.read"),
                            json=_modern_message(
                                "tools/call",
                                params={"name": "file.read", "arguments": {"path": "public/readme.md"}},
                            ),
                        )
                    )
                    self.assertTrue(await asyncio.to_thread(entered.wait, 1))
                    task.cancel()
                    await asyncio.sleep(0.2)
                    observed = cancelled.is_set()
                    release.set()
                    try:
                        await asyncio.wait_for(task, timeout=1)
                    except asyncio.CancelledError:
                        pass
                    return observed

        self.assertTrue(asyncio.run(exercise()))

    def test_modern_request_rejects_missing_method_header(self) -> None:
        message = _modern_message("server/discover")
        headers = _modern_headers("server/discover")
        headers.pop("Mcp-Method")

        response = self.client.post("/api/mcp", headers=headers, json=message)

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error"]["code"], -32020)

    def test_modern_request_rejects_missing_required_accept_types(self) -> None:
        message = _modern_message("server/discover")
        headers = _modern_headers("server/discover")
        headers["Accept"] = "application/json"

        response = self.client.post("/api/mcp", headers=headers, json=message)

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error"]["code"], -32020)

    def test_modern_request_rejects_jsonrpc_notification_shape(self) -> None:
        message = _modern_message("tools/call", params={"name": "file.read", "arguments": {"path": "public/readme.md"}})
        message.pop("id")

        response = self.client.post(
            "/api/mcp",
            headers=_modern_headers("tools/call", name="file.read"),
            json=message,
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error"]["code"], -32600)

    def test_modern_session_isolation_requires_application_session_header(self) -> None:
        message = _modern_message("tools/list", request_id="missing-session")
        headers = _modern_headers("tools/list")
        headers.pop("X-Agent-Session-ID")

        response = self.client.post("/api/mcp", headers=headers, json=message)

        self.assertEqual(response.status_code, 400)
        self.assertIn("X-Agent-Session-ID", response.json()["detail"])

    def test_modern_request_accepts_standard_session_header_alias(self) -> None:
        message = _modern_message("tools/list", request_id="standard-session")
        headers = _modern_headers("tools/list")
        headers.pop("X-Agent-Session-ID")
        headers["Mcp-Session-Id"] = "modern-standard-session"

        response = self.client.post("/api/mcp", headers=headers, json=message)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["result"]["resultType"], "complete")

    def test_modern_request_rejects_invalid_jsonrpc_before_discover_dispatch(self) -> None:
        message = _modern_message("server/discover")
        message["jsonrpc"] = "1.0"

        response = self.client.post("/api/mcp", headers=_modern_headers("server/discover"), json=message)

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error"]["code"], -32600)

    def test_unknown_modern_method_uses_method_not_found_http_status(self) -> None:
        message = _modern_message("unknown/operation", request_id="unknown-modern")

        response = self.client.post("/api/mcp", headers=_modern_headers("unknown/operation"), json=message)

        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json()["error"]["code"], -32601)

    def test_unknown_protocol_version_returns_negotiation_error(self) -> None:
        message = _modern_message("server/discover")
        message["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"] = "2099-01-01"
        headers = _modern_headers("server/discover")
        headers["MCP-Protocol-Version"] = "2099-01-01"

        response = self.client.post("/api/mcp", headers=headers, json=message)

        self.assertEqual(response.status_code, 400)
        error = response.json()["error"]
        self.assertEqual(error["code"], -32022)
        self.assertEqual(error["data"]["requested"], "2099-01-01")
        self.assertIn(MODERN_PROTOCOL_VERSION, error["data"]["supported"])

    def test_modern_request_accepts_optional_client_info(self) -> None:
        message = _modern_message("server/discover")
        message["params"]["_meta"].pop("io.modelcontextprotocol/clientInfo")

        response = self.client.post("/api/mcp", headers=_modern_headers("server/discover"), json=message)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["result"]["resultType"], "complete")

    def test_legacy_request_can_carry_non_protocol_metadata(self) -> None:
        message = {
            "jsonrpc": "2.0",
            "id": "legacy-meta",
            "method": "tools/list",
            "params": {"_meta": {"progressToken": "legacy-progress"}},
        }
        response = self.client.post(
            "/api/mcp",
            headers={
                "Accept": "application/json",
                "MCP-Protocol-Version": "2025-06-18",
                "X-Agent-Session-ID": "legacy-meta-session",
            },
            json=message,
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["result"]["tools"])

    def test_legacy_initialize_returns_standard_session_and_reuses_child(self) -> None:
        """A headerless legacy handshake must remain addressable by MCP's header."""

        initialize = {
            "jsonrpc": "2.0",
            "id": "legacy-init-session",
            "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {}},
        }
        first = self.client.post(
            "/api/mcp",
            headers={"Accept": "application/json"},
            json=initialize,
        )

        self.assertEqual(first.status_code, 200)
        session_id = first.headers.get("Mcp-Session-Id")
        self.assertIsNotNone(session_id)
        assert session_id is not None
        self.assertRegex(session_id, r"^[A-Za-z0-9_.:/-]{1,160}$")

        follow_up = self.client.post(
            "/api/mcp",
            headers={"Accept": "application/json", "Mcp-Session-Id": session_id},
            json={"jsonrpc": "2.0", "id": "legacy-list-session", "method": "tools/list", "params": {}},
        )
        self.assertEqual(follow_up.status_code, 200)

        gateway = get_gateway()
        assert gateway is not None
        self.assertEqual(gateway.session_pool_status()["active_sessions"], 1)
        with gateway._session_lock:
            keys = list(gateway._session_gateways)
        self.assertEqual(len(keys), 1)
        self.assertEqual(keys[0][1], session_id)

    def test_session_header_alias_conflict_is_rejected_before_dispatch(self) -> None:
        response = self.client.post(
            "/api/mcp",
            headers={
                "Accept": "application/json",
                "X-Agent-Session-ID": "application-session",
                "Mcp-Session-Id": "protocol-session",
            },
            json={"jsonrpc": "2.0", "id": "conflict", "method": "ping", "params": {}},
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("不一致", response.json()["detail"])

    def test_modern_request_rejects_untrusted_origin(self) -> None:
        message = _modern_message("server/discover")
        headers = {**_modern_headers("server/discover"), "Origin": "https://attacker.example"}

        response = self.client.post("/api/mcp", headers=headers, json=message)

        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["error"]["code"], -32600)

    def test_empty_legacy_batch_still_validates_origin(self) -> None:
        response = self.client.post(
            "/api/mcp",
            headers={"Origin": "https://attacker.example"},
            json=[],
        )

        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["error"]["data"]["reason"], "origin-not-allowed")

    def test_host_header_cannot_expand_origin_allowlist(self) -> None:
        with patch.dict(
            os.environ,
            {"AGENT_SUPERVISOR_CORS_ORIGINS": "http://127.0.0.1:5178,http://localhost:5178"},
            clear=False,
        ):
            response = self.client.post(
                "/api/mcp",
                headers={"Host": "attacker.example", "Origin": "http://attacker.example"},
                json=[],
            )

        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["error"]["data"]["reason"], "origin-not-allowed")

    def test_modern_tools_list_is_bridged_to_legacy_upstream(self) -> None:
        message = _modern_message("tools/list", request_id="tools-modern")

        response = self.client.post("/api/mcp", headers=_modern_headers("tools/list"), json=message)

        self.assertEqual(response.status_code, 200)
        result = response.json()["result"]
        self.assertEqual(result["resultType"], "complete")
        self.assertEqual(result["cacheScope"], "private")
        self.assertTrue(result["tools"])
        self.assertEqual(result["tools"][0]["name"], "file.read")

    def test_modern_tools_call_keeps_enforcement_and_audit_metadata(self) -> None:
        message = _modern_message(
            "tools/call",
            request_id="tool-modern",
            params={"name": "file.read", "arguments": {"path": "public/readme.md"}},
        )

        response = self.client.post(
            "/api/mcp",
            headers=_modern_headers("tools/call", name="file.read"),
            json=message,
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["result"]["resultType"], "complete")
        self.assertFalse(payload["result"]["isError"])
        self.assertTrue(payload["result"]["zhiAnSentinel"]["audit_id"])
        self.assertEqual(
            payload["result"]["_meta"]["io.modelcontextprotocol/serverInfo"]["version"],
            "0.2.0",
        )

    def test_modern_tools_call_rejects_mismatched_name_before_dispatch(self) -> None:
        message = _modern_message(
            "tools/call",
            request_id="tool-name-mismatch",
            params={"name": "file.read", "arguments": {"path": "public/readme.md"}},
        )

        response = self.client.post(
            "/api/mcp",
            headers=_modern_headers("tools/call", name="file.write"),
            json=message,
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error"]["code"], -32020)

    def test_subscriptions_listen_returns_request_scoped_sse(self) -> None:
        message = _modern_message(
            "subscriptions/listen",
            request_id="subscription-1",
            params={"notifications": {"toolsListChanged": True}},
        )
        finite_stream = iter(
            [
                "data: "
                + json.dumps(build_subscription_acknowledgement("subscription-1", {"toolsListChanged": True}))
                + "\n\n"
            ]
        )

        with patch(
            "apps.api.agent_supervisor.routers.mcp.stream_modern_subscription",
            return_value=finite_stream,
        ):
            response = self.client.post(
                "/api/mcp",
                headers=_modern_headers("subscriptions/listen"),
                json=message,
            )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.headers["content-type"].startswith("text/event-stream"))
        payload = json.loads(response.text.removeprefix("data: ").strip())
        self.assertEqual(payload["method"], "notifications/subscriptions/acknowledged")
        self.assertEqual(
            payload["params"]["_meta"]["io.modelcontextprotocol/subscriptionId"],
            "subscription-1",
        )

    def test_subscription_capacity_failure_returns_json_before_sse_headers(self) -> None:
        message = _modern_message(
            "subscriptions/listen",
            request_id="subscription-full",
            params={"notifications": {"toolsListChanged": True}},
        )
        with patch(
            "apps.api.agent_supervisor.routers.mcp.stream_modern_subscription",
            side_effect=SubscriptionCapacityError("MCP 活动订阅已达到 1 条上限。"),
        ):
            response = self.client.post(
                "/api/mcp",
                headers=_modern_headers("subscriptions/listen"),
                json=message,
            )

        self.assertEqual(response.status_code, 429)
        self.assertTrue(response.headers["content-type"].startswith("application/json"))
        self.assertIn("订阅已达到", response.json()["detail"])

    def test_legacy_polling_cannot_race_an_active_modern_subscription(self) -> None:
        with patch("apps.api.agent_supervisor.routers.mcp.modern_subscription_active", return_value=True):
            response = self.client.post(
                "/api/mcp/notifications",
                headers={"X-Agent-Session-ID": "modern-http-session"},
            )

        self.assertEqual(response.status_code, 409)
        self.assertIn("不能并发消费", response.json()["detail"])


class ModernSubscriptionProjectionTest(unittest.TestCase):
    def test_notification_filter_is_explicit_and_resource_scoped(self) -> None:
        requested = {
            "toolsListChanged": True,
            "resourceSubscriptions": ["file:///allowed.txt"],
        }
        tool_change = project_subscription_notification(
            {"jsonrpc": "2.0", "method": "notifications/tools/list_changed"},
            requested,
            "sub-1",
        )
        denied_resource = project_subscription_notification(
            {
                "jsonrpc": "2.0",
                "method": "notifications/resources/updated",
                "params": {"uri": "file:///secret.txt"},
            },
            requested,
            "sub-1",
        )
        progress = project_subscription_notification(
            {"jsonrpc": "2.0", "method": "notifications/progress", "params": {"progress": 1}},
            requested,
            "sub-1",
        )

        self.assertIsNotNone(tool_change)
        self.assertIsNone(denied_resource)
        self.assertIsNone(progress)
        assert tool_change is not None
        self.assertEqual(
            tool_change["params"]["_meta"]["io.modelcontextprotocol/subscriptionId"],
            "sub-1",
        )

    def test_non_ascii_name_header_accepts_required_base64_sentinel(self) -> None:
        message = _modern_message("resources/read", params={"uri": "file:///项目/配置.json"})
        encoded_name = "=?base64?ZmlsZTovLy/pobnnm64v6YWN572uLmpzb24=?="
        headers = _modern_headers("resources/read", name=encoded_name)

        context = validate_http_transport_request(message, {key.lower(): value for key, value in headers.items()})

        self.assertTrue(context.modern)

    def test_invalid_base64_name_header_fails_closed(self) -> None:
        message = _modern_message("resources/read", params={"uri": "file:///项目/配置.json"})
        headers = _modern_headers("resources/read", name="=?base64?not-valid!?=")

        with self.assertRaises(McpHttpTransportError) as raised:
            validate_http_transport_request(message, {key.lower(): value for key, value in headers.items()})

        self.assertEqual(raised.exception.code, -32020)


class ModernToolParameterHeaderTest(unittest.TestCase):
    def setUp(self) -> None:
        self.definition = {
            "name": "api.call",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "tenant": {"type": "string", "x-mcp-header": "Tenant"},
                    "options": {
                        "type": "object",
                        "properties": {
                            "count": {"type": "integer", "x-mcp-header": "Count"},
                            "dryRun": {"type": "boolean", "x-mcp-header": "Dry-Run"},
                        },
                    },
                },
            },
        }
        self.message = _modern_message(
            "tools/call",
            params={
                "name": "api.call",
                "arguments": {"tenant": "研发组", "options": {"count": 42, "dryRun": True}},
            },
        )

    def test_nested_custom_headers_are_decoded_and_bound_to_arguments(self) -> None:
        headers = {
            "mcp-param-tenant": "=?base64?56CU5Y+R57uE?=",
            "mcp-param-count": "42",
            "mcp-param-dry-run": "true",
        }

        validate_modern_tool_parameter_headers(self.message, headers, self.definition)

    def test_missing_custom_header_fails_closed(self) -> None:
        headers = {
            "mcp-param-tenant": "=?base64?56CU5Y+R57uE?=",
            "mcp-param-count": "42",
        }

        with self.assertRaises(McpHttpTransportError) as raised:
            validate_modern_tool_parameter_headers(self.message, headers, self.definition)

        self.assertEqual(raised.exception.code, -32020)

    def test_invalid_annotation_is_removed_from_modern_tool_catalog(self) -> None:
        response = {
            "jsonrpc": "2.0",
            "id": "list-1",
            "result": {
                "tools": [
                    {
                        "name": "invalid",
                        "inputSchema": {
                            "type": "object",
                            "items": {"type": "string", "x-mcp-header": "Hidden"},
                        },
                    },
                    {"name": "valid", "inputSchema": {"type": "object", "properties": {}}},
                ]
            },
        }

        projected = project_modern_response("tools/list", response)

        assert projected is not None
        self.assertEqual([item["name"] for item in projected["result"]["tools"]], ["valid"])
        self.assertEqual(
            projected["result"]["zhiAnSentinel"]["modernHeaderProjection"]["invalidToolCount"],
            1,
        )


class ModernSubscriptionBrokerTest(unittest.TestCase):
    def test_stream_reserves_capacity_before_returning_sse_iterator(self) -> None:
        class IdleGateway:
            server_name = "idle"
            server_version = "1.0"

            def __init__(self) -> None:
                self.pins = 0

            def notifications(self, **_: object) -> list[dict]:
                return []

            def pin_session(self, **_: object) -> None:
                self.pins += 1

            def unpin_session(self, **_: object) -> None:
                self.pins -= 1

        reset_subscription_broker()
        gateway = IdleGateway()
        with patch.dict(os.environ, {"MCP_GATEWAY_MAX_SUBSCRIPTIONS": "1"}, clear=False):
            stream = stream_modern_subscription(
                gateway,
                agent_id="agent-1",
                session_id="session-1",
                subscription_id="first",
                params={"notifications": {"toolsListChanged": True}},
            )
            try:
                self.assertEqual(gateway.pins, 1)
                self.assertIn("subscriptions/acknowledged", next(stream))
                with self.assertRaises(SubscriptionCapacityError):
                    stream_modern_subscription(
                        gateway,
                        agent_id="agent-2",
                        session_id="session-2",
                        subscription_id="second",
                        params={"notifications": {"toolsListChanged": True}},
                    )
            finally:
                stream.close()
                reset_subscription_broker()
        self.assertEqual(gateway.pins, 0)

    def test_concurrent_subscriptions_receive_only_requested_notifications(self) -> None:
        class FakeGateway:
            def __init__(self) -> None:
                self.lock = threading.Lock()
                self.sent = False

            def notifications(self, **_: object) -> list[dict]:
                with self.lock:
                    if self.sent:
                        return []
                    self.sent = True
                return [
                    {"jsonrpc": "2.0", "method": "notifications/tools/list_changed"},
                    {
                        "jsonrpc": "2.0",
                        "method": "notifications/resources/updated",
                        "params": {"uri": "file:///allowed.txt"},
                    },
                    {"jsonrpc": "2.0", "method": "notifications/progress", "params": {"progress": 1}},
                ]

            def pin_session(self, **_: object) -> None:
                return None

            def unpin_session(self, **_: object) -> None:
                return None

        gateway = FakeGateway()
        broker = SubscriptionBroker()
        tool_subscriber, tool_scope, tool_token = broker.subscribe(
            gateway,
            agent_id="agent-1",
            session_id="session-1",
            subscription_id="tools-sub",
            agreed_filter={"toolsListChanged": True},
        )
        resource_subscriber, resource_scope, resource_token = broker.subscribe(
            gateway,
            agent_id="agent-1",
            session_id="session-1",
            subscription_id="resource-sub",
            agreed_filter={"resourceSubscriptions": ["file:///allowed.txt"]},
        )
        try:
            self.assertTrue(broker.has_active(gateway, agent_id="agent-1", session_id="session-1"))
            tool_message = tool_subscriber.messages.get(timeout=2)
            resource_message = resource_subscriber.messages.get(timeout=2)
            assert tool_message is not None
            assert resource_message is not None
            self.assertEqual(tool_message["method"], "notifications/tools/list_changed")
            self.assertEqual(resource_message["method"], "notifications/resources/updated")
            self.assertEqual(
                tool_message["params"]["_meta"]["io.modelcontextprotocol/subscriptionId"],
                "tools-sub",
            )
            self.assertEqual(
                resource_message["params"]["_meta"]["io.modelcontextprotocol/subscriptionId"],
                "resource-sub",
            )
            with self.assertRaises(queue.Empty):
                tool_subscriber.messages.get(timeout=0.2)
            with self.assertRaises(queue.Empty):
                resource_subscriber.messages.get(timeout=0.2)
        finally:
            broker.unsubscribe(tool_scope, tool_token)
            broker.unsubscribe(resource_scope, resource_token)
            broker.reset()
        self.assertFalse(broker.has_active(gateway, agent_id="agent-1", session_id="session-1"))

    def test_broken_upstream_releases_subscription_scope_and_session_lease(self) -> None:
        class BrokenGateway:
            def __init__(self) -> None:
                self.pins = 0

            def notifications(self, **_: object) -> list[dict]:
                raise RuntimeError("sensitive upstream failure")

            def pin_session(self, **_: object) -> None:
                self.pins += 1

            def unpin_session(self, **_: object) -> None:
                self.pins -= 1

        gateway = BrokenGateway()
        broker = SubscriptionBroker()
        subscriber, scope, token = broker.subscribe(
            gateway,
            agent_id="agent-1",
            session_id="session-1",
            subscription_id="broken-sub",
            agreed_filter={"toolsListChanged": True},
        )
        try:
            self.assertIsNone(subscriber.messages.get(timeout=2))
            self.assertFalse(broker.has_active(gateway, agent_id="agent-1", session_id="session-1"))
            self.assertEqual(gateway.pins, 0)
        finally:
            broker.unsubscribe(scope, token)
            broker.reset()


if __name__ == "__main__":
    unittest.main()
