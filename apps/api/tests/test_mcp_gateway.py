"""MCP Gateway 测试：代理转发、强制拦截、端到端链路与监督延迟。"""

from __future__ import annotations

import json
import os
import statistics
import sys
import tempfile
import unittest
from pathlib import Path
from time import perf_counter
from unittest.mock import patch

from apps.api.agent_supervisor.mcp_gateway.gateway import McpGateway, reset_gateway
from apps.api.agent_supervisor.mcp_gateway.interceptor import build_blocked_result, inspect_tools_call
from apps.api.agent_supervisor.mcp_gateway.upstream import StdioMcpUpstream

FIXTURE_SERVER = Path(__file__).resolve().parent / "fixtures" / "mcp_echo_server.py"


def _make_gateway(
    trace_path: str | None = None,
    *,
    guard_enabled: bool = True,
) -> tuple[McpGateway, StdioMcpUpstream]:
    env = {"MCP_ECHO_TRACE": trace_path} if trace_path else None
    upstream = StdioMcpUpstream(
        [sys.executable, "-X", "utf8", str(FIXTURE_SERVER)],
        cwd=str(Path.cwd()),
        extra_env=env,
        timeout=15.0,
    )
    return McpGateway(upstream, guard_enabled=guard_enabled, server_name="test-gateway"), upstream


def _request(method: str, params: dict | None = None, request_id: int | str = 1) -> dict:
    message: dict = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params is not None:
        message["params"] = params
    return message


def _benign_call(path: str = "public/readme.md", request_id: int | str = 2) -> dict:
    return _request(
        "tools/call",
        {"name": "file.read", "arguments": {"path": path}},
        request_id=request_id,
    )


def _handle(gateway: McpGateway, message: dict) -> dict:
    """handle 的非空断言版本：请求类消息必须返回响应。"""
    response = gateway.handle(message)
    assert response is not None, "请求消息必须返回响应"
    return response


class InterceptorTest(unittest.TestCase):
    def test_benign_standard_capability_call_is_allowed(self) -> None:
        decision = inspect_tools_call({"name": "file.read", "arguments": {"path": "public/readme.md"}})
        self.assertIsNone(decision)

    def test_path_traversal_file_read_is_blocked(self) -> None:
        decision = inspect_tools_call(
            {"name": "file.read", "arguments": {"path": "../../etc/passwd"}},
        )
        assert decision is not None
        self.assertIn(decision.decision, {"拒绝", "隔离", "询问"})

    def test_blocked_result_is_error_with_metadata(self) -> None:
        decision = inspect_tools_call(
            {"name": "file.read", "arguments": {"path": "confidential/competition-teams.csv"}},
        )
        assert decision is not None
        result = build_blocked_result(decision)
        self.assertTrue(result["isError"])
        self.assertTrue(result["structuredContent"]["blocked"])
        self.assertEqual(result["structuredContent"]["decision"], decision.decision)
        self.assertTrue(result["content"][0]["text"].startswith("[智安哨]"))

    def test_non_dict_arguments_are_wrapped_not_crashing(self) -> None:
        decision = inspect_tools_call({"name": "file.read", "arguments": ["not", "a", "dict"]})
        # 参数异常包装后仍能评估，不抛异常
        self.assertTrue(decision is None or decision.decision in {"拒绝", "隔离", "询问"})


class GatewayProxyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.gateway, self.upstream = _make_gateway()
        self.addCleanup(self.upstream.close)

    def test_initialize_augments_server_info(self) -> None:
        response = _handle(self.gateway,
            _request("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}}),
        )
        result = response["result"]
        self.assertEqual(result["serverInfo"]["name"], "test-gateway")
        marker = result["zhiAnSentinel"]
        self.assertTrue(marker["gateway"])
        self.assertTrue(marker["guardEnabled"])
        self.assertEqual(marker["upstreamServerInfo"]["name"], "echo-fixture")

    def test_tools_list_is_forwarded(self) -> None:
        response = _handle(self.gateway,_request("tools/list", {}))
        self.assertEqual(response["result"]["tools"][0]["name"], "file.read")

    def test_allowed_tools_call_is_forwarded_and_traced(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            trace = str(Path(tmp) / "trace.jsonl")
            self.upstream.close()
            self.gateway, self.upstream = _make_gateway(trace_path=trace)
            self.addCleanup(self.upstream.close)

            response = _handle(self.gateway,_benign_call("public/readme.md"))
            self.assertFalse(response["result"]["isError"])
            self.assertEqual(
                json.loads(response["result"]["content"][0]["text"]),
                {"path": "public/readme.md"},
            )
            lines = [json.loads(line) for line in Path(trace).read_text(encoding="utf-8").splitlines()]
            self.assertEqual(len(lines), 1)
            self.assertEqual(lines[0]["params"]["name"], "file.read")

    def test_ping_is_answered_locally(self) -> None:
        response = _handle(self.gateway,_request("ping", None))
        self.assertEqual(response["result"], {})

    def test_unknown_method_error_is_forwarded(self) -> None:
        response = _handle(self.gateway,_request("resources/list", {}))
        self.assertEqual(response["error"]["code"], -32601)

    def test_notification_returns_none_without_error(self) -> None:
        self.assertIsNone(self.gateway.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}))

    def test_client_id_is_preserved_in_responses(self) -> None:
        response = _handle(self.gateway,_request("ping", None, request_id="agent-req-42"))
        self.assertEqual(response["id"], "agent-req-42")


class EnforcedBlockingTest(unittest.TestCase):
    """强制阻断验收：拒绝/隔离决策 100% 不到达上游。"""

    def setUp(self) -> None:
        self.trace_file = tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False)
        self.trace_file.close()
        self.addCleanup(os.unlink, self.trace_file.name)
        Path(self.trace_file.name).write_text("", encoding="utf-8")
        self.gateway, self.upstream = _make_gateway(trace_path=self.trace_file.name)
        self.addCleanup(self.upstream.close)

    def _trace_events(self) -> list[dict]:
        text = Path(self.trace_file.name).read_text(encoding="utf-8").strip()
        return [json.loads(line) for line in text.splitlines() if line]

    def test_sensitive_file_read_never_reaches_upstream(self) -> None:
        blocked = _handle(self.gateway,
            _request(
                "tools/call",
                {"name": "file.read", "arguments": {"path": "confidential/competition-teams.csv"}},
                request_id="blocked-1",
            ),
        )
        self.assertTrue(blocked["result"]["isError"])
        self.assertTrue(blocked["result"]["structuredContent"]["blocked"])
        self.assertIn(blocked["result"]["structuredContent"]["decision"], {"拒绝", "隔离", "询问"})
        self.assertEqual(blocked["id"], "blocked-1")
        # 强制式验收：上游 trace 中没有任何该调用
        self.assertEqual(self._trace_events(), [])

    def test_quarantine_code_run_never_reaches_upstream(self) -> None:
        blocked = _handle(self.gateway,
            _request("tools/call", {"name": "code.run", "arguments": {"command": "rm -rf /"}}),
        )
        self.assertTrue(blocked["result"]["isError"])
        self.assertEqual(self._trace_events(), [])

    def test_blocked_then_allowed_keeps_stats_consistent(self) -> None:
        self.gateway.handle(
            _request("tools/call", {"name": "file.read", "arguments": {"path": "confidential/teams.csv"}}),
        )
        self.gateway.handle(_benign_call())
        stats = self.gateway.stats()
        self.assertEqual(stats["tool_calls"], 2)
        self.assertEqual(stats["blocked"], 1)
        self.assertEqual(stats["forwarded_tool_calls"], 1)
        forwarded = self._trace_events()
        self.assertEqual(len(forwarded), 1)
        self.assertEqual(forwarded[0]["params"]["name"], "file.read")

    def test_guard_disabled_gateway_forwards_everything(self) -> None:
        self.upstream.close()
        self.gateway, self.upstream = _make_gateway(trace_path=self.trace_file.name, guard_enabled=False)
        self.addCleanup(self.upstream.close)
        response = _handle(self.gateway,
            _request("tools/call", {"name": "file.read", "arguments": {"path": "public/notes.md"}}),
        )
        self.assertFalse(response["result"]["isError"])


class GatewayHttpEndpointTest(unittest.TestCase):
    def setUp(self) -> None:
        from fastapi.testclient import TestClient

        from apps.api.agent_supervisor.main import app

        self.client = TestClient(app)

    def test_mcp_returns_503_when_gateway_disabled(self) -> None:
        env = {"AGENT_SUPERVISOR_AUTH_DISABLED": "true"}
        with patch.dict(os.environ, env, clear=False):
            os.environ.pop("MCP_GATEWAY_UPSTREAM_COMMAND", None)
            reset_gateway()
            response = self.client.post("/api/mcp", json=_request("ping", None))
        # 未启用时必须显式拒绝而不是静默转发
        self.assertEqual(response.status_code, 503)

    def test_mcp_info_reports_disabled_without_config(self) -> None:
        env = {"AGENT_SUPERVISOR_AUTH_DISABLED": "true"}
        with patch.dict(os.environ, env, clear=False):
            os.environ.pop("MCP_GATEWAY_UPSTREAM_COMMAND", None)
            reset_gateway()
            info = self.client.get("/api/mcp/info")
        self.assertEqual(info.status_code, 200)
        self.assertFalse(info.json()["enabled"])


class SupervisionLatencyTest(unittest.TestCase):
    """M-04 验收：单次监督决策开销 p95 < 10ms。"""

    def test_interceptor_overhead_p95_under_10ms(self) -> None:
        params = {"name": "file.read", "arguments": {"path": "public/readme.md"}}
        durations: list[float] = []
        for _ in range(300):
            start = perf_counter()
            inspect_tools_call(params)
            durations.append((perf_counter() - start) * 1000)
        durations.sort()
        p50 = durations[len(durations) // 2]
        p95 = durations[int(len(durations) * 0.95)]
        report = {
            "module": "mcp_gateway",
            "metric": "supervision_overhead_ms",
            "iterations": len(durations),
            "p50_ms": round(p50, 3),
            "p95_ms": round(p95, 3),
            "max_ms": round(durations[-1], 3),
            "mean_ms": round(statistics.mean(durations), 3),
            "acceptance_p95_ms": 10,
            "passed": p95 < 10,
        }
        report_path = Path("apps/api/sandbox/reports") / "mcp_gateway_latency_report.json"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(
            json.dumps({"generated_at": _now_iso(), **report}, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        self.assertLess(p95, 10, f"监督开销 p95={p95:.2f}ms 超过 10ms 验收线")


def _now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    unittest.main()
