"""MCP Gateway 核心：JSON-RPC 方法路由 + 强制拦截 + 多上游转发 + 审计落库。"""

from __future__ import annotations

import threading
from time import perf_counter
from typing import Any

from apps.api.agent_supervisor.domains.governance.skill_scanner import POLICY_ID as SKILL_SCAN_POLICY_ID
from apps.api.agent_supervisor.domains.governance.skill_scanner import skill_scan_enabled
from apps.api.agent_supervisor.domains.governance.supervisor import GuardDecision
from apps.api.agent_supervisor.mcp_gateway.audit import record_gateway_tool_call
from apps.api.agent_supervisor.mcp_gateway.interceptor import (
    BLOCKED_DECISIONS,
    build_blocked_response,
    evaluate_tools_call,
)
from apps.api.agent_supervisor.mcp_gateway.router import DEFAULT_ROUTE, UpstreamRouter
from apps.api.agent_supervisor.mcp_gateway.upstream import StdioMcpUpstream

GATEWAY_VERSION = "0.2.0"


class McpGateway:
    """把 Agent 的 MCP 请求转发给真实上游，并强制监督 tools/call。"""

    def __init__(
        self,
        upstream: StdioMcpUpstream | None = None,
        *,
        router: UpstreamRouter | None = None,
        guard_enabled: bool = True,
        server_name: str = "zhiAn-sentinel-mcp-gateway",
        audit_enabled: bool = True,
    ) -> None:
        if router is not None:
            self._router = router
        elif upstream is not None:
            self._router = UpstreamRouter({DEFAULT_ROUTE: upstream})
        else:
            raise ValueError("必须提供 upstream 或 router。")
        self._guard_enabled = guard_enabled
        self._audit_enabled = audit_enabled
        self._server_name = server_name
        self._stats_lock = threading.Lock()
        self._stats = {
            "messages": 0,
            "tool_calls": 0,
            "blocked": 0,
            "forwarded_tool_calls": 0,
            "audit_records": 0,
            "audit_errors": 0,
        }

    # -- 对外接口 -----------------------------------------------------------

    @property
    def upstream(self) -> StdioMcpUpstream:
        return self._router.default

    @property
    def router(self) -> UpstreamRouter:
        return self._router

    @property
    def guard_enabled(self) -> bool:
        return self._guard_enabled

    def stats(self) -> dict[str, int]:
        with self._stats_lock:
            return dict(self._stats)

    def route_names(self) -> list[str]:
        return self._router.route_names()

    def notifications(self) -> list[dict[str, Any]]:
        """读取并清空所有上游路由缓冲的上行通知。"""
        drained: list[dict[str, Any]] = []
        for route in self._router.route_names():
            drained.extend(self._router.upstream(route).notifications())
        return drained

    def handle(self, message: dict[str, Any]) -> dict[str, Any] | None:
        """处理单条 JSON-RPC 消息；通知返回 None，请求返回响应。"""
        if not isinstance(message, dict) or not message.get("method"):
            raise ValueError("MCP 消息必须是包含 method 的 JSON-RPC 请求或通知。")
        method = str(message["method"])
        params = message.get("params")
        if not isinstance(params, dict):
            params = {}
        client_id = message.get("id")

        with self._stats_lock:
            self._stats["messages"] += 1

        is_notification = "id" not in message

        if method == "tools/call" and not is_notification:
            return self._handle_tools_call(params, client_id)

        if is_notification:
            self._router.default.notify(method, params)
            return None

        if method == "initialize":
            return self._handle_initialize(params, client_id)

        if method == "ping":
            return {"jsonrpc": "2.0", "id": client_id, "result": {}}

        if method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": client_id,
                "result": self._router.list_tools(),
            }

        return self._router.default.request(method, params, client_id=client_id)

    def close(self) -> None:
        self._router.close()

    # -- 内部 ---------------------------------------------------------------

    def _audit(self, **kwargs: Any) -> dict[str, Any] | None:
        """落库；失败时计数并继续，保证网关可用性可观测。"""
        if not self._audit_enabled:
            return None
        try:
            record = record_gateway_tool_call(**kwargs)
        except Exception:  # noqa: BLE001 - 审计失败不得中断网关响应
            with self._stats_lock:
                self._stats["audit_errors"] += 1
            return None
        with self._stats_lock:
            self._stats["audit_records"] += 1
        return record

    def _handle_tools_call(self, params: dict[str, Any], client_id: Any) -> dict[str, Any]:
        with self._stats_lock:
            self._stats["tool_calls"] += 1

        tool_name = str(params.get("name") or "")
        route_name, upstream = self._router.route_for_tool(tool_name)
        decision = None
        detection_latency_ms = 0.0

        # Skill 扫描（OWASP A04）：description 投毒达到隔离级的工具禁止调用。
        # 先于常规策略评估，保证命中策略是 tool-description-scan 而非 tool-contract。
        # tools/call 可能先于 tools/list 到达：ensure_catalog 保证扫描结论已就绪。
        if self._guard_enabled and skill_scan_enabled():
            self._router.ensure_catalog()
        if self._guard_enabled and skill_scan_enabled() and self._router.tool_is_quarantined(tool_name):
            verdict = self._router.skill_verdict(tool_name) or {}
            signal_text = "、".join(verdict.get("signals") or [])
            decision = GuardDecision(
                decision="隔离",
                risk_level="critical",
                policy_id=SKILL_SCAN_POLICY_ID,
                reason=f"工具 `{tool_name}` 的描述命中可疑指令：{signal_text}。",
                recommendation="移除该工具或人工复核其 description 后再恢复调用。",
                risk_score=92,
            )
            with self._stats_lock:
                self._stats["blocked"] += 1
            audit_ref = self._audit(
                params=params,
                decision=decision,
                forwarded=False,
                detection_latency_ms=0.0,
                client_request_id=client_id,
                upstream_route=route_name,
            )
            response = build_blocked_response(client_id, decision)
            if audit_ref:
                self._embed_audit_ref(response, audit_ref)
            return response

        if self._guard_enabled:
            started = perf_counter()
            decision = evaluate_tools_call(params)
            detection_latency_ms = round((perf_counter() - started) * 1000, 3)
            if decision.decision in BLOCKED_DECISIONS:
                with self._stats_lock:
                    self._stats["blocked"] += 1
                audit_ref = self._audit(
                    params=params,
                    decision=decision,
                    forwarded=False,
                    detection_latency_ms=detection_latency_ms,
                    client_request_id=client_id,
                    upstream_route=route_name,
                )
                response = build_blocked_response(client_id, decision)
                if audit_ref:
                    self._embed_audit_ref(response, audit_ref)
                return response

        with self._stats_lock:
            self._stats["forwarded_tool_calls"] += 1
        try:
            response = upstream.request("tools/call", params, client_id=client_id)
        except Exception as exc:  # noqa: BLE001 - 上游异常转成 JSON-RPC 错误并留痕
            if decision is not None:
                self._audit(
                    params=params,
                    decision=decision,
                    forwarded=True,
                    detection_latency_ms=detection_latency_ms,
                    client_request_id=client_id,
                    upstream_route=route_name,
                    upstream_error=str(exc),
                )
            return {
                "jsonrpc": "2.0",
                "id": client_id,
                "error": {"code": -32603, "message": f"MCP Gateway 上游错误：{exc}"},
            }

        if decision is not None:
            audit_ref = self._audit(
                params=params,
                decision=decision,
                forwarded=True,
                detection_latency_ms=detection_latency_ms,
                client_request_id=client_id,
                upstream_route=route_name,
                upstream_result=response.get("result") if isinstance(response.get("result"), dict) else None,
            )
            if audit_ref:
                self._embed_audit_ref(response, audit_ref)
        return response

    @staticmethod
    def _embed_audit_ref(response: dict[str, Any], audit_ref: dict[str, Any]) -> None:
        container = response.get("result")
        if isinstance(container, dict):
            container.setdefault("zhiAnSentinel", {}).update(
                {
                    "audit_id": audit_ref["audit_id"],
                    "run_id": audit_ref["run_id"],
                }
            )

    def _handle_initialize(self, params: dict[str, Any], client_id: Any) -> dict[str, Any]:
        response = self._router.default.request("initialize", params, client_id=client_id)
        result = response.get("result")
        if isinstance(result, dict):
            upstream_info = result.get("serverInfo")
            result["serverInfo"] = {"name": self._server_name, "version": GATEWAY_VERSION}
            result["zhiAnSentinel"] = {
                "gateway": True,
                "guardEnabled": self._guard_enabled,
                "routes": self._router.route_names(),
                "upstreamServerInfo": upstream_info,
            }
        return response


# -- 模块级单例（按环境变量懒加载） -----------------------------------------

_gateway_lock = threading.Lock()
_gateway: McpGateway | None = None


def get_gateway() -> McpGateway | None:
    """获取配置驱动的网关单例；未配置上游时返回 None。"""
    global _gateway
    with _gateway_lock:
        if _gateway is not None:
            return _gateway
        from apps.api.agent_supervisor.mcp_gateway.config import (
            gateway_guard_enabled,
            gateway_routes,
            gateway_server_name,
            gateway_timeout_seconds,
            route_cwds,
            upstream_command,
            upstream_cwd,
        )
        from apps.api.agent_supervisor.mcp_gateway.router import router_from_config
        from apps.api.agent_supervisor.mcp_gateway.upstream import StdioMcpUpstream

        command = upstream_command()
        if not command:
            return None
        default = StdioMcpUpstream(command, cwd=upstream_cwd(), timeout=gateway_timeout_seconds())
        cwds = route_cwds()
        routes = {
            name: StdioMcpUpstream(argv, cwd=cwds.get(name) or None, timeout=gateway_timeout_seconds())
            for name, argv in gateway_routes().items()
        }
        _gateway = McpGateway(
            router=router_from_config(default, routes),
            guard_enabled=gateway_guard_enabled(),
            server_name=gateway_server_name(),
        )
        return _gateway


def reset_gateway() -> None:
    """关闭并清空单例（测试与配置变更时使用）。"""
    global _gateway
    with _gateway_lock:
        if _gateway is not None:
            _gateway.close()
        _gateway = None
