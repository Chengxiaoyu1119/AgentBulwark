"""MCP Gateway 核心：JSON-RPC 方法路由 + 强制拦截 + 多上游转发 + 审计落库。"""

from __future__ import annotations

import hashlib
import json
import re
import threading
from collections import OrderedDict
from copy import deepcopy
from time import perf_counter
from typing import Any
from uuid import uuid4

from apps.api.agent_supervisor.domains.governance.skill_scanner import POLICY_ID as SKILL_SCAN_POLICY_ID
from apps.api.agent_supervisor.domains.governance.skill_scanner import (
    context_scan_enabled,
    project_mcp_context_response,
    scan_mcp_context_response,
    scan_text,
    skill_scan_enabled,
)
from apps.api.agent_supervisor.domains.governance.supervisor import GuardDecision
from apps.api.agent_supervisor.domains.governance.tool_contract import (
    get_agent_api_allowlist,
    normalize_tool_call,
    resolve_public_endpoint,
)
from apps.api.agent_supervisor.domains.governance.tool_registry import resolve_tool_call
from apps.api.agent_supervisor.mcp_gateway.audit import audit_backend_available, record_gateway_tool_call
from apps.api.agent_supervisor.mcp_gateway.config import gateway_max_message_bytes, gateway_network_mode
from apps.api.agent_supervisor.mcp_gateway.interceptor import (
    BLOCKED_DECISIONS,
    build_blocked_response,
    evaluate_tools_call,
    validate_tool_arguments,
)
from apps.api.agent_supervisor.mcp_gateway.router import (
    CONTEXT_LIST_METHODS,
    DEFAULT_ROUTE,
    UpstreamRouter,
)
from apps.api.agent_supervisor.mcp_gateway.upstream import StdioMcpUpstream, StdioUpstreamError
from apps.api.agent_supervisor.storage.data import get_policy_settings

GATEWAY_VERSION = "0.2.0"
SAFE_NOTIFICATION_METHODS = frozenset(
    {
        # MCP lifecycle/progress notifications are protocol messages.  Any
        # extension notification is treated as a potential side effect and is
        # dropped unless it is converted to a request with an id.
        "notifications/initialized",
        "notifications/cancelled",
        "notifications/progress",
        "notifications/message",
        "notifications/roots/list_changed",
        "notifications/resources/list_changed",
        "notifications/prompts/list_changed",
        "notifications/tools/list_changed",
    }
)
MCP_SAFE_METHOD_RE = re.compile(r"^[A-Za-z0-9_.:/-]{1,160}$")
MCP_NOTIFICATION_SAFE_TEXT_CHARS = 512


def _normalize_mcp_method(value: Any) -> str:
    method = str(value or "").strip()
    if not MCP_SAFE_METHOD_RE.fullmatch(method):
        raise ValueError("MCP method 长度或格式无效。")
    return method


def _normalize_mcp_client_id(message: dict[str, Any]) -> Any:
    if "id" not in message:
        return None
    value = message.get("id")
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        raise ValueError("MCP JSON-RPC id 必须是字符串、数字或 null。")
    if isinstance(value, str):
        if len(value) > 160 or not MCP_SAFE_METHOD_RE.fullmatch(value):
            raise ValueError("MCP JSON-RPC id 长度或格式无效。")
        return value
    if isinstance(value, float) and (value != value or value in {float("inf"), float("-inf")}):
        raise ValueError("MCP JSON-RPC id 必须是有限数字。")
    if abs(value) > 2**53:
        raise ValueError("MCP JSON-RPC id 超出安全范围。")
    return value


def _safe_upstream_error(value: Any) -> dict[str, str]:
    raw = str(value or "")
    return {
        "error": "MCP 上游请求失败；详细原因仅保留在审计记录中。",
        "error_hash": hashlib.sha256(raw.encode("utf-8")).hexdigest(),
    }


def _safe_upstream_server_info(value: Any) -> dict[str, Any]:
    """Project MCP ``serverInfo`` without reflecting upstream metadata.

    ``initialize.result.serverInfo`` is supplied by the child process and can
    contain arbitrary strings or extension fields.  Returning it under a
    gateway-owned marker would create a model-visible metadata injection
    channel.  Operators still need to correlate the observed implementation,
    so retain presence and bounded hashes rather than the original values.
    """

    if not isinstance(value, dict):
        return {"present": False}
    projected: dict[str, Any] = {"present": True}
    for field in ("name", "version"):
        raw_value = value.get(field)
        if raw_value is None:
            continue
        serialized = str(raw_value)[:512]
        projected[f"{field}_hash"] = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
    projected["extension_fields_stripped"] = any(
        key not in {"name", "version"} for key in value
    )
    return projected


def _normalize_session_id(value: str | None) -> str:
    """Normalize a caller-provided correlation id without accepting header breaks."""
    normalized = str(value or "").strip()
    if not normalized:
        return ""
    if len(normalized) > 160 or not MCP_SAFE_METHOD_RE.fullmatch(normalized):
        raise ValueError("MCP session_id 长度或格式无效。")
    return normalized


def _safe_notification_scalar(value: Any) -> str | int | float | None:
    """Keep protocol identifiers numeric/bounded without reflecting text."""

    if isinstance(value, bool):
        return None
    if isinstance(value, str):
        normalized = value.strip()
        if not normalized or len(normalized) > 160 or not MCP_SAFE_METHOD_RE.fullmatch(normalized):
            return None
        return normalized
    if isinstance(value, int):
        return value if abs(value) <= 2**53 else None
    if isinstance(value, float):
        return value if value == value and value not in {float("inf"), float("-inf")} else None
    return None


def _notification_value_hash(value: Any) -> str:
    """Hash opaque notification data for operators while keeping it out of context."""

    try:
        serialized = json.dumps(value, ensure_ascii=False, default=str, separators=(",", ":"))
    except (TypeError, ValueError, RecursionError):
        serialized = "[mcp-notification-value-serialization-failure]"
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _project_notification(notification: dict[str, Any]) -> dict[str, Any]:
    """Project an upstream notification to a bounded MCP protocol shape.

    Context scanning is a detector and can be disabled for local compatibility;
    it must never control whether arbitrary upstream params are reflected to an
    Agent.  Free-form reason/message/data values therefore remain hash-only in
    both scanner modes, while lifecycle fields retain their protocol meaning.
    """

    method = str(notification.get("method") or "")
    raw_params = notification.get("params")
    params = raw_params if isinstance(raw_params, dict) else {}
    projected_params: dict[str, Any] = {}

    if method == "notifications/cancelled":
        request_id = _safe_notification_scalar(params.get("requestId"))
        if request_id is not None:
            projected_params["requestId"] = request_id
        if "reason" in params:
            projected_params["reason_hash"] = _notification_value_hash(str(params.get("reason"))[:MCP_NOTIFICATION_SAFE_TEXT_CHARS])
    elif method == "notifications/progress":
        progress_token = _safe_notification_scalar(params.get("progressToken"))
        if progress_token is not None:
            projected_params["progressToken"] = progress_token
        for field in ("progress", "total"):
            value = params.get(field)
            if isinstance(value, (int, float)) and not isinstance(value, bool) and value == value:
                if value not in {float("inf"), float("-inf")} and 0 <= value <= 10**12:
                    projected_params[field] = value
        if "message" in params:
            projected_params["message_hash"] = _notification_value_hash(str(params.get("message"))[:MCP_NOTIFICATION_SAFE_TEXT_CHARS])
    elif method == "notifications/message":
        for field in ("level", "logger"):
            value = params.get(field)
            if isinstance(value, str) and value.strip() and len(value.strip()) <= 160:
                projected_params[field] = value.strip()
        if "data" in params:
            projected_params["data_hash"] = _notification_value_hash(params.get("data"))
    # initialized and list-changed notifications intentionally carry no
    # upstream-controlled params across the boundary.

    projected: dict[str, Any] = {
        "jsonrpc": "2.0",
        "method": method,
    }
    if projected_params:
        projected["params"] = projected_params
    projected["zhiAnSentinel"] = {
        "projection": "protocol-only",
        "opaque_fields_stripped": True,
    }
    return projected


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
        allow_side_effect_notifications: bool = False,
        session_isolation: bool = False,
        max_sessions: int = 128,
    ) -> None:
        if router is not None:
            self._router = router
        elif upstream is not None:
            self._router = UpstreamRouter({DEFAULT_ROUTE: upstream})
        else:
            raise ValueError("必须提供 upstream 或 router。")
        self._guard_enabled = guard_enabled
        self._audit_enabled = audit_enabled
        self._allow_side_effect_notifications = allow_side_effect_notifications
        self._server_name = server_name
        self._session_isolation = bool(session_isolation)
        try:
            bounded_max_sessions = int(max_sessions)
        except (TypeError, ValueError):
            bounded_max_sessions = 128
        self._max_sessions = max(1, min(bounded_max_sessions, 1024))
        self._session_lock = threading.Lock()
        self._session_gateways: OrderedDict[tuple[str, str], McpGateway] = OrderedDict()
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

    @property
    def allow_side_effect_notifications(self) -> bool:
        return self._allow_side_effect_notifications

    def stats(self) -> dict[str, int]:
        with self._stats_lock:
            combined = dict(self._stats)
        if self._session_isolation:
            with self._session_lock:
                children = list(self._session_gateways.values())
            for child in children:
                for key, value in child.stats().items():
                    combined[key] = combined.get(key, 0) + value
        return combined

    def session_pool_status(self) -> dict[str, Any]:
        """Return bounded, secret-free evidence about MCP session isolation."""

        with self._session_lock:
            active_sessions = len(self._session_gateways)
        return {
            "enabled": self._session_isolation,
            "scope": "agent+session" if self._session_isolation else "gateway-shared",
            "active_sessions": active_sessions,
            "max_sessions": self._max_sessions,
            "child_process_per_session": self._session_isolation,
        }

    def route_names(self) -> list[str]:
        return self._router.route_names()

    def notifications(
        self,
        *,
        agent_id: str | None = None,
        session_id: str | None = None,
        include_all: bool = False,
    ) -> list[dict[str, Any]]:
        """读取限定作用域的上游通知并清空队列。

        Session-isolated gateways must never drain every Agent's queue for a
        normal request.  Operators can explicitly request an all-session
        drain through the admin-only management route; regular callers must
        provide the authenticated Agent and session scope.
        """
        if self._session_isolation:
            normalized_agent = str(agent_id or "mcp-gateway").strip() or "mcp-gateway"
            normalized_session = _normalize_session_id(session_id)
            with self._session_lock:
                if include_all:
                    children = list(self._session_gateways.items())
                elif normalized_session:
                    child = self._session_gateways.get((normalized_agent, normalized_session))
                    children = [((normalized_agent, normalized_session), child)] if child is not None else []
                else:
                    children = []
            scoped_drained: list[dict[str, Any]] = []
            for (agent_id, session_id), child in children:
                if child is None:
                    continue
                for item in child.notifications():
                    if isinstance(item, dict):
                        annotated = deepcopy(item)
                        marker = annotated.setdefault("zhiAnSentinel", {})
                        if isinstance(marker, dict):
                            marker["sessionScope"] = {
                                "agent": agent_id,
                                "sessionHash": hashlib.sha256(session_id.encode("utf-8")).hexdigest(),
                            }
                        scoped_drained.append(annotated)
            return scoped_drained
        drained: list[dict[str, Any]] = []
        for route in self._router.route_names():
            for notification in self._router.upstream(route).notifications():
                notification_method = str(notification.get("method") or "") if isinstance(notification, dict) else ""
                # A tool-list change invalidates the last scanned description
                # and schema.  Force a fresh catalog before the next
                # tools/call instead of trusting stale definitions.
                if notification_method == (
                    "notifications/tools/list_changed"
                ):
                    self._router.invalidate_catalog()
                if notification_method not in SAFE_NOTIFICATION_METHODS:
                    try:
                        serialized = json.dumps(notification, ensure_ascii=False, default=str, separators=(",", ":"))
                    except (TypeError, ValueError, RecursionError):
                        serialized = ""
                    drained.append(
                        {
                            "jsonrpc": "2.0",
                            "method": "notifications/zhiAnSentinel_blocked",
                            "params": {
                                "blocked": True,
                                "signals": ["unknown-notification-method"],
                            "context_hash": hashlib.sha256(
                                serialized.encode("utf-8") if serialized else b"mcp-notification-serialization-failure"
                            ).hexdigest(),
                            },
                        }
                    )
                    continue
                try:
                    serialized = json.dumps(notification, ensure_ascii=False, default=str, separators=(",", ":"))
                except (TypeError, ValueError, RecursionError):
                    serialized = ""
                    drained.append(
                        {
                            "jsonrpc": "2.0",
                            "method": "notifications/zhiAnSentinel_blocked",
                            "params": {
                                "blocked": True,
                                "signals": ["context-serialization-failure"],
                                "context_hash": hashlib.sha256(b"mcp-notification-serialization-failure").hexdigest(),
                            },
                        }
                    )
                    continue
                scan = scan_text(serialized, quarantine_on_truncate=True) if context_scan_enabled() else None
                if scan is not None and scan.verdict == "quarantine":
                    # Preserve only a bounded security marker. The original
                    # notification may be a second indirect-injection carrier.
                    drained.append(
                        {
                            "jsonrpc": "2.0",
                            "method": "notifications/zhiAnSentinel_blocked",
                            "params": {
                                "blocked": True,
                                "signals": list(scan.signals),
                                "context_hash": hashlib.sha256(serialized.encode("utf-8")).hexdigest(),
                            },
                        }
                    )
                else:
                    annotated = _project_notification(notification)
                    marker = annotated["zhiAnSentinel"]
                    marker["contextScan"] = {
                        "verdict": scan.verdict if scan is not None else "disabled",
                        "signals": list(scan.signals) if scan is not None else [],
                        "trust": "untrusted-data",
                    }
                    drained.append(annotated)
        return drained

    def tool_inventory(
        self,
        *,
        agent_id: str = "mcp-gateway",
        session_id: str | None = None,
    ) -> dict[str, Any]:
        """Return operator-only tool evidence for one Agent/session scope."""

        if self._session_isolation:
            normalized_session = _normalize_session_id(session_id)
            if not normalized_session:
                return {
                    "schema_version": "mcp-tools-operator-inventory.v1",
                    "agent": agent_id or "mcp-gateway",
                    "session_scope": "missing",
                    "summary": {"catalog_tool_count": 0, "active": False},
                    "visible_tools": [],
                    "filtered_tools": [],
                    "quarantined_tools": [],
                    "projection_blocked_tools": [],
                    "conflicts": [],
                }
            with self._session_lock:
                child = self._session_gateways.get((str(agent_id or "mcp-gateway"), normalized_session))
            if child is None:
                return {
                    "schema_version": "mcp-tools-operator-inventory.v1",
                    "agent": agent_id or "mcp-gateway",
                    "session_scope": "not-active",
                    "session_hash": hashlib.sha256(normalized_session.encode("utf-8")).hexdigest(),
                    "summary": {"catalog_tool_count": 0, "active": False},
                    "visible_tools": [],
                    "filtered_tools": [],
                    "quarantined_tools": [],
                    "projection_blocked_tools": [],
                    "conflicts": [],
                }
            evidence = child.router.tool_inventory(agent_id=agent_id)
            evidence["session_scope"] = "agent+session"
            evidence["session_hash"] = hashlib.sha256(normalized_session.encode("utf-8")).hexdigest()
            evidence.setdefault("summary", {})["active"] = True
            return evidence
        evidence = self._router.tool_inventory(agent_id=agent_id)
        evidence["session_scope"] = "gateway-shared"
        return evidence

    def context_inventory(
        self,
        *,
        agent_id: str = "mcp-gateway",
        session_id: str | None = None,
    ) -> dict[str, Any]:
        """Return operator-only MCP context evidence for one Agent/session.

        Context catalogs are owned by the same isolated child gateway as tool
        catalogs.  The management endpoint must therefore inspect that child
        rather than the parent router, otherwise a session could see another
        Agent's URI/name routes or stale discovery state.
        """

        normalized_agent = str(agent_id or "mcp-gateway").strip() or "mcp-gateway"
        if self._session_isolation:
            normalized_session = _normalize_session_id(session_id)
            if not normalized_session:
                return {
                    "schema_version": "mcp-context-operator-inventory.v1",
                    "agent": normalized_agent,
                    "session_scope": "missing",
                    "summary": {
                        "catalog_entry_count": 0,
                        "visible_context_count": 0,
                        "filtered_context_count": 0,
                        "active": False,
                    },
                    "visible_context": [],
                    "filtered_context": [],
                }
            with self._session_lock:
                child = self._session_gateways.get((normalized_agent, normalized_session))
            if child is None:
                return {
                    "schema_version": "mcp-context-operator-inventory.v1",
                    "agent": normalized_agent,
                    "session_scope": "not-active",
                    "session_hash": hashlib.sha256(normalized_session.encode("utf-8")).hexdigest(),
                    "summary": {
                        "catalog_entry_count": 0,
                        "visible_context_count": 0,
                        "filtered_context_count": 0,
                        "active": False,
                    },
                    "visible_context": [],
                    "filtered_context": [],
                }
            evidence = child.router.context_inventory(agent_id=normalized_agent)
            evidence["session_scope"] = "agent+session"
            evidence["session_hash"] = hashlib.sha256(normalized_session.encode("utf-8")).hexdigest()
            evidence.setdefault("summary", {})["active"] = True
            return evidence
        evidence = self._router.context_inventory(agent_id=normalized_agent)
        evidence["session_scope"] = "gateway-shared"
        return evidence

    def handle(
        self,
        message: dict[str, Any],
        *,
        agent_id: str = "mcp-gateway",
        session_id: str | None = None,
    ) -> dict[str, Any] | None:
        """处理单条 JSON-RPC 消息；通知返回 None，请求返回响应。

        ``agent_id`` comes from the authenticated MCP caller at the HTTP
        boundary.  Keeping it explicit prevents the gateway from evaluating
        every caller as the shared ``mcp-gateway`` identity.
        """
        if not isinstance(message, dict) or not message.get("method"):
            raise ValueError("MCP 消息必须是包含 method 的 JSON-RPC 请求或通知。")
        if message.get("jsonrpc") != "2.0":
            raise ValueError("MCP 消息必须使用 JSON-RPC 2.0。")
        try:
            encoded_message = json.dumps(message, ensure_ascii=False, default=str, separators=(",", ":")).encode(
                "utf-8"
            )
        except (TypeError, ValueError, RecursionError) as exc:
            raise ValueError("MCP 消息无法序列化。") from exc
        if len(encoded_message) > gateway_max_message_bytes():
            raise ValueError(f"MCP 消息超过 {gateway_max_message_bytes()} 字节安全上限。")
        session_id = _normalize_session_id(session_id) or f"mcp-request-{uuid4().hex}"
        if self._session_isolation:
            scoped_gateway = self._session_gateway(agent_id, session_id)
            scoped_response = scoped_gateway.handle(message, agent_id=agent_id, session_id=session_id)
            if isinstance(scoped_response, dict) and isinstance(scoped_response.get("result"), dict):
                marker = scoped_response["result"].setdefault("zhiAnSentinel", {})
                if isinstance(marker, dict):
                    marker["sessionIsolation"] = {
                        "enabled": True,
                        "scope": "agent+session",
                        "sessionHash": hashlib.sha256(session_id.encode("utf-8")).hexdigest(),
                    }
            return scoped_response
        method = _normalize_mcp_method(message["method"])
        params = message.get("params")
        if "params" in message and not isinstance(params, dict):
            raise ValueError("MCP params 必须是对象。")
        if not isinstance(params, dict):
            params = {}
        client_id = _normalize_mcp_client_id(message)

        with self._stats_lock:
            self._stats["messages"] += 1

        is_notification = "id" not in message

        if method == "tools/call":
            # JSON-RPC notifications still have side effects. They must pass
            # through the same guard; omitting an id cannot become a bypass.
            return self._handle_tools_call(
                params,
                client_id,
                agent_id=agent_id,
                session_id=session_id,
                notification=is_notification,
            )

        if is_notification:
            if method not in SAFE_NOTIFICATION_METHODS:
                decision = GuardDecision(
                    decision="拒绝",
                    risk_level="high",
                    policy_id="mcp-notification-contract",
                    reason=f"MCP 通知方法 `{method}` 不在协议通知白名单中，默认不转发无回执副作用消息。",
                    recommendation="将需要执行的动作改为带唯一 id 的 JSON-RPC 请求，以便经过监督和审计。",
                    risk_score=86,
                )
                with self._stats_lock:
                    self._stats["blocked"] += 1
                self._audit(
                    params={"method": method, "params": params},
                    decision=decision,
                    forwarded=False,
                    detection_latency_ms=0.0,
                    agent_id=agent_id or "mcp-gateway",
                    session_id=session_id,
                    client_request_id=None,
                    upstream_route=DEFAULT_ROUTE,
                )
                return None
            # Lifecycle notifications apply to the logical Gateway session, so
            # every configured MCP child must receive them.  A single default
            # child would otherwise leave additional servers uninitialized.
            self._router.notify_all(method, params)
            return None

        if method == "initialize":
            response = self._handle_initialize(params, client_id)
            return self._guard_context_response(
                method,
                response,
                client_id,
                agent_id=agent_id,
                session_id=session_id,
            )

        if method == "ping":
            return {"jsonrpc": "2.0", "id": client_id, "result": {}}

        if method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": client_id,
                "result": self._router.list_tools(agent_id=agent_id),
            }

        if method in CONTEXT_LIST_METHODS:
            response = self._router.list_context(method, params, client_id=client_id, agent_id=agent_id)
            return self._guard_context_response(
                method,
                response,
                client_id,
                agent_id=agent_id,
                session_id=session_id,
            )

        context_access_reason = self._router.context_access_reason(method, params, agent_id or "mcp-gateway")
        if context_access_reason:
            decision = GuardDecision(
                decision="拒绝",
                risk_level="high",
                policy_id="mcp-context-allowlist",
                reason=context_access_reason,
                recommendation="为当前 Agent 登记精确的 MCP resource URI、resource template 或 prompt 名称后重试。",
                risk_score=88,
            )
            with self._stats_lock:
                self._stats["blocked"] += 1
            context_serialized = json.dumps(params, ensure_ascii=False, default=str, separators=(",", ":"))
            audit_ref = self._audit(
                params={
                    "name": f"context:{method}",
                    "arguments": {"context_hash": hashlib.sha256(context_serialized.encode("utf-8")).hexdigest()},
                },
                decision=decision,
                forwarded=False,
                detection_latency_ms=0.0,
                agent_id=agent_id or "mcp-gateway",
                session_id=session_id,
                client_request_id=client_id,
                upstream_route=DEFAULT_ROUTE,
            )
            data: dict[str, Any] = {
                "blocked": True,
                "decision": decision.decision,
                "policy_id": decision.policy_id,
                "risk_score": decision.risk_score,
                "context_access": "denied",
                "context_hash": hashlib.sha256(context_serialized.encode("utf-8")).hexdigest(),
                "forwarded": False,
            }
            if audit_ref:
                data.update({"audit_id": audit_ref["audit_id"], "run_id": audit_ref["run_id"]})
            return {
                "jsonrpc": "2.0",
                "id": client_id,
                "error": {
                    "code": -32003,
                    "message": "MCP Gateway 已拒绝未登记的 Agent 上下文访问。",
                    "data": data,
                },
            }

        routed_context = self._router.route_for_context(method, params)
        if routed_context is None:
            # In a multi-upstream Gateway, forwarding an unknown context request
            # to ``default`` can disclose or mutate the wrong server.  Require a
            # previously discovered URI/name route (or a single configured child)
            # and fail closed otherwise.
            return {
                "jsonrpc": "2.0",
                "id": client_id,
                "error": {
                    "code": -32052,
                    "message": "MCP 上下文请求无法确定唯一上游路由。",
                    "data": {
                        "method": method,
                        "route_required": True,
                        "hint": "先调用对应的 resources/list、resources/templates/list 或 prompts/list。",
                    },
                },
            }
        route_name, upstream = routed_context
        forward_params = {key: value for key, value in params.items() if key != "zhiAnRoute"}
        response = upstream.request(method, forward_params, client_id=client_id)
        return self._guard_context_response(
            method,
            response,
            client_id,
            agent_id=agent_id,
            session_id=session_id,
            upstream_route=route_name,
        )

    def close(self) -> None:
        with self._session_lock:
            children = list(self._session_gateways.values())
            self._session_gateways.clear()
        for child in children:
            child.close()
        self._router.close()

    def _session_gateway(self, agent_id: str, session_id: str) -> "McpGateway":
        """Get or create the isolated Gateway instance for one Agent session.

        The child owns a cloned route set, so its MCP initialize handshake,
        tool/resource catalogs, response buffers and child process are never
        shared with another Agent/session.  The parent only manages the bounded
        pool and aggregates operator-visible statistics.
        """

        key = (str(agent_id or "mcp-gateway"), session_id)
        evicted: McpGateway | None = None
        with self._session_lock:
            existing = self._session_gateways.get(key)
            if existing is not None:
                self._session_gateways.move_to_end(key)
                return existing
            if len(self._session_gateways) >= self._max_sessions:
                _evicted_key, evicted = self._session_gateways.popitem(last=False)
            child = McpGateway(
                router=self._router.clone(),
                guard_enabled=self._guard_enabled,
                server_name=self._server_name,
                audit_enabled=self._audit_enabled,
                allow_side_effect_notifications=self._allow_side_effect_notifications,
                session_isolation=False,
                max_sessions=self._max_sessions,
            )
            self._session_gateways[key] = child
        if evicted is not None:
            evicted.close()
        return child

    # -- 内部 ---------------------------------------------------------------

    def _audit(self, **kwargs: Any) -> dict[str, Any] | None:
        """落库；失败时计数并由调用方执行 fail-closed 处置。"""
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

    def _handle_tools_call(
        self,
        params: dict[str, Any],
        client_id: Any,
        *,
        agent_id: str,
        session_id: str,
        notification: bool = False,
    ) -> dict[str, Any] | None:
        with self._stats_lock:
            self._stats["tool_calls"] += 1

        tool_name = str(params.get("name") or "")
        # A client may call tools/call before tools/list.  Load the catalog
        # before selecting the upstream so first-use calls cannot silently fall
        # back to the default route in a multi-server gateway.
        self._router.ensure_catalog()
        route_name, upstream = self._router.route_for_tool(tool_name)
        decision = None
        detection_latency_ms = 0.0
        response: dict[str, Any] | None = None

        # MCP tool discovery is part of the execution contract.  Falling back
        # to the default upstream for an unadvertised name would let a caller
        # reach a hidden capability or bypass the route/schema that the
        # gateway actually scanned.  Fail closed before any upstream I/O.
        if not self._router.tool_is_registered(tool_name):
            decision = GuardDecision(
                decision="拒绝",
                risk_level="high",
                policy_id="mcp-gateway-contract",
                reason=f"工具 `{tool_name or 'unknown'}` 未出现在当前 MCP tools/list 目录中。",
                recommendation="先通过 tools/list 获取已登记工具，并仅调用其声明的名称。",
                risk_score=86,
            )
            with self._stats_lock:
                self._stats["blocked"] += 1
            audit_ref = self._audit(
                params=params,
                decision=decision,
                forwarded=False,
                detection_latency_ms=0.0,
                agent_id=agent_id or "mcp-gateway",
                session_id=session_id,
                client_request_id=client_id,
                upstream_route=route_name,
            )
            response = build_blocked_response(client_id, decision)
            if audit_ref:
                self._embed_audit_ref(response, audit_ref)
            return None if notification else response

        # ``tools/list`` hides capabilities that are not registered for the
        # authenticated Agent, but discovery is not authorization: a caller can
        # forge a direct JSON-RPC ``tools/call``.  Re-check the same mapping at
        # the side-effect boundary before schema validation or upstream I/O.
        if not self._router.tool_allowed_for_agent(tool_name, agent_id or "mcp-gateway"):
            decision = GuardDecision(
                decision="拒绝",
                risk_level="high",
                policy_id="tool-contract",
                reason=f"工具 `{tool_name or 'unknown'}` 不在当前 Agent 的能力白名单中。",
                recommendation="由管理员登记该 Agent 所需的最小工具能力后重试。",
                risk_score=88,
            )
            with self._stats_lock:
                self._stats["blocked"] += 1
            audit_ref = self._audit(
                params=params,
                decision=decision,
                forwarded=False,
                detection_latency_ms=0.0,
                agent_id=agent_id or "mcp-gateway",
                session_id=session_id,
                client_request_id=client_id,
                upstream_route=route_name,
            )
            response = build_blocked_response(client_id, decision)
            if audit_ref:
                self._embed_audit_ref(response, audit_ref)
            return None if notification else response

        schema_issue = validate_tool_arguments(
            self._router.tool_definition(tool_name),
            params.get("arguments", {}),
        )
        if schema_issue:
            decision = GuardDecision(
                decision="拒绝",
                risk_level="high",
                policy_id="mcp-gateway-contract",
                reason=schema_issue,
                recommendation="按 tools/list 返回的 inputSchema 修正 arguments 后重试。",
                risk_score=80,
            )
            with self._stats_lock:
                self._stats["blocked"] += 1
            audit_ref = self._audit(
                params=params,
                decision=decision,
                forwarded=False,
                detection_latency_ms=0.0,
                agent_id=agent_id or "mcp-gateway",
                session_id=session_id,
                client_request_id=client_id,
                upstream_route=route_name,
            )
            response = build_blocked_response(client_id, decision)
            if audit_ref:
                self._embed_audit_ref(response, audit_ref)
            return None if notification else response

        # Skill 扫描（OWASP A04）：description 投毒达到隔离级的工具禁止调用。
        # 先于常规策略评估，保证命中策略是 tool-description-scan 而非 tool-contract。
        # tools/call 可能先于 tools/list 到达：ensure_catalog 保证扫描结论已就绪。
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
                agent_id=agent_id or "mcp-gateway",
                session_id=session_id,
                client_request_id=client_id,
                upstream_route=route_name,
            )
            response = build_blocked_response(client_id, decision)
            if audit_ref:
                self._embed_audit_ref(response, audit_ref)
            return None if notification else response

        if self._guard_enabled:
            started = perf_counter()
            decision = evaluate_tools_call(params, agent_id=agent_id or "mcp-gateway")
            detection_latency_ms = round((perf_counter() - started) * 1000, 3)
            if decision.decision in BLOCKED_DECISIONS:
                with self._stats_lock:
                    self._stats["blocked"] += 1
                audit_ref = self._audit(
                    params=params,
                    decision=decision,
                    forwarded=False,
                    detection_latency_ms=detection_latency_ms,
                    agent_id=agent_id or "mcp-gateway",
                    session_id=session_id,
                    client_request_id=client_id,
                    upstream_route=route_name,
                )
                response = build_blocked_response(client_id, decision)
                if audit_ref:
                    self._embed_audit_ref(response, audit_ref)
                return None if notification else response

        # A mapped MCP tool can hide an HTTP client behind an arbitrary name.
        # ``decide`` checks the URL shape and Agent host allowlist, but a
        # hostname that passes those checks can still resolve to a private
        # address (or change between the check and the connection).  Resolve
        # the exact target before the call crosses the MCP side-effect boundary
        # and fail closed when the caller has no Agent-bound allowlist.  This
        # keeps MCP's strong enforcement semantics aligned with the generic
        # runtime evaluator and prevents an upstream fetch tool from becoming
        # an SSRF/DNS-rebinding bypass.
        if decision is None or decision.decision == "允许":
            network_decision = self._network_boundary_decision(params, agent_id or "mcp-gateway")
            if network_decision is not None:
                decision = network_decision
                with self._stats_lock:
                    self._stats["blocked"] += 1
                audit_ref = self._audit(
                    params=params,
                    decision=decision,
                    forwarded=False,
                    detection_latency_ms=detection_latency_ms,
                    agent_id=agent_id or "mcp-gateway",
                    session_id=session_id,
                    client_request_id=client_id,
                    upstream_route=route_name,
                )
                response = build_blocked_response(client_id, decision)
                if audit_ref:
                    self._embed_audit_ref(response, audit_ref)
                return None if notification else response

        # A JSON-RPC notification has no response channel.  Forwarding a
        # side-effecting tools/call notification would make the execution
        # boundary observable only after the fact, while an audit write failure
        # would leave no way to report or bind the resulting side effect.  Keep
        # the secure default fail-closed; compatibility callers must explicitly
        # opt in at gateway construction/configuration time.
        if notification and not self._allow_side_effect_notifications:
            decision = GuardDecision(
                decision="拒绝",
                risk_level="high",
                policy_id="mcp-notification-contract",
                reason="MCP tools/call notification 没有响应回执通道，默认不允许其越过执行边界。",
                recommendation="为每次 tools/call 携带唯一 id；如确需兼容通知，显式开启 MCP_GATEWAY_ALLOW_SIDE_EFFECT_NOTIFICATIONS。",
                risk_score=86,
            )
            with self._stats_lock:
                self._stats["blocked"] += 1
            self._audit(
                params=params,
                decision=decision,
                forwarded=False,
                detection_latency_ms=detection_latency_ms,
                agent_id=agent_id or "mcp-gateway",
                session_id=session_id,
                client_request_id=client_id,
                upstream_route=route_name,
            )
            return None

        # An allowed MCP call can mutate files, send data, or invoke another
        # service. Do not cross that side-effect boundary when the local
        # append-only evidence store is unavailable.
        if self._audit_enabled and not audit_backend_available():
            decision = GuardDecision(
                decision="隔离",
                risk_level="critical",
                policy_id="audit-fail-closed",
                reason="审计存储不可写，已阻止 MCP 工具调用越过执行边界。",
                recommendation="恢复审计数据库后重试；不要在无审计状态下放行副作用工具。",
                risk_score=99,
            )
            with self._stats_lock:
                self._stats["blocked"] += 1
            audit_ref = self._audit(
                params=params,
                decision=decision,
                forwarded=False,
                detection_latency_ms=detection_latency_ms,
                agent_id=agent_id or "mcp-gateway",
                session_id=session_id,
                client_request_id=client_id,
                upstream_route=route_name,
            )
            response = build_blocked_response(client_id, decision)
            if audit_ref:
                self._embed_audit_ref(response, audit_ref)
            return None if notification else response

        # Persist an intent before the MCP child can perform a side effect.
        # The later result record is deliberately append-only; if that second
        # write fails, operators still see this pending intent and can
        # reconcile the upstream execution instead of mistaking a missing log
        # for a call that never happened.
        intent_audit_ref: dict[str, Any] | None = None
        if self._audit_enabled and decision is not None:
            intent_audit_ref = self._audit(
                params=params,
                decision=decision,
                forwarded=False,
                detection_latency_ms=detection_latency_ms,
                agent_id=agent_id or "mcp-gateway",
                session_id=session_id,
                client_request_id=client_id,
                upstream_route=route_name,
                execution_phase="intent",
            )
            if intent_audit_ref is None:
                fail_closed = GuardDecision(
                    decision="隔离",
                    risk_level="critical",
                    policy_id="audit-fail-closed",
                    reason="执行意图写入失败，已阻止 MCP 工具调用越过执行边界。",
                    recommendation="恢复审计数据库后重试；不要在无法记录执行意图时放行副作用工具。",
                    risk_score=99,
                )
                with self._stats_lock:
                    self._stats["blocked"] += 1
                response = build_blocked_response(client_id, fail_closed)
                return None if notification else response

        with self._stats_lock:
            self._stats["forwarded_tool_calls"] += 1
        try:
            if notification:
                upstream.notify("tools/call", params)
                response = None
            else:
                response = upstream.request("tools/call", params, client_id=client_id)
        except Exception as exc:  # noqa: BLE001 - 上游异常转成 JSON-RPC 错误并留痕
            if decision is not None:
                self._audit(
                    params=params,
                    decision=decision,
                    forwarded=True,
                    detection_latency_ms=detection_latency_ms,
                    agent_id=agent_id or "mcp-gateway",
                    session_id=session_id,
                    client_request_id=client_id,
                    upstream_route=route_name,
                    upstream_error=_safe_upstream_error(exc),
                    execution_phase="result",
                    intent_audit_id=str((intent_audit_ref or {}).get("audit_id") or ""),
                )
            if notification:
                return None
            return {
                "jsonrpc": "2.0",
                "id": client_id,
                "error": {
                    "code": -32603,
                    "message": "MCP Gateway 上游请求失败；详细原因仅保存在审计记录中。",
                    "data": _safe_upstream_error(exc),
                },
            }

        context_quarantined = False
        raw_upstream_response = response
        context_scan: dict[str, Any] = {}
        if response is not None:
            guarded_response = self._guard_context_response(
                "tools/call",
                response,
                client_id,
                agent_id=agent_id,
                session_id=session_id,
                forwarded=True,
                upstream_route=route_name,
            )
            context_quarantined = self._is_context_quarantine_response(guarded_response)
            if context_quarantined:
                error = guarded_response.get("error")
                data = error.get("data") if isinstance(error, dict) else None
                context_scan = data if isinstance(data, dict) else {}
            response = guarded_response

        if decision is not None:
            raw_result = (
                {}
                if notification
                else raw_upstream_response.get("result")
                if isinstance(raw_upstream_response, dict) and isinstance(raw_upstream_response.get("result"), dict)
                else None
            )
            audit_ref = self._audit(
                params=params,
                decision=decision,
                forwarded=True,
                detection_latency_ms=detection_latency_ms,
                agent_id=agent_id or "mcp-gateway",
                session_id=session_id,
                client_request_id=client_id,
                upstream_route=route_name,
                # JSON-RPC notifications have no response by definition, but
                # a successful notify() still crossed the execution boundary.
                upstream_result=raw_result,
                result_quarantined=context_quarantined,
                result_scan=context_scan,
                execution_phase="result",
                intent_audit_id=str((intent_audit_ref or {}).get("audit_id") or ""),
            )
            if audit_ref and isinstance(response, dict):
                self._embed_audit_ref(response, audit_ref)
            elif self._audit_enabled and not notification:
                # The upstream already ran, so hide its result if the
                # post-execution evidence write failed. The pre-write intent
                # remains pending and carries the reconciliation anchor.
                return {
                    "jsonrpc": "2.0",
                    "id": client_id,
                    "error": {
                        "code": -32050,
                        "message": "MCP 工具已执行，但审计回执写入失败；结果未返回给 Agent。",
                        "data": {
                            "upstream_executed": True,
                            "audit_required": True,
                            "execution_status": "unknown",
                            "execution_outcome": "audit-uncertain",
                            "intent_audit_id": str((intent_audit_ref or {}).get("audit_id") or ""),
                        },
                    },
                }
            if context_quarantined:
                return response
        return response

    @staticmethod
    def _network_boundary_decision(params: dict[str, Any], agent_id: str) -> GuardDecision | None:
        """Validate mapped ``api.call`` destinations before MCP forwarding."""
        tool_name = str(params.get("name") or "")
        try:
            resolution = resolve_tool_call(
                {
                    "tool": tool_name,
                    "arguments": params.get("arguments", {}),
                },
                agent_id=agent_id,
            )
            normalized = normalize_tool_call(resolution.effective_tool_call)
        except ValueError as exc:
            return GuardDecision(
                decision="拒绝",
                risk_level="critical",
                policy_id="tool-contract",
                reason=f"MCP 工具映射校验失败：{exc}",
                recommendation="修正管理员登记的工具能力映射和必填参数后重试。",
                risk_score=95,
            )
        if normalized.get("tool") != "api.call":
            return None
        raw_arguments = normalized.get("arguments")
        arguments: dict[str, Any] = raw_arguments if isinstance(raw_arguments, dict) else {}
        endpoint = str(arguments.get("endpoint") or "")
        if not endpoint.lower().startswith(("http://", "https://")):
            return None
        allowlist = get_agent_api_allowlist(get_policy_settings(), agent_id)
        try:
            resolve_public_endpoint(endpoint, allowed_targets=allowlist)
        except ValueError as exc:
            return GuardDecision(
                decision="拒绝",
                risk_level="critical",
                policy_id="network-boundary",
                reason=f"MCP 网络目标解析未通过：{exc}",
                recommendation="仅允许当前 Agent 白名单中的 HTTPS 公网目标，并复用本次解析地址执行。",
                risk_score=95,
                risk_factors=["MCP api.call network boundary"],
            )
        if gateway_network_mode() != "allow-unpinned":
            return GuardDecision(
                decision="拒绝",
                risk_level="critical",
                policy_id="network-boundary",
                reason=(
                    "MCP 上游是独立 stdio 进程，网关虽已完成公网解析，"
                    "但当前没有网关自有 HTTP 执行器把连接绑定到该解析地址；"
                    "为避免 DNS 重绑定，绝对网络目标默认不转发。"
                ),
                recommendation=(
                    "把网络调用改为网关托管的固定执行器；临时兼容旧上游时显式设置 "
                    "MCP_GATEWAY_NETWORK_MODE=allow-unpinned，并接受降级审计语义。"
                ),
                risk_score=96,
                risk_factors=["MCP network target is not address-pinned"],
            )
        return None

    @staticmethod
    def _embed_audit_ref(response: dict[str, Any], audit_ref: dict[str, Any]) -> None:
        container = response.get("result")
        if not isinstance(container, dict):
            error = response.get("error")
            container = error.get("data") if isinstance(error, dict) else None
        if not isinstance(container, dict):
            return
        existing_audit_id = str(container.get("audit_id") or "")
        marker = container.setdefault("zhiAnSentinel", {})
        if not isinstance(marker, dict):
            marker = {}
            container["zhiAnSentinel"] = marker
        if existing_audit_id and existing_audit_id != str(audit_ref.get("audit_id") or ""):
            marker["context_audit_id"] = existing_audit_id
        marker.update(
            {
                "audit_id": audit_ref["audit_id"],
                "run_id": audit_ref["run_id"],
            }
        )
        intent_id = str(audit_ref.get("intent_audit_id") or "")
        if intent_id:
            marker["intent_audit_id"] = intent_id
        execution_outcome = str(audit_ref.get("execution_outcome") or "").strip()
        if execution_outcome:
            marker["execution_outcome"] = execution_outcome

    def _handle_initialize(self, params: dict[str, Any], client_id: Any) -> dict[str, Any]:
        # A logical Gateway session fronts every configured MCP child.  Sending
        # ``initialize`` only to ``default`` leaves additional servers
        # uninitialized even though their tools are later aggregated and
        # callable.  Initialize all children, keep the default response as the
        # public server identity when available, and expose partial failures as
        # evidence instead of silently pretending the whole fleet is ready.
        route_names = list(self._router.route_names())
        route_names.sort(key=lambda route: 0 if route == DEFAULT_ROUTE else 1)
        initialized_routes: list[str] = []
        failures: list[dict[str, str]] = []
        selected_response: dict[str, Any] | None = None
        for route in route_names:
            try:
                candidate = self._router.upstream(route).request("initialize", params, client_id=client_id)
            except (StdioUpstreamError, OSError, TimeoutError) as exc:
                error = _safe_upstream_error(exc)
                failures.append({"route": route, **error})
                continue
            if not isinstance(candidate, dict):
                failures.append({"route": route, "error": "initialize 响应不是 JSON-RPC 对象"})
                continue
            if isinstance(candidate.get("error"), dict):
                failures.append(
                    {
                        "route": route,
                        **_safe_upstream_error(candidate["error"].get("message") or "upstream initialize error"),
                    }
                )
                continue
            initialized_routes.append(route)
            if selected_response is None or route == DEFAULT_ROUTE:
                selected_response = candidate
        if selected_response is None:
            raise StdioUpstreamError("MCP 上游 initialize 全部失败；详细原因仅保存在审计记录中。")
        response = selected_response
        result = response.get("result")
        if isinstance(result, dict):
            upstream_info = _safe_upstream_server_info(result.get("serverInfo"))
            result["serverInfo"] = {"name": self._server_name, "version": GATEWAY_VERSION}
            result["zhiAnSentinel"] = {
                "gateway": True,
                "guardEnabled": self._guard_enabled,
                "schema_version": "mcp-initialize-context.v2",
                "route_count": len(route_names),
                "initialized_route_count": len(initialized_routes),
                "failed_route_count": len(failures),
                "initialization_status": "partial" if failures else "ready",
                "upstreamServerInfo": upstream_info,
            }
        return response

    def _guard_context_response(
        self,
        method: str,
        response: dict[str, Any],
        client_id: Any,
        *,
        agent_id: str,
        session_id: str = "",
        forwarded: bool = False,
        upstream_route: str = DEFAULT_ROUTE,
    ) -> dict[str, Any]:
        """Keep indirect prompt injections out of model-visible MCP context."""
        if not self._guard_enabled:
            return response
        # Projection is unconditional whenever the gateway is in enforced
        # mode.  Disabling the detector must not re-open the raw extension
        # field channel; it only disables the semantic quarantine decision.
        projection_input = response
        # Only the gateway-created initialize/list markers are trusted.  An
        # upstream result may use the same extension name to spoof an audit ID
        # or a block decision, so drop it before the generic projection for
        # read/get/completion/tool-result responses.
        if method not in {
            "initialize",
            "resources/list",
            "resources/templates/list",
            "prompts/list",
        } and isinstance(response.get("result"), dict) and "zhiAnSentinel" in response["result"]:
            projection_input = dict(response)
            projection_input["result"] = {
                key: value for key, value in response["result"].items() if key != "zhiAnSentinel"
            }
        projected_response, stripped_fields = project_mcp_context_response(
            method,
            projection_input,
            client_id=client_id,
        )
        scan = scan_mcp_context_response(method, response) if context_scan_enabled() else None
        result = projected_response.get("result")
        if scan is None or scan.verdict != "quarantine":
            if isinstance(result, dict):
                marker = result.setdefault("zhiAnSentinel", {})
                if isinstance(marker, dict):
                    marker["contextProjection"] = {
                        "profile": "mcp-standard-context-v1",
                        "strippedFieldCount": len(stripped_fields),
                        "trust": "untrusted-data",
                    }
                    marker["contextScan"] = {
                        "verdict": scan.verdict if scan is not None else "disabled",
                        "signals": list(scan.signals) if scan is not None else [],
                        "trust": "untrusted-data",
                    }
            return projected_response

        # Keep the original response below for the quarantine audit hash and
        # never return it.  The replacement contains only fixed fields and the
        # bounded scan signals, so an upstream extension cannot echo an
        # instruction through the error envelope.
        assert scan is not None
        result = response.get("result")

        context_payload: dict[str, Any] = (
            {"result": result} if isinstance(result, (dict, list, str)) else {"error": response.get("error")}
        )
        try:
            serialized = json.dumps(context_payload, ensure_ascii=False, default=str, separators=(",", ":"))
        except (TypeError, ValueError, RecursionError) as exc:
            serialized = f"mcp-context-serialization-failure:{type(exc).__name__}"
            scan.signals = [*scan.signals, "context-serialization-failure"]
        context_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        decision = GuardDecision(
            decision="隔离",
            risk_level="critical",
            policy_id="tool-return-trust",
            reason=f"MCP `{method}` 返回内容命中间接提示注入扫描：{'、'.join(scan.signals)}。",
            recommendation="不要把该响应交给模型；人工复核来源后再重新发布干净内容。",
            risk_score=92,
            risk_factors=[f"MCP context signal: {signal}" for signal in scan.signals],
        )
        audit_ref = self._audit(
            params={"name": method, "arguments": {"context_hash": context_hash, "signals": scan.signals}},
            decision=decision,
            forwarded=forwarded,
            detection_latency_ms=0.0,
            agent_id=agent_id or "mcp-gateway",
            session_id=session_id,
            client_request_id=client_id,
            upstream_route=upstream_route,
            upstream_result=(
                response.get("result")
                if forwarded and isinstance(response.get("result"), dict)
                else {"error": response.get("error")}
                if forwarded and isinstance(response.get("error"), dict)
                else None
            ),
            result_quarantined=forwarded,
            result_scan={"context_hash": context_hash, "signals": list(scan.signals)},
        )
        data: dict[str, Any] = {
            "blocked": True,
            "decision": decision.decision,
            "policy_id": decision.policy_id,
            "risk_score": decision.risk_score,
            "signals": list(scan.signals),
            "context_hash": context_hash,
            "context_scan_blocked": True,
            "forwarded": forwarded,
            "route_resolved": bool(upstream_route),
            # A quarantined tools/call result may already represent an
            # upstream side effect. Keep that fact separate from a
            # pre-execution policy block.
            "execution_outcome": "executed-result-contained" if forwarded else "blocked-before-execution",
            "upstream_execution_confirmed": forwarded,
        }
        if audit_ref:
            data.update({"audit_id": audit_ref["audit_id"], "run_id": audit_ref["run_id"]})
        return {
            "jsonrpc": "2.0",
            "id": client_id,
            "error": {
                "code": -32001,
                "message": "MCP Gateway 已隔离包含可疑指令的上下文响应。",
                "data": data,
            },
        }

    @staticmethod
    def _is_context_quarantine_response(response: dict[str, Any]) -> bool:
        error = response.get("error")
        if not isinstance(error, dict) or error.get("code") != -32001:
            return False
        data = error.get("data")
        return isinstance(data, dict) and data.get("context_scan_blocked") is True


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
            gateway_allow_side_effect_notifications,
            gateway_enabled,
            gateway_guard_enabled,
            gateway_max_message_bytes,
            gateway_max_pending_responses,
            gateway_max_sessions,
            gateway_resource_limits_enabled,
            gateway_routes,
            gateway_server_name,
            gateway_session_isolation,
            gateway_timeout_seconds,
            route_cwds,
            upstream_command,
            upstream_cwd,
        )
        from apps.api.agent_supervisor.mcp_gateway.router import router_from_config
        from apps.api.agent_supervisor.mcp_gateway.upstream import StdioMcpUpstream

        command = upstream_command()
        # Respect the explicit kill switch as well as the presence of a child
        # command.  Previously a configured command could still start the
        # singleton after ``MCP_GATEWAY_ENABLED=false``, leaving status and the
        # HTTP contract inconsistent with the operator's setting.
        if not gateway_enabled() or not command:
            return None
        default = StdioMcpUpstream(
            command,
            cwd=upstream_cwd(),
            timeout=gateway_timeout_seconds(),
            max_message_bytes=gateway_max_message_bytes(),
            max_pending_responses=gateway_max_pending_responses(),
            resource_limits_enabled=gateway_resource_limits_enabled(),
        )
        cwds = route_cwds()
        routes = {
            name: StdioMcpUpstream(
                argv,
                cwd=cwds.get(name) or None,
                timeout=gateway_timeout_seconds(),
                max_message_bytes=gateway_max_message_bytes(),
                max_pending_responses=gateway_max_pending_responses(),
                resource_limits_enabled=gateway_resource_limits_enabled(),
            )
            for name, argv in gateway_routes().items()
        }
        _gateway = McpGateway(
            router=router_from_config(default, routes),
            guard_enabled=gateway_guard_enabled(),
            server_name=gateway_server_name(),
            allow_side_effect_notifications=gateway_allow_side_effect_notifications(),
            session_isolation=gateway_session_isolation(),
            max_sessions=gateway_max_sessions(),
        )
        return _gateway


def reset_gateway() -> None:
    """关闭并清空单例（测试与配置变更时使用）。"""
    global _gateway
    with _gateway_lock:
        if _gateway is not None:
            _gateway.close()
        _gateway = None
