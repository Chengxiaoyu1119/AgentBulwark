"""MCP Gateway HTTP 入口：2026 现代请求与 2025 兼容请求。"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import queue
import threading
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, Body, Depends, Header, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse

from apps.api.agent_supervisor.auth import (
    current_agent_identity,
    current_security_role,
    require_any_role,
    require_api_token,
)
from apps.api.agent_supervisor.domains.governance.task_profiles import (
    evaluate_task_scope,
    normalize_task_id,
    resolve_task_profile,
)
from apps.api.agent_supervisor.domains.runtime.mcp_access import mcp_access_capabilities
from apps.api.agent_supervisor.mcp_gateway.config import gateway_max_message_bytes, gateway_max_subscriptions, gateway_mrtr_timeout_seconds
from apps.api.agent_supervisor.mcp_gateway.gateway import _normalize_session_id, _project_notification, get_gateway
from apps.api.agent_supervisor.mcp_gateway.http_transport import (
    LOG_LEVELS,
    MODERN_METHODS,
    MODERN_PROTOCOL_VERSION,
    SUPPORTED_PROTOCOL_VERSIONS,
    HttpTransportContext,
    McpHttpTransportError,
    build_modern_discover_response,
    log_level_allows,
    normalize_subscription_filter,
    project_modern_response,
    validate_http_transport_request,
    validate_mcp_origin,
    validate_modern_tool_parameter_headers,
)
from apps.api.agent_supervisor.mcp_gateway.subscriptions import (
    SubscriptionCapacityError,
    modern_subscription_active,
    stream_modern_subscription,
)
from apps.api.agent_supervisor.mcp_gateway.upstream import StdioUpstreamError

router = APIRouter(dependencies=[Depends(require_api_token)])
MCP_MAX_BATCH_ITEMS = 32


@router.get("/api/mcp/info")
def mcp_gateway_info(role: str = Depends(current_security_role)) -> dict[str, Any]:
    gateway = get_gateway()
    from apps.api.agent_supervisor.mcp_gateway.config import (
        gateway_guard_enabled,
        gateway_max_sessions,
        gateway_network_mode,
        gateway_server_name,
        gateway_session_isolation,
    )

    return {
        "enabled": gateway is not None,
        "server_name": gateway_server_name(),
        "guard_enabled": gateway_guard_enabled() if gateway is not None else False,
        "network_mode": gateway_network_mode(),
        "session_isolation": gateway.session_pool_status() if gateway is not None else {
            "enabled": gateway_session_isolation(),
            "scope": "agent+session" if gateway_session_isolation() else "gateway-shared",
            "active_sessions": 0,
            "max_sessions": gateway_max_sessions(),
            "child_process_per_session": gateway_session_isolation(),
        },
        "routes": gateway.route_names() if gateway is not None and role in {"analyst", "admin"} else [],
        "transport": "streamable-http-dual-era",
        "protocol": {
            "supported_versions": list(SUPPORTED_PROTOCOL_VERSIONS),
            "modern": {
                "version": MODERN_PROTOCOL_VERSION,
                "request_metadata": "protocolVersion+clientCapabilities required; clientInfo optional",
                "server_discover": True,
                "subscriptions_listen": True,
                "standalone_get_stream": False,
                "protocol_sessions": False,
                "ordinary_response": "application/json-or-request-scoped-sse",
                "request_logs": {
                    "opt_in": "io.modelcontextprotocol/logLevel",
                    "levels": list(LOG_LEVELS),
                    "lower_severity_filtered": True,
                },
                "subscription_response": "text/event-stream",
                "mrtr": {
                    "input_required": True,
                    "request_state": "hmac-ttl-single-use",
                    "request_state_secret_configured": bool(
                        os.getenv("MCP_GATEWAY_REQUEST_STATE_SECRET", "").strip()
                        or os.getenv("AGENT_SUPERVISOR_AUDIT_HMAC_KEY", "").strip()
                    ),
                    "request_state_ttl_seconds": gateway_mrtr_timeout_seconds(),
                    "request_state_replay_scope": "process",
                },
            },
            "legacy": {
                "version": "2025-06-18",
                "initialize_bridge": True,
                "operator_notification_polling": True,
                "upstream_server_requests": "converted-to-modern-mrtr",
            },
        },
        "max_subscriptions": gateway_max_subscriptions(),
        "enforcement": "enforced",
        "side_effect_notifications": {
            "allowed": gateway.allow_side_effect_notifications if gateway is not None else False,
            "default": False,
            "reason": "无 id 的 tools/call 没有响应/回执通道，默认不转发。",
        },
    }


@router.post("/api/mcp/notifications")
def mcp_gateway_notifications(
    authenticated_agent_id: str | None = Depends(current_agent_identity),
    role: str = Depends(current_security_role),
    x_agent_session_id: str | None = Header(default=None, alias="X-Agent-Session-ID"),
    mcp_session_id: str | None = Header(default=None, alias="Mcp-Session-Id"),
    all_sessions: bool = Query(default=False),
) -> dict[str, Any]:
    """旧版运维兼容入口：读取并清空指定会话的上游通知。"""
    # Notifications may contain resource updates, tool descriptions or other
    # model-visible context.  They are not a health endpoint; keep them out of
    # observer credentials while allowing analyst/admin operators to inspect
    # and drain the queue.
    require_any_role({"analyst", "admin"}, role)
    gateway = get_gateway()
    if gateway is None:
        raise HTTPException(status_code=503, detail="MCP Gateway 未启用：请配置 MCP_GATEWAY_UPSTREAM_COMMAND。")
    session_id = _resolve_session_headers(x_agent_session_id, mcp_session_id)
    session_status = gateway.session_pool_status()
    if all_sessions:
        require_any_role({"admin"}, role)
    elif session_status.get("enabled") and not session_id:
        raise HTTPException(
            status_code=400,
            detail="Session-isolated MCP Gateway 读取通知必须提供 X-Agent-Session-ID；管理员可显式使用 all_sessions=true。",
        )
    scoped_agent_id = authenticated_agent_id or "mcp-gateway"
    if modern_subscription_active(
        gateway,
        agent_id=None if all_sessions else scoped_agent_id,
        session_id=None if all_sessions else session_id,
    ):
        raise HTTPException(status_code=409, detail="当前会话已有现代 MCP 订阅流，旧版轮询不能并发消费同一通知队列。")
    return {
        "notifications": gateway.notifications(
            agent_id=scoped_agent_id,
            session_id=session_id,
            include_all=all_sessions,
        )
    }


@router.get("/api/mcp/tools/evidence")
def mcp_gateway_tool_evidence(
    authenticated_agent_id: str | None = Depends(current_agent_identity),
    role: str = Depends(current_security_role),
    x_agent_session_id: str | None = Header(default=None, alias="X-Agent-Session-ID"),
    mcp_session_id: str | None = Header(default=None, alias="Mcp-Session-Id"),
    requested_agent_id: str | None = Query(default=None, alias="agent_id"),
) -> dict[str, Any]:
    """Return operator-only MCP capability evidence.

    Tool names, route assignments and scanner signals stay behind this
    authenticated management endpoint; the model-facing ``tools/list`` does
    not carry them.
    """

    require_any_role({"analyst", "admin"}, role)
    gateway = get_gateway()
    if gateway is None:
        raise HTTPException(status_code=503, detail="MCP Gateway 未启用：请配置 MCP_GATEWAY_UPSTREAM_COMMAND。")
    requested = str(requested_agent_id or "").strip()
    if requested and authenticated_agent_id and requested != authenticated_agent_id and role != "admin":
        raise HTTPException(status_code=403, detail="当前身份不能查看其他 Agent 的 MCP 工具证据。")
    if requested and not authenticated_agent_id and role != "admin":
        raise HTTPException(status_code=403, detail="非管理员必须使用已绑定 Agent 身份查看 MCP 工具证据。")
    agent_id = requested or authenticated_agent_id or "mcp-gateway"
    session_id = _resolve_session_headers(x_agent_session_id, mcp_session_id)
    if gateway.session_pool_status().get("enabled") and not session_id:
        raise HTTPException(status_code=400, detail="Session-isolated MCP Gateway 需要 X-Agent-Session-ID。")
    return gateway.tool_inventory(agent_id=agent_id, session_id=session_id)


@router.get("/api/mcp/context/evidence")
def mcp_gateway_context_evidence(
    authenticated_agent_id: str | None = Depends(current_agent_identity),
    role: str = Depends(current_security_role),
    x_agent_session_id: str | None = Header(default=None, alias="X-Agent-Session-ID"),
    mcp_session_id: str | None = Header(default=None, alias="Mcp-Session-Id"),
    requested_agent_id: str | None = Query(default=None, alias="agent_id"),
) -> dict[str, Any]:
    """Return operator-only MCP resource/template/prompt route evidence."""

    require_any_role({"analyst", "admin"}, role)
    gateway = get_gateway()
    if gateway is None:
        raise HTTPException(status_code=503, detail="MCP Gateway 未启用：请配置 MCP_GATEWAY_UPSTREAM_COMMAND。")
    requested = str(requested_agent_id or "").strip()
    if requested and authenticated_agent_id and requested != authenticated_agent_id and role != "admin":
        raise HTTPException(status_code=403, detail="当前身份不能查看其他 Agent 的 MCP 上下文证据。")
    if requested and not authenticated_agent_id and role != "admin":
        raise HTTPException(status_code=403, detail="非管理员必须使用已绑定 Agent 身份查看 MCP 上下文证据。")
    agent_id = requested or authenticated_agent_id or "mcp-gateway"
    session_id = _resolve_session_headers(x_agent_session_id, mcp_session_id)
    if gateway.session_pool_status().get("enabled") and not session_id:
        raise HTTPException(status_code=400, detail="Session-isolated MCP Gateway 需要 X-Agent-Session-ID。")
    return gateway.context_inventory(agent_id=agent_id, session_id=session_id)


@router.post("/api/mcp")
async def mcp_message(
    http_request: Request,
    request: Any = Body(...),
    authenticated_agent_id: str | None = Depends(current_agent_identity),
    role: str = Depends(current_security_role),
    x_agent_session_id: str | None = Header(default=None, alias="X-Agent-Session-ID"),
    mcp_session_id: str | None = Header(default=None, alias="Mcp-Session-Id"),
    x_agent_task_id: str | None = Header(default=None, alias="X-Agent-Task-ID"),
) -> Any:
    # X-Agent-Session-ID is the historical supervisor correlation key while
    # Mcp-Session-Id is the standard MCP protocol key. Resolve both once at the
    # HTTP boundary so a request can never accidentally select two children.
    resolved_session_id = _resolve_session_headers(x_agent_session_id, mcp_session_id)
    try:
        task_id = normalize_task_id(x_agent_task_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    try:
        request_size = len(json.dumps(request, ensure_ascii=False, default=str, separators=(",", ":")).encode("utf-8"))
    except (TypeError, ValueError, RecursionError) as exc:
        raise HTTPException(status_code=400, detail="MCP 请求无法序列化。") from exc
    if request_size > gateway_max_message_bytes():
        raise HTTPException(status_code=413, detail=f"MCP 请求超过 {gateway_max_message_bytes()} 字节安全上限。")
    try:
        validate_mcp_origin(http_request.headers, allowed_origins=_mcp_allowed_origins(http_request))
    except McpHttpTransportError as exc:
        request_id = request.get("id") if isinstance(request, dict) else None
        return _transport_error_response(exc, request_id)

    if isinstance(request, list):
        if not request:
            return Response(status_code=202)
        if len(request) > MCP_MAX_BATCH_ITEMS:
            raise HTTPException(status_code=413, detail=f"MCP 批量请求不能超过 {MCP_MAX_BATCH_ITEMS} 项。")
        transport_contexts: list[HttpTransportContext] = []
        for message in request:
            if not isinstance(message, dict):
                raise HTTPException(status_code=400, detail="MCP 批量消息中的每一项都必须是 JSON-RPC 对象。")
            try:
                transport_contexts.append(
                    validate_http_transport_request(
                        message,
                        http_request.headers,
                        allowed_origins=_mcp_allowed_origins(http_request),
                    )
                )
            except McpHttpTransportError as exc:
                return _transport_error_response(exc, message.get("id"))
        if any(context.modern for context in transport_contexts):
            return _transport_error_response(
                McpHttpTransportError("现代 MCP Streamable HTTP 不接受 JSON-RPC 批量请求。"),
                None,
            )
        for message in request:
            _require_mcp_operation_access(message, role=role, authenticated_agent_id=authenticated_agent_id)
        gateway = _required_gateway()
        batch_has_initialize = any(str(message.get("method") or "").strip() == "initialize" for message in request)
        batch_session_id = resolved_session_id
        if batch_has_initialize and not batch_session_id:
            batch_session_id = _new_legacy_session_id()
        responses = []
        for message in request:
            responses.append(
                await asyncio.to_thread(
                    _handle_one,
                    gateway,
                    message,
                    agent_id=authenticated_agent_id or "mcp-gateway",
                    session_id=batch_session_id,
                    task_id=task_id,
                )
            )
        payload = [item for item in responses if item is not None]
        if not payload:
            return Response(status_code=202)
        return JSONResponse(
            payload,
            headers=_legacy_session_response_headers(batch_session_id if batch_has_initialize else None),
        )

    if not isinstance(request, dict):
        raise HTTPException(status_code=400, detail="MCP 消息必须是 JSON-RPC 对象或数组。")

    try:
        transport_context = validate_http_transport_request(
            request,
            http_request.headers,
            allowed_origins=_mcp_allowed_origins(http_request),
        )
    except McpHttpTransportError as exc:
        return _transport_error_response(exc, request.get("id"))

    if transport_context.modern:
        method = str(request.get("method") or "")
        if method not in MODERN_METHODS:
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "id": request.get("id"),
                    "error": {"code": -32601, "message": f"Method not found: {method}"},
                },
                status_code=404,
            )
    _require_mcp_operation_access(request, role=role, authenticated_agent_id=authenticated_agent_id)
    gateway = _required_gateway()
    method = str(request.get("method") or "").strip()
    session_id: str | None = resolved_session_id
    # Legacy MCP establishes its protocol session at initialize.  When an old
    # client does not send either header, mint one here and return it so every
    # subsequent request can target the same isolated stdio child.
    if not transport_context.modern and method == "initialize" and not session_id:
        session_id = _new_legacy_session_id()
    if transport_context.modern:
        task_binding = resolve_task_profile(authenticated_agent_id or "mcp-gateway", task_id)
        if task_binding.required and not task_binding.valid:
            response = await asyncio.to_thread(
                _handle_one,
                gateway,
                request,
                agent_id=authenticated_agent_id or "mcp-gateway",
                session_id=session_id,
                task_id=task_id,
                modern=True,
                client_capabilities=transport_context.client_capabilities,
            )
            projected = project_modern_response(
                method,
                response,
                server_name=gateway.server_name,
                server_version=gateway.server_version,
            )
            return JSONResponse(projected or {"jsonrpc": "2.0", "id": request.get("id"), "result": {}})
        if method == "tools/call":
            raw_params = request.get("params")
            task_scope = evaluate_task_scope(
                task_binding,
                {
                    "tool": (raw_params or {}).get("name") if isinstance(raw_params, dict) else "",
                    "arguments": (raw_params or {}).get("arguments", {}) if isinstance(raw_params, dict) else {},
                },
                agent_id=authenticated_agent_id or "mcp-gateway",
            )
            if task_binding.required and not task_scope.allowed:
                response = await asyncio.to_thread(
                    _handle_one,
                    gateway,
                    request,
                    agent_id=authenticated_agent_id or "mcp-gateway",
                    session_id=session_id,
                    task_id=task_id,
                    modern=True,
                    client_capabilities=transport_context.client_capabilities,
                )
                projected = project_modern_response(
                    method,
                    response,
                    server_name=gateway.server_name,
                    server_version=gateway.server_version,
                )
                return JSONResponse(projected or {"jsonrpc": "2.0", "id": request.get("id"), "result": {}})
        if method == "server/discover":
            return JSONResponse(
                build_modern_discover_response(
                    request.get("id"),
                    server_name=gateway.server_name,
                    server_version=gateway.server_version,
                )
            )

        provided_session_id = session_id
        session_id = _modern_internal_session_id(
            transport_context,
            authenticated_agent_id=authenticated_agent_id,
            role=role,
            requested_session_id=session_id,
        )
        if gateway.session_pool_status().get("enabled") and not provided_session_id:
            raise HTTPException(
                status_code=400,
                detail="Session-isolated MCP Gateway 的现代请求必须携带 X-Agent-Session-ID 或 Mcp-Session-Id，以绑定跨轮次状态。",
            )
        try:
            await asyncio.to_thread(
                gateway.ensure_modern_bridge,
                agent_id=authenticated_agent_id or "mcp-gateway",
                session_id=session_id,
                client_info=transport_context.client_info,
            )
        except (StdioUpstreamError, OSError, TimeoutError, ValueError) as exc:
            raise HTTPException(status_code=503, detail="MCP 上游现代兼容桥初始化失败。") from exc

        if method == "tools/call":
            params = request.get("params")
            params = params if isinstance(params, dict) else {}
            tool_name = str(params.get("name") or "")
            definition = await asyncio.to_thread(
                gateway.modern_tool_definition,
                tool_name,
                agent_id=authenticated_agent_id or "mcp-gateway",
                session_id=session_id,
            )
            try:
                validate_modern_tool_parameter_headers(request, http_request.headers, definition)
            except McpHttpTransportError as exc:
                return _transport_error_response(exc, request.get("id"))

        if method == "subscriptions/listen":
            if "id" not in request:
                return _transport_error_response(
                    McpHttpTransportError("subscriptions/listen 必须是带 id 的 JSON-RPC 请求。"),
                    None,
                )
            params = request.get("params")
            params = params if isinstance(params, dict) else {}
            try:
                normalize_subscription_filter(params)
            except McpHttpTransportError as exc:
                return _transport_error_response(exc, request.get("id"))
            try:
                subscription_stream = stream_modern_subscription(
                    gateway,
                    agent_id=authenticated_agent_id or "mcp-gateway",
                    session_id=session_id,
                    subscription_id=request.get("id"),
                    params=params,
                )
            except SubscriptionCapacityError as exc:
                raise HTTPException(status_code=429, detail=str(exc)) from exc
            except ValueError as exc:
                raise HTTPException(status_code=503, detail="MCP 订阅会话当前不可用。") from exc
            except (StdioUpstreamError, OSError, TimeoutError) as exc:
                raise HTTPException(status_code=503, detail="MCP 订阅上游当前不可用。") from exc
            return StreamingResponse(
                subscription_stream,
                media_type="text/event-stream",
                headers={
                    "Cache-Control": "no-cache, no-transform",
                    "Connection": "keep-alive",
                    "X-Accel-Buffering": "no",
                },
            )
        params = request.get("params")
        params = params if isinstance(params, dict) else {}
        metadata_value = params.get("_meta")
        metadata: dict[str, Any] = metadata_value if isinstance(metadata_value, dict) else {}
        if metadata.get("progressToken") is not None or transport_context.log_level is not None:
            return StreamingResponse(
                _stream_modern_request(
                    gateway,
                    request,
                    agent_id=authenticated_agent_id or "mcp-gateway",
                    session_id=session_id,
                    task_id=task_id,
                    client_capabilities=transport_context.client_capabilities,
                    log_level=transport_context.log_level,
                ),
                media_type="text/event-stream",
                headers={
                    "Cache-Control": "no-cache, no-transform",
                    "Connection": "keep-alive",
                    "X-Accel-Buffering": "no",
                },
            )
    if transport_context.modern:
        response = await _handle_one_until_disconnect(
            http_request,
            gateway,
            request,
            agent_id=authenticated_agent_id or "mcp-gateway",
            session_id=session_id,
            task_id=task_id,
            client_capabilities=transport_context.client_capabilities,
        )
    else:
        response = await asyncio.to_thread(
            _handle_one,
            gateway,
            request,
            agent_id=authenticated_agent_id or "mcp-gateway",
            session_id=session_id,
            task_id=task_id,
        )
    if transport_context.modern:
        response = project_modern_response(
            str(request.get("method") or ""),
            response,
            server_name=gateway.server_name,
            server_version=gateway.server_version,
        )
    if response is None:
        return Response(status_code=202)
    return JSONResponse(
        response,
        status_code=_modern_response_status(response) if transport_context.modern else 200,
        headers=_legacy_session_response_headers(session_id if not transport_context.modern and method == "initialize" else None),
    )


def _required_gateway() -> Any:
    gateway = get_gateway()
    if gateway is None:
        raise HTTPException(status_code=503, detail="MCP Gateway 未启用：请配置 MCP_GATEWAY_UPSTREAM_COMMAND。")
    if not gateway.guard_enabled:
        raise HTTPException(status_code=503, detail="MCP Gateway 强制安全模式未启用，拒绝提供未监督的工具代理。")
    return gateway


def _require_mcp_operation_access(
    message: Any,
    *,
    role: str,
    authenticated_agent_id: str | None,
) -> None:
    """Apply the HTTP caller's role before any MCP side effect can occur.

    The in-process gateway is intentionally reusable in tests and embedded
    deployments, so role enforcement belongs at this authenticated HTTP
    boundary.  ``tools/call`` is the execution capability; discovery and
    lifecycle messages remain available to analyst/executor/admin operator
    roles.  Unrecognised methods are treated as context-capable operations and
    require an analyst or stronger role rather than being silently exposed to
    read-only callers.
    """
    if not isinstance(message, dict):
        raise HTTPException(status_code=400, detail="MCP 批量消息中的每一项都必须是 JSON-RPC 对象。")
    method = str(message.get("method") or "").strip()
    if not method:
        raise HTTPException(status_code=400, detail="MCP 消息缺少 method。")
    capabilities = mcp_access_capabilities(role, authenticated_agent_id)
    if role == "executor" and not capabilities["can_use_mcp"]:
        raise HTTPException(status_code=403, detail="MCP 请求必须使用绑定到 agent_id 的独立 executor 凭证")
    if method == "tools/call":
        if not capabilities["can_execute_mcp_tools"]:
            require_any_role({"executor", "admin"}, role)
        return
    if method in {
        "server/discover",
        "subscriptions/listen",
        "initialize",
        "ping",
        "tools/list",
        "resources/list",
        "resources/templates/list",
        "resources/read",
        "prompts/list",
        "prompts/get",
        "completion/complete",
    } or method.startswith("notifications/"):
        if not capabilities["can_use_mcp"]:
            require_any_role({"analyst", "executor", "admin"}, role)
        return
    raise HTTPException(status_code=400, detail=f"MCP Gateway 不支持方法：{method}")


def _transport_error_response(error: McpHttpTransportError, request_id: Any) -> JSONResponse:
    return JSONResponse(error.payload(request_id), status_code=error.status_code)


def _mcp_allowed_origins(request: Request) -> set[str]:
    configured = {
        item.strip()
        for item in (os.getenv("AGENT_SUPERVISOR_CORS_ORIGINS") or "").split(",")
        if item.strip() and item.strip() != "*"
    }
    configured.update({"http://127.0.0.1:5178", "http://localhost:5178"})
    return configured


def _resolve_session_headers(
    x_agent_session_id: str | None,
    mcp_session_id: str | None,
) -> str | None:
    """Normalize the two supported session headers into one routing key.

    The application header predates the MCP standard header.  Accept either
    spelling, but never guess when both are supplied with different values:
    choosing one would let a single request address two isolated child
    processes depending on which layer happened to read it first.
    """

    try:
        application_value = _normalize_session_id(x_agent_session_id)
        protocol_value = _normalize_session_id(mcp_session_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="MCP 会话标识长度或格式无效。") from exc
    if application_value and protocol_value and application_value != protocol_value:
        raise HTTPException(
            status_code=400,
            detail="X-Agent-Session-ID 与 Mcp-Session-Id 不一致。",
        )
    return application_value or protocol_value or None


def _new_legacy_session_id() -> str:
    """Mint a bounded protocol session id for a headerless legacy initialize."""

    return f"mcp-legacy-{uuid4().hex}"


def _legacy_session_response_headers(session_id: str | None) -> dict[str, str]:
    """Return the standard session header only for a legacy initialize reply."""

    if not session_id:
        return {}
    try:
        normalized = _normalize_session_id(session_id)
    except ValueError:
        return {}
    return {"Mcp-Session-Id": normalized} if normalized else {}


def _modern_internal_session_id(
    context: HttpTransportContext,
    *,
    authenticated_agent_id: str | None,
    role: str,
    requested_session_id: str | None,
) -> str:
    requested = str(requested_session_id or "").strip()
    if requested:
        return requested
    scope = json.dumps(
        {
            "agent_id": authenticated_agent_id or "",
            "role": role,
            "client": context.client_info,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return "modern-" + hashlib.sha256(scope.encode("utf-8")).hexdigest()[:32]


def _handle_one(
    gateway: Any,
    message: Any,
    *,
    agent_id: str = "mcp-gateway",
    session_id: str | None = None,
    task_id: str = "",
    modern: bool = False,
    client_capabilities: dict[str, Any] | None = None,
    progress_callback: Any = None,
    cancel_event: threading.Event | None = None,
) -> dict[str, Any] | None:
    try:
        return gateway.handle(
            message,
            agent_id=agent_id,
            session_id=session_id,
            task_id=task_id,
            modern=modern,
            client_capabilities=client_capabilities,
            progress_callback=progress_callback,
            cancel_event=cancel_event,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except StdioUpstreamError as exc:
        error_hash = hashlib.sha256(str(exc).encode("utf-8")).hexdigest()
        return {
            "jsonrpc": "2.0",
            "id": message.get("id") if isinstance(message, dict) else None,
            "error": {
                "code": -32603,
                "message": "MCP Gateway 上游请求失败；详细原因仅保存在审计记录中。",
                "data": {
                    "error": "MCP 上游请求失败；详细原因仅保留在审计记录中。",
                    "error_hash": error_hash,
                },
            },
        }


async def _handle_one_until_disconnect(
    http_request: Request,
    gateway: Any,
    message: dict[str, Any],
    *,
    agent_id: str,
    session_id: str | None,
    task_id: str,
    client_capabilities: dict[str, Any],
) -> dict[str, Any] | None:
    """Run blocking MCP I/O off-loop and cancel it when its HTTP owner leaves."""

    cancel_event = threading.Event()
    worker = asyncio.create_task(
        asyncio.to_thread(
            _handle_one,
            gateway,
            message,
            agent_id=agent_id,
            session_id=session_id,
            task_id=task_id,
            modern=True,
            client_capabilities=client_capabilities,
            cancel_event=cancel_event,
        )
    )
    try:
        while not worker.done():
            if await http_request.is_disconnected():
                cancel_event.set()
                try:
                    await asyncio.wait_for(asyncio.shield(worker), timeout=1)
                except (TimeoutError, asyncio.CancelledError):
                    pass
                return None
            await asyncio.wait({worker}, timeout=0.05)
        return worker.result()
    except asyncio.CancelledError:
        cancel_event.set()
        try:
            await asyncio.wait_for(asyncio.shield(worker), timeout=1)
        except (TimeoutError, asyncio.CancelledError):
            pass
        raise


def _stream_modern_request(
    gateway: Any,
    message: dict[str, Any],
    *,
    agent_id: str,
    session_id: str | None,
    task_id: str,
    client_capabilities: dict[str, Any],
    log_level: str | None,
) -> Any:
    """Project request-scoped progress/log notifications into one SSE response."""
    events: queue.Queue[dict[str, Any] | None] = queue.Queue(maxsize=128)
    cancel_event = threading.Event()

    def put_terminal(item: dict[str, Any] | None) -> None:
        """Make room for the final response without blocking a dead client."""

        while not cancel_event.is_set():
            try:
                events.put_nowait(item)
                return
            except queue.Full:
                # Progress/log events are advisory.  The JSON-RPC response (or
                # terminal sentinel) is authoritative and must not be lost
                # behind a slow consumer's bounded notification backlog.
                try:
                    events.get_nowait()
                except queue.Empty:
                    continue

    def on_notification(notification: dict[str, Any]) -> None:
        if cancel_event.is_set():
            return
        method = str(notification.get("method") or "")
        if method not in {"notifications/progress", "notifications/message"}:
            return
        if method == "notifications/message":
            raw_params = notification.get("params")
            params: dict[str, Any] = raw_params if isinstance(raw_params, dict) else {}
            if not log_level_allows(log_level, params.get("level")):
                return
        projected = _project_notification(notification)
        try:
            events.put_nowait(projected)
        except queue.Full:
            # A slow client must not turn progress buffering into unbounded
            # memory. The final response remains available to the caller.
            return

    def run() -> None:
        try:
            result = _handle_one(
                gateway,
                message,
                agent_id=agent_id,
                session_id=session_id,
                task_id=task_id,
                modern=True,
                client_capabilities=client_capabilities,
                progress_callback=on_notification,
                cancel_event=cancel_event,
            )
            put_terminal(result)
        except BaseException as exc:  # noqa: BLE001 - converted to JSON-RPC error
            put_terminal(
                {
                    "jsonrpc": "2.0",
                    "id": message.get("id"),
                    "error": {"code": -32603, "message": "MCP 请求流执行失败。", "data": {"error_hash": hashlib.sha256(str(exc).encode()).hexdigest()}},
                }
            )
        finally:
            # If the client is still connected, wake the iterator when the
            # handler returned no response (normally only for a protocol
            # notification).  A cancelled stream has no consumer to wake.
            if not cancel_event.is_set() and events.empty():
                put_terminal(None)

    threading.Thread(target=run, daemon=True, name="mcp-modern-response-stream").start()
    try:
        while True:
            try:
                item = events.get(timeout=15)
            except queue.Empty:
                yield ": keepalive\n\n"
                continue
            if item is None:
                return
            if isinstance(item, dict) and "method" in item and "id" not in item:
                yield "data: " + json.dumps(item, ensure_ascii=False, separators=(",", ":")) + "\n\n"
                continue
            response = project_modern_response(
                str(message.get("method") or ""),
                item if isinstance(item, dict) else None,
                server_name=gateway.server_name,
                server_version=gateway.server_version,
            )
            if response is not None:
                yield "data: " + json.dumps(response, ensure_ascii=False, separators=(",", ":")) + "\n\n"
            # A request-scoped SSE stream terminates immediately after its
            # final JSON-RPC response.  The generator's finally block signals
            # cancellation for the handler if the client disconnects earlier.
            return
    finally:
        cancel_event.set()


def _modern_response_status(response: dict[str, Any]) -> int:
    """Map modern capability negotiation failures to their required HTTP status."""

    error = response.get("error")
    code = error.get("code") if isinstance(error, dict) else None
    return 400 if code == -32021 else 200
