"""MCP Gateway HTTP 入口：Streamable HTTP 子集（单条 / 批量 JSON-RPC POST）。"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from fastapi import APIRouter, Body, Depends, Header, HTTPException, Query, Response
from fastapi.responses import JSONResponse

from apps.api.agent_supervisor.auth import current_agent_identity, current_security_role, require_any_role, require_api_token
from apps.api.agent_supervisor.domains.runtime.agent_credentials import shared_executor_compatibility_enabled
from apps.api.agent_supervisor.mcp_gateway.config import gateway_max_message_bytes
from apps.api.agent_supervisor.mcp_gateway.gateway import get_gateway
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
        "transport": "streamable-http-subset",
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
    all_sessions: bool = Query(default=False),
) -> dict[str, Any]:
    """读取并清空各上游缓冲的上行通知（SSE 之前的轮询替代）。"""
    # Notifications may contain resource updates, tool descriptions or other
    # model-visible context.  They are not a health endpoint; keep them out of
    # observer credentials while allowing analyst/admin operators to inspect
    # and drain the queue.
    require_any_role({"analyst", "admin"}, role)
    gateway = get_gateway()
    if gateway is None:
        raise HTTPException(status_code=503, detail="MCP Gateway 未启用：请配置 MCP_GATEWAY_UPSTREAM_COMMAND。")
    session_status = gateway.session_pool_status()
    if all_sessions:
        require_any_role({"admin"}, role)
    elif session_status.get("enabled") and not str(x_agent_session_id or "").strip():
        raise HTTPException(
            status_code=400,
            detail="Session-isolated MCP Gateway 读取通知必须提供 X-Agent-Session-ID；管理员可显式使用 all_sessions=true。",
        )
    return {
        "notifications": gateway.notifications(
            agent_id=authenticated_agent_id or "mcp-gateway",
            session_id=x_agent_session_id,
            include_all=all_sessions,
        )
    }


@router.get("/api/mcp/tools/evidence")
def mcp_gateway_tool_evidence(
    authenticated_agent_id: str | None = Depends(current_agent_identity),
    role: str = Depends(current_security_role),
    x_agent_session_id: str | None = Header(default=None, alias="X-Agent-Session-ID"),
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
    if gateway.session_pool_status().get("enabled") and not str(x_agent_session_id or "").strip():
        raise HTTPException(status_code=400, detail="Session-isolated MCP Gateway 需要 X-Agent-Session-ID。")
    return gateway.tool_inventory(agent_id=agent_id, session_id=x_agent_session_id)


@router.get("/api/mcp/context/evidence")
def mcp_gateway_context_evidence(
    authenticated_agent_id: str | None = Depends(current_agent_identity),
    role: str = Depends(current_security_role),
    x_agent_session_id: str | None = Header(default=None, alias="X-Agent-Session-ID"),
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
    if gateway.session_pool_status().get("enabled") and not str(x_agent_session_id or "").strip():
        raise HTTPException(status_code=400, detail="Session-isolated MCP Gateway 需要 X-Agent-Session-ID。")
    return gateway.context_inventory(agent_id=agent_id, session_id=x_agent_session_id)


@router.post("/api/mcp")
def mcp_message(
    request: Any = Body(...),
    authenticated_agent_id: str | None = Depends(current_agent_identity),
    role: str = Depends(current_security_role),
    x_agent_session_id: str | None = Header(default=None, alias="X-Agent-Session-ID"),
) -> Any:
    try:
        request_size = len(json.dumps(request, ensure_ascii=False, default=str, separators=(",", ":")).encode("utf-8"))
    except (TypeError, ValueError, RecursionError) as exc:
        raise HTTPException(status_code=400, detail="MCP 请求无法序列化。") from exc
    if request_size > gateway_max_message_bytes():
        raise HTTPException(status_code=413, detail=f"MCP 请求超过 {gateway_max_message_bytes()} 字节安全上限。")

    if isinstance(request, list):
        if not request:
            return Response(status_code=202)
        if len(request) > MCP_MAX_BATCH_ITEMS:
            raise HTTPException(status_code=413, detail=f"MCP 批量请求不能超过 {MCP_MAX_BATCH_ITEMS} 项。")
        for message in request:
            _require_mcp_operation_access(message, role=role, authenticated_agent_id=authenticated_agent_id)
        gateway = _required_gateway()
        responses = [
            _handle_one(
                gateway,
                message,
                agent_id=authenticated_agent_id or "mcp-gateway",
                session_id=x_agent_session_id,
            )
            for message in request
        ]
        payload = [item for item in responses if item is not None]
        return JSONResponse(payload) if payload else Response(status_code=202)

    if not isinstance(request, dict):
        raise HTTPException(status_code=400, detail="MCP 消息必须是 JSON-RPC 对象或数组。")

    _require_mcp_operation_access(request, role=role, authenticated_agent_id=authenticated_agent_id)
    gateway = _required_gateway()
    response = _handle_one(
        gateway,
        request,
        agent_id=authenticated_agent_id or "mcp-gateway",
        session_id=x_agent_session_id,
    )
    return JSONResponse(response) if response is not None else Response(status_code=202)


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
    lifecycle messages remain available to observers.  Unrecognised methods
    are treated as context-capable operations and require an analyst or
    stronger role rather than being silently exposed to read-only callers.
    """
    if not isinstance(message, dict):
        raise HTTPException(status_code=400, detail="MCP 批量消息中的每一项都必须是 JSON-RPC 对象。")
    method = str(message.get("method") or "").strip()
    if not method:
        raise HTTPException(status_code=400, detail="MCP 消息缺少 method。")
    if role == "executor" and not authenticated_agent_id and not shared_executor_compatibility_enabled():
        raise HTTPException(status_code=403, detail="MCP 请求必须使用绑定到 agent_id 的独立 executor 凭证")
    if method == "tools/call":
        require_any_role({"executor", "admin"}, role)
        return
    if method in {
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
        require_any_role({"analyst", "executor", "admin"}, role)
        return
    raise HTTPException(status_code=400, detail=f"MCP Gateway 不支持方法：{method}")


def _handle_one(
    gateway: Any,
    message: Any,
    *,
    agent_id: str = "mcp-gateway",
    session_id: str | None = None,
) -> dict[str, Any] | None:
    try:
        return gateway.handle(message, agent_id=agent_id, session_id=session_id)
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
