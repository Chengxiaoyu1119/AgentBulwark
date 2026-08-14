"""MCP Gateway HTTP 入口：Streamable HTTP 子集（单条 / 批量 JSON-RPC POST）。"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, Response
from fastapi.responses import JSONResponse

from apps.api.agent_supervisor.auth import require_api_token
from apps.api.agent_supervisor.mcp_gateway.gateway import get_gateway
from apps.api.agent_supervisor.mcp_gateway.upstream import StdioUpstreamError

router = APIRouter(dependencies=[Depends(require_api_token)])


@router.get("/api/mcp/info")
def mcp_gateway_info() -> dict[str, Any]:
    gateway = get_gateway()
    from apps.api.agent_supervisor.mcp_gateway.config import gateway_guard_enabled, gateway_server_name

    return {
        "enabled": gateway is not None,
        "server_name": gateway_server_name(),
        "guard_enabled": gateway_guard_enabled() if gateway is not None else False,
        "routes": gateway.route_names() if gateway is not None else [],
        "transport": "streamable-http-subset",
        "enforcement": "enforced",
    }


@router.get("/api/mcp/notifications")
def mcp_gateway_notifications() -> dict[str, Any]:
    """读取并清空各上游缓冲的上行通知（SSE 之前的轮询替代）。"""
    gateway = get_gateway()
    if gateway is None:
        raise HTTPException(status_code=503, detail="MCP Gateway 未启用：请配置 MCP_GATEWAY_UPSTREAM_COMMAND。")
    return {"notifications": gateway.notifications()}


@router.post("/api/mcp")
def mcp_message(request: Any = Body(...)) -> Any:
    gateway = get_gateway()
    if gateway is None:
        raise HTTPException(status_code=503, detail="MCP Gateway 未启用：请配置 MCP_GATEWAY_UPSTREAM_COMMAND。")

    if isinstance(request, list):
        if not request:
            return Response(status_code=202)
        responses = [_handle_one(gateway, message) for message in request]
        payload = [item for item in responses if item is not None]
        return JSONResponse(payload) if payload else Response(status_code=202)

    if not isinstance(request, dict):
        raise HTTPException(status_code=400, detail="MCP 消息必须是 JSON-RPC 对象或数组。")

    response = _handle_one(gateway, request)
    return JSONResponse(response) if response is not None else Response(status_code=202)


def _handle_one(gateway: Any, message: Any) -> dict[str, Any] | None:
    try:
        return gateway.handle(message)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except StdioUpstreamError as exc:
        return {
            "jsonrpc": "2.0",
            "id": message.get("id") if isinstance(message, dict) else None,
            "error": {"code": -32603, "message": f"MCP Gateway 上游错误：{exc}"},
        }
