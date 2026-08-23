"""ASGI request limits and JSON parser-differential guards.

The HTTP boundary owns the byte limit and rejects duplicate JSON keys or
non-finite numbers before FastAPI and provider adapters can parse the same
payload with different semantics.  Keeping this middleware in the runtime
domain makes the application entrypoint responsible only for composition.
"""

from __future__ import annotations

import json
from typing import Any

from fastapi.responses import JSONResponse

# The OpenAI-compatible proxy validates requests up to 4 MiB internally.  The
# outer ASGI guard must not reject a valid proxy payload before that contract
# runs; protocol-specific endpoints keep their own tighter limits after
# deserialization.
MAX_REQUEST_BODY_BYTES = 4 * 1024 * 1024


class _RequestBodyTooLarge(Exception):
    pass


class _RequestJsonInvalid(Exception):
    pass


class RequestBodyLimitMiddleware:
    def __init__(self, app: Any, max_body_bytes: int) -> None:
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        content_length = headers.get(b"content-length", b"")
        try:
            declared_size = int(content_length) if content_length else 0
        except ValueError:
            declared_size = 0
        if declared_size > self.max_body_bytes:
            await self._reject(scope, receive, send)
            return

        received_size = 0
        response_started = False
        inspect_json = (
            scope.get("method", "").upper() == "POST"
            and scope.get("path") in {"/v1/chat/completions", "/v1/responses", "/api/mcp"}
        )
        json_buffer = bytearray()

        async def limited_receive() -> dict[str, Any]:
            nonlocal received_size
            message = await receive()
            if message.get("type") == "http.request":
                body = message.get("body", b"")
                received_size += len(body)
                if received_size > self.max_body_bytes:
                    raise _RequestBodyTooLarge
                if inspect_json:
                    json_buffer.extend(body)
                    if not message.get("more_body", False):
                        try:
                            json.loads(
                                bytes(json_buffer),
                                object_pairs_hook=_reject_duplicate_json_keys,
                                parse_constant=_reject_non_finite_json,
                            )
                        except _RequestJsonInvalid:
                            raise
                        except (TypeError, ValueError, RecursionError) as exc:
                            # FastAPI still owns normal JSON/schema errors. This
                            # branch only rejects parser-differential payloads
                            # that could be interpreted differently downstream.
                            raise _RequestJsonInvalid from exc
            return message

        async def tracked_send(message: dict[str, Any]) -> None:
            nonlocal response_started
            if message.get("type") == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracked_send)
        except _RequestBodyTooLarge:
            if response_started:
                raise
            await self._reject(scope, receive, send, status_code=413)
        except _RequestJsonInvalid:
            if response_started:
                raise
            await self._reject(scope, receive, send, status_code=400)

    async def _reject(
        self,
        scope: dict[str, Any],
        receive: Any,
        send: Any,
        *,
        status_code: int = 413,
    ) -> None:
        response = JSONResponse(
            status_code=status_code,
            content={
                "detail": (
                    f"请求体不能超过 {self.max_body_bytes} 字节"
                    if status_code == 413
                    else "请求 JSON 包含重复字段、非有限数字或无法安全解析"
                )
            },
        )
        await response(scope, receive, send)


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _RequestJsonInvalid
        result[key] = value
    return result


def _reject_non_finite_json(value: str) -> Any:
    raise _RequestJsonInvalid
