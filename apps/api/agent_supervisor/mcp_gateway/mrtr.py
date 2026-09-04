"""可信的 MCP 2026-07-28 Multi Round-Trip Request 状态。

``requestState`` 会被客户端原样带回，因此它不是会话凭据，也不是可直接
信任的 JSON。这个模块只负责有限时、完整性保护和进程内单次使用；业务层
仍必须把主体、会话、原始请求摘要和当前轮次绑定进 payload。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import threading
import time
from typing import Any

MRTR_REQUEST_METHODS = frozenset({"tools/call", "prompts/get", "resources/read"})
MAX_INPUT_RESPONSES = 64
MAX_INPUT_RESPONSES_BYTES = 256 * 1024
MAX_REQUEST_STATE_CHARS = 32 * 1024 + 256


class RequestStateError(ValueError):
    """requestState 缺失、篡改、过期或重放。"""


def validate_mrtr_retry_fields(method: str, params: dict[str, Any]) -> None:
    """Validate the modern retry envelope before gateway or upstream I/O.

    ``inputResponses`` and ``requestState`` describe one retry round. Treating
    either member as optional lets a malformed retry silently become a fresh
    side-effecting request, so the pair is validated as one protocol unit.
    """

    has_responses = "inputResponses" in params
    has_state = "requestState" in params
    if not has_responses and not has_state:
        return
    if method not in MRTR_REQUEST_METHODS:
        raise RequestStateError("inputResponses/requestState 只允许用于 tools/call、prompts/get 或 resources/read。")
    if has_responses != has_state:
        raise RequestStateError("inputResponses 与 requestState 必须在同一重试请求中成对出现。")

    request_state = params.get("requestState")
    if not isinstance(request_state, str) or not request_state or len(request_state) > MAX_REQUEST_STATE_CHARS:
        raise RequestStateError("requestState 必须是非空且大小受限的字符串。")

    responses = params.get("inputResponses")
    if not isinstance(responses, dict):
        raise RequestStateError("inputResponses 必须是对象。")
    if len(responses) > MAX_INPUT_RESPONSES:
        raise RequestStateError(f"inputResponses 不能超过 {MAX_INPUT_RESPONSES} 项。")
    for key, value in responses.items():
        if not isinstance(key, str) or not key or len(key) > 256:
            raise RequestStateError("inputResponses 键必须是长度不超过 256 的非空字符串。")
        if not isinstance(value, dict):
            raise RequestStateError("inputResponses 的每个值必须是对象。")
    try:
        encoded = json.dumps(responses, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise RequestStateError("inputResponses 无法编码。") from exc
    if len(encoded) > MAX_INPUT_RESPONSES_BYTES:
        raise RequestStateError("inputResponses 超过安全大小上限。")


class RequestStateCodec:
    """签名 opaque state 的小型、无第三方依赖实现。

    HMAC 保护完整性但不隐藏 payload；业务层不得把凭据、原始用户内容或
    其他需要保密的数据放入 state。单次使用集合是进程内的，并受 TTL 和
    数量上限约束；跨进程部署应把同一 key 与会话亲和/共享 replay store
    一起配置。
    """

    _PREFIX = b"mcp.requestState.v1:"

    def __init__(self, key: str | bytes, *, ttl_seconds: int = 300, max_payload_bytes: int = 32 * 1024) -> None:
        raw = key.encode("utf-8") if isinstance(key, str) else bytes(key)
        if len(raw) < 32:
            raise ValueError("MCP requestState key 至少需要 32 字节。")
        self._key = raw
        self._ttl_seconds = max(10, min(int(ttl_seconds), 3600))
        self._max_payload_bytes = max(1024, min(int(max_payload_bytes), 256 * 1024))
        self._used: dict[str, int] = {}
        self._lock = threading.Lock()

    @property
    def ttl_seconds(self) -> int:
        return self._ttl_seconds

    def mint(self, payload: dict[str, Any], *, now: int | None = None) -> str:
        if not isinstance(payload, dict):
            raise RequestStateError("requestState payload 必须是对象。")
        issued_at = int(time.time() if now is None else now)
        envelope = {
            "v": 1,
            "iat": issued_at,
            "exp": issued_at + self._ttl_seconds,
            "nonce": secrets.token_urlsafe(18),
            "payload": payload,
        }
        try:
            serialized = json.dumps(envelope, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        except (TypeError, ValueError, RecursionError) as exc:
            raise RequestStateError("requestState payload 无法编码。") from exc
        encoded = _b64url(serialized.encode("utf-8"))
        if len(encoded) > self._max_payload_bytes:
            raise RequestStateError("requestState 超过安全大小上限。")
        signature = _b64url(hmac.new(self._key, self._PREFIX + encoded.encode("ascii"), hashlib.sha256).digest())
        return f"v1.{encoded}.{signature}"

    def verify(self, token: str, *, now: int | None = None, consume: bool = False) -> dict[str, Any]:
        if not isinstance(token, str) or len(token) > self._max_payload_bytes + 256:
            raise RequestStateError("requestState 格式无效。")
        parts = token.split(".")
        if len(parts) != 3 or parts[0] != "v1" or not parts[1] or not parts[2]:
            raise RequestStateError("requestState 格式无效。")
        encoded, supplied_signature = parts[1], parts[2]
        try:
            expected_signature = hmac.new(
                self._key, self._PREFIX + encoded.encode("ascii"), hashlib.sha256
            ).digest()
            actual_signature = _b64url_decode(supplied_signature)
            if not hmac.compare_digest(actual_signature, expected_signature):
                raise RequestStateError("requestState 签名校验失败。")
            envelope = json.loads(_b64url_decode(encoded).decode("utf-8"))
        except (UnicodeError, ValueError, json.JSONDecodeError, RecursionError) as exc:
            if isinstance(exc, RequestStateError):
                raise
            raise RequestStateError("requestState 编码无效。") from exc
        if not isinstance(envelope, dict) or envelope.get("v") != 1:
            raise RequestStateError("requestState 版本无效。")
        try:
            issued_at = int(envelope["iat"])
            expires_at = int(envelope["exp"])
        except (KeyError, TypeError, ValueError) as exc:
            raise RequestStateError("requestState 时间字段无效。") from exc
        current = int(time.time() if now is None else now)
        if expires_at <= current or issued_at > current + 30 or expires_at - issued_at > 3600:
            raise RequestStateError("requestState 已过期或时间字段无效。")
        nonce = envelope.get("nonce")
        payload = envelope.get("payload")
        if not isinstance(nonce, str) or not nonce or not isinstance(payload, dict):
            raise RequestStateError("requestState 内容无效。")
        with self._lock:
            self._prune(current)
            if consume and nonce in self._used:
                raise RequestStateError("requestState 已被使用。")
            if consume:
                self._used[nonce] = expires_at
        return dict(payload)

    def consume(self, token: str, *, now: int | None = None) -> dict[str, Any]:
        return self.verify(token, now=now, consume=True)

    def _prune(self, now: int) -> None:
        for nonce, expiry in list(self._used.items()):
            if expiry <= now:
                self._used.pop(nonce, None)
        if len(self._used) > 10_000:
            for nonce in list(self._used)[: len(self._used) - 10_000]:
                self._used.pop(nonce, None)


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64url_decode(value: str) -> bytes:
    if not isinstance(value, str) or any(character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for character in value):
        raise ValueError("base64url 字符无效")
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
