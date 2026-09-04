"""Version-aware MCP Streamable HTTP contract helpers.

The gateway is dual-era: legacy clients establish a 2025-06-18 session with
``initialize`` while modern 2026-07-28 clients carry identity, capabilities and
protocol version on every request.  Keeping transport validation separate from
the JSON-RPC gateway prevents HTTP headers from becoming a second, divergent
source of authorization or routing truth.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Mapping

from apps.api.agent_supervisor.mcp_gateway.mrtr import RequestStateError, validate_mrtr_retry_fields

MODERN_PROTOCOL_VERSION = "2026-07-28"
LEGACY_PROTOCOL_VERSIONS = ("2025-06-18",)
SUPPORTED_PROTOCOL_VERSIONS = (MODERN_PROTOCOL_VERSION, *LEGACY_PROTOCOL_VERSIONS)
LOG_LEVELS = ("debug", "info", "notice", "warning", "error", "critical", "alert", "emergency")
_LOG_LEVEL_RANK = {level: index for index, level in enumerate(LOG_LEVELS)}

MODERN_METHODS = frozenset(
    {
        "server/discover",
        "ping",
        "tools/list",
        "tools/call",
        "resources/list",
        "resources/templates/list",
        "resources/read",
        "prompts/list",
        "prompts/get",
        "completion/complete",
        "subscriptions/listen",
    }
)
_NAMED_METHOD_FIELDS = {
    "tools/call": "name",
    "prompts/get": "name",
    "resources/read": "uri",
}
_SUBSCRIPTION_FILTER_FIELDS = frozenset(
    {
        "toolsListChanged",
        "promptsListChanged",
        "resourcesListChanged",
        "resourceSubscriptions",
    }
)
_SUBSCRIPTION_NOTIFICATION_FIELDS = {
    "notifications/tools/list_changed": "toolsListChanged",
    "notifications/prompts/list_changed": "promptsListChanged",
    "notifications/resources/list_changed": "resourcesListChanged",
}
_HEADER_TOKEN = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_MISSING = object()


@dataclass(frozen=True)
class ToolParameterHeader:
    name: str
    path: tuple[str, ...]
    value_type: str


@dataclass(frozen=True)
class HttpTransportContext:
    era: str
    protocol_version: str
    client_info: dict[str, str]
    client_capabilities: dict[str, Any]
    log_level: str | None

    @property
    def modern(self) -> bool:
        return self.era == "modern"


class McpHttpTransportError(ValueError):
    def __init__(
        self,
        message: str,
        *,
        status_code: int = 400,
        code: int = -32600,
        data: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.data = dict(data or {})

    def payload(self, request_id: Any = None) -> dict[str, Any]:
        error: dict[str, Any] = {"code": self.code, "message": str(self)}
        if self.data:
            error["data"] = self.data
        return {"jsonrpc": "2.0", "id": request_id, "error": error}


def validate_http_transport_request(
    message: dict[str, Any],
    headers: Mapping[str, str],
    *,
    allowed_origins: set[str] | None = None,
) -> HttpTransportContext:
    """Select legacy/modern semantics and enforce the modern HTTP envelope."""

    headers = _normalize_headers(headers)
    validate_mcp_origin(headers, allowed_origins=allowed_origins)

    header_version = str(headers.get("mcp-protocol-version") or "").strip()
    params = message.get("params")
    params = params if isinstance(params, dict) else {}
    metadata = params.get("_meta")
    metadata = metadata if isinstance(metadata, dict) else {}
    body_version = str(metadata.get("io.modelcontextprotocol/protocolVersion") or "").strip()

    if header_version and body_version and header_version != body_version:
        raise _header_mismatch("MCP-Protocol-Version 与请求体 _meta 协议版本不一致。")

    requested_version = body_version or header_version
    # Legacy MCP clients may legitimately use ``params._meta`` for progress
    # tokens or vendor metadata.  Treating every non-empty metadata object as a
    # modern request rejects those otherwise valid 2025 calls.  Modern intent
    # is explicit: the new protocol version, a modern identity/capability
    # marker, or the discover method.  Arbitrary legacy metadata remains on
    # the compatibility path while modern markers still fail closed when the
    # required version/header pair is missing.
    modern_intent = (
        requested_version == MODERN_PROTOCOL_VERSION
        or message.get("method") == "server/discover"
        or "io.modelcontextprotocol/clientInfo" in metadata
        or "io.modelcontextprotocol/clientCapabilities" in metadata
    )
    if not modern_intent:
        if requested_version and requested_version not in LEGACY_PROTOCOL_VERSIONS:
            raise _unsupported_version(requested_version)
        return HttpTransportContext(
            era="legacy",
            protocol_version=requested_version or LEGACY_PROTOCOL_VERSIONS[0],
            client_info={},
            client_capabilities={},
            log_level=None,
        )

    if not requested_version:
        raise _header_mismatch("现代 MCP 请求缺少 MCP-Protocol-Version 和请求体协议版本。")
    if requested_version not in SUPPORTED_PROTOCOL_VERSIONS:
        raise _unsupported_version(requested_version)
    if requested_version != MODERN_PROTOCOL_VERSION:
        raise _header_mismatch("旧版 MCP 请求不能携带现代 per-request _meta。")
    if not header_version or not body_version:
        raise _header_mismatch("现代 MCP 请求必须同时携带 HTTP 与请求体协议版本。")
    if message.get("jsonrpc") != "2.0":
        raise McpHttpTransportError("现代 MCP 请求必须使用 JSON-RPC 2.0。", code=-32600)
    request_id = message.get("id")
    if "id" not in message or isinstance(request_id, bool) or not isinstance(request_id, (str, int)):
        raise McpHttpTransportError("现代 MCP HTTP 消息必须是带字符串或整数 id 的 JSON-RPC 请求。", code=-32600)

    accept = {item.split(";", 1)[0].strip().lower() for item in str(headers.get("accept") or "").split(",")}
    if not {"application/json", "text/event-stream"}.issubset(accept):
        raise _header_mismatch("现代 MCP 请求的 Accept 必须同时包含 application/json 和 text/event-stream。")

    method = str(message.get("method") or "").strip()
    mirrored_method = _decode_header_value(str(headers.get("mcp-method") or ""), "Mcp-Method")
    if not mirrored_method or mirrored_method != method:
        raise _header_mismatch("Mcp-Method 缺失或与请求体 method 不一致。")

    name_field = _NAMED_METHOD_FIELDS.get(method)
    if name_field:
        expected_name = str(params.get(name_field) or "")
        mirrored_name = _decode_header_value(str(headers.get("mcp-name") or ""), "Mcp-Name")
        if not expected_name or not mirrored_name or mirrored_name != expected_name:
            raise _header_mismatch(f"Mcp-Name 缺失或与 params.{name_field} 不一致。")

    if not isinstance(params.get("_meta"), dict):
        raise _header_mismatch("现代 MCP 请求缺少 params._meta。")
    client_info = metadata.get("io.modelcontextprotocol/clientInfo")
    client_capabilities = metadata.get("io.modelcontextprotocol/clientCapabilities")
    raw_log_level = metadata.get("io.modelcontextprotocol/logLevel")
    # The final 2026-07-28 revision makes clientInfo a SHOULD rather than a
    # required envelope member.  A present value remains strictly validated;
    # an absent value is represented as an empty, non-authoritative identity.
    if client_info is None:
        client_info_value: dict[str, str] = {}
    elif not isinstance(client_info, dict):
        raise _header_mismatch("clientInfo 必须是对象。")
    else:
        client_name = str(client_info.get("name") or "").strip()
        client_version = str(client_info.get("version") or "").strip()
        if not client_name or not client_version or len(client_name) > 256 or len(client_version) > 128:
            raise _header_mismatch("clientInfo.name/version 缺失或超过安全长度。")
        client_info_value = {"name": client_name, "version": client_version}
    if not isinstance(client_capabilities, dict):
        raise _header_mismatch("现代 MCP 请求缺少 clientCapabilities。")
    if raw_log_level is None:
        log_level = None
    elif not isinstance(raw_log_level, str) or raw_log_level not in _LOG_LEVEL_RANK:
        raise McpHttpTransportError(
            "io.modelcontextprotocol/logLevel 必须是标准 MCP 日志级别。",
            code=-32602,
            data={"allowedLevels": list(LOG_LEVELS)},
        )
    else:
        log_level = raw_log_level
    try:
        validate_mrtr_retry_fields(method, params)
    except RequestStateError as exc:
        raise McpHttpTransportError(str(exc), code=-32602) from exc

    return HttpTransportContext(
        era="modern",
        protocol_version=MODERN_PROTOCOL_VERSION,
        client_info=client_info_value,
        client_capabilities=deepcopy(client_capabilities),
        log_level=log_level,
    )


def log_level_allows(minimum_level: str | None, emitted_level: Any) -> bool:
    """Return whether one request opted into the emitted MCP log severity."""

    if minimum_level not in _LOG_LEVEL_RANK or not isinstance(emitted_level, str):
        return False
    emitted_rank = _LOG_LEVEL_RANK.get(emitted_level)
    return emitted_rank is not None and emitted_rank >= _LOG_LEVEL_RANK[minimum_level]


def validate_mcp_origin(headers: Mapping[str, str], *, allowed_origins: set[str] | None = None) -> None:
    origin = str(_normalize_headers(headers).get("origin") or "").strip()
    if origin and origin not in (allowed_origins or set()):
        raise McpHttpTransportError(
            "MCP 请求 Origin 未被部署配置允许。",
            status_code=403,
            code=-32600,
            data={"reason": "origin-not-allowed"},
        )


def build_modern_discover_response(request_id: Any, *, server_name: str, server_version: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {
            "resultType": "complete",
            "supportedVersions": list(SUPPORTED_PROTOCOL_VERSIONS),
            "capabilities": {
                "tools": {"listChanged": True},
                "resources": {"listChanged": True},
                "prompts": {"listChanged": True},
            },
            "_meta": {
                "io.modelcontextprotocol/serverInfo": {
                    "name": server_name,
                    "version": server_version,
                }
            },
            "instructions": "工具、资源、提示词和工具结果均经过智安哨安全边界与审计。",
            "ttlMs": 60_000,
            "cacheScope": "private",
        },
    }


def project_modern_response(
    method: str,
    response: dict[str, Any] | None,
    *,
    server_name: str = "",
    server_version: str = "",
) -> dict[str, Any] | None:
    if response is None or not isinstance(response.get("result"), dict):
        return response
    result = response["result"]
    result.setdefault("resultType", "complete")
    if server_name and server_version:
        metadata = result.get("_meta")
        if not isinstance(metadata, dict):
            metadata = {}
            result["_meta"] = metadata
        metadata.setdefault(
            "io.modelcontextprotocol/serverInfo",
            {"name": server_name, "version": server_version},
        )
    if method in {"tools/list", "resources/list", "resources/templates/list", "prompts/list"}:
        result.setdefault("ttlMs", 1_000)
        result.setdefault("cacheScope", "private")
    if method == "tools/list":
        _filter_invalid_modern_tool_headers(result)
    return response


def validate_modern_tool_parameter_headers(
    message: dict[str, Any],
    headers: Mapping[str, str],
    tool_definition: dict[str, Any] | None,
) -> None:
    """Validate ``Mcp-Param-*`` mirrors declared by a tool input schema."""

    if not isinstance(tool_definition, dict):
        return
    try:
        contracts = _tool_parameter_header_contracts(tool_definition)
    except ValueError as exc:
        raise McpHttpTransportError(
            "工具定义包含无效的 x-mcp-header，已拒绝直接调用。",
            code=-32602,
            data={"reason": "invalid-tool-header-schema"},
        ) from exc
    params = message.get("params")
    params = params if isinstance(params, dict) else {}
    arguments = params.get("arguments")
    arguments = arguments if isinstance(arguments, dict) else {}
    normalized_headers = {str(key).lower(): str(value) for key, value in headers.items()}
    for contract in contracts:
        header_key = f"mcp-param-{contract.name}".lower()
        value = _value_at_path(arguments, contract.path)
        present = header_key in normalized_headers
        if value is _MISSING or value is None:
            if present:
                raise _header_mismatch(f"Mcp-Param-{contract.name} 不应在参数缺失或为 null 时出现。")
            continue
        if not present:
            raise _header_mismatch(f"缺少工具参数镜像头 Mcp-Param-{contract.name}。")
        expected = _tool_header_value(value, contract)
        actual = _decode_header_value(normalized_headers[header_key], f"Mcp-Param-{contract.name}")
        if contract.value_type == "integer":
            try:
                matches = int(actual) == int(expected)
            except ValueError:
                matches = False
        else:
            matches = actual == expected
        if not matches:
            raise _header_mismatch(f"Mcp-Param-{contract.name} 与工具调用参数不一致。")


def normalize_subscription_filter(params: dict[str, Any]) -> dict[str, Any]:
    raw_filter = params.get("notifications")
    if not isinstance(raw_filter, dict):
        raise McpHttpTransportError("subscriptions/listen 必须提供 notifications 对象。")
    if len(raw_filter) > 16:
        raise McpHttpTransportError("subscriptions/listen 通知过滤器超过安全字段上限。")

    agreed: dict[str, Any] = {}
    for field in ("toolsListChanged", "promptsListChanged", "resourcesListChanged"):
        value = raw_filter.get(field)
        if value is None:
            continue
        if not isinstance(value, bool):
            raise McpHttpTransportError(f"notifications.{field} 必须是布尔值。")
        if value:
            agreed[field] = True

    raw_resources = raw_filter.get("resourceSubscriptions")
    if raw_resources is not None:
        if not isinstance(raw_resources, list) or len(raw_resources) > 128:
            raise McpHttpTransportError("notifications.resourceSubscriptions 必须是最多 128 项的数组。")
        resources: list[str] = []
        seen: set[str] = set()
        for item in raw_resources:
            uri = str(item or "").strip()
            if not uri or len(uri) > 2_048:
                raise McpHttpTransportError("resourceSubscriptions 包含空值或超长 URI。")
            if uri not in seen:
                seen.add(uri)
                resources.append(uri)
        if resources:
            agreed["resourceSubscriptions"] = resources

    # Unknown filters are ignored and therefore omitted from the acknowledgement.
    return {key: value for key, value in agreed.items() if key in _SUBSCRIPTION_FILTER_FIELDS}


def build_subscription_acknowledgement(
    subscription_id: Any,
    agreed_filter: dict[str, Any],
    *,
    server_name: str = "",
    server_version: str = "",
) -> dict[str, Any]:
    metadata: dict[str, Any] = {"io.modelcontextprotocol/subscriptionId": subscription_id}
    if server_name and server_version:
        metadata["io.modelcontextprotocol/serverInfo"] = {"name": server_name, "version": server_version}
    return {
        "jsonrpc": "2.0",
        "method": "notifications/subscriptions/acknowledged",
        "params": {
            "_meta": metadata,
            "notifications": deepcopy(agreed_filter),
        },
    }


def project_subscription_notification(
    notification: dict[str, Any],
    agreed_filter: dict[str, Any],
    subscription_id: Any,
) -> dict[str, Any] | None:
    method = str(notification.get("method") or "")
    required_flag = _SUBSCRIPTION_NOTIFICATION_FIELDS.get(method)
    if required_flag:
        if agreed_filter.get(required_flag) is not True:
            return None
    elif method == "notifications/resources/updated":
        params = notification.get("params")
        uri = str(params.get("uri") or "") if isinstance(params, dict) else ""
        if uri not in set(agreed_filter.get("resourceSubscriptions") or []):
            return None
    else:
        # Progress/logging messages are request-scoped and must not leak onto a
        # long-lived subscription stream.
        return None

    projected = deepcopy(notification)
    params = projected.get("params")
    if not isinstance(params, dict):
        params = {}
        projected["params"] = params
    metadata = params.get("_meta")
    if not isinstance(metadata, dict):
        metadata = {}
        params["_meta"] = metadata
    metadata["io.modelcontextprotocol/subscriptionId"] = subscription_id
    return projected


def encode_sse_message(message: dict[str, Any]) -> str:
    return "data: " + json.dumps(message, ensure_ascii=False, separators=(",", ":")) + "\n\n"


def _unsupported_version(requested: str) -> McpHttpTransportError:
    return McpHttpTransportError(
        "Unsupported protocol version",
        status_code=400,
        code=-32022,
        data={"supported": list(SUPPORTED_PROTOCOL_VERSIONS), "requested": requested},
    )


def _header_mismatch(message: str) -> McpHttpTransportError:
    return McpHttpTransportError(message, status_code=400, code=-32020)


def _decode_header_value(value: str, field: str) -> str:
    if not value:
        return ""
    if value.startswith("=?base64?") and value.endswith("?="):
        encoded = value[len("=?base64?") : -2]
        try:
            return base64.b64decode(encoded, validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError) as exc:
            raise _header_mismatch(f"{field} Base64 编码无效。") from exc
    if value != value.strip() or any(ord(character) < 0x20 or ord(character) > 0x7E for character in value):
        raise _header_mismatch(f"{field} 包含未编码的非 ASCII 或控制字符。")
    return value


def _normalize_headers(headers: Mapping[str, str]) -> dict[str, str]:
    return {str(key).lower(): str(value) for key, value in headers.items()}


def _filter_invalid_modern_tool_headers(result: dict[str, Any]) -> None:
    tools = result.get("tools")
    if not isinstance(tools, list):
        return
    visible: list[Any] = []
    filtered_count = 0
    for tool in tools:
        if not isinstance(tool, dict):
            filtered_count += 1
            continue
        try:
            _tool_parameter_header_contracts(tool)
        except ValueError:
            filtered_count += 1
            continue
        visible.append(tool)
    if filtered_count:
        result["tools"] = visible
        marker = result.setdefault("zhiAnSentinel", {})
        if isinstance(marker, dict):
            marker["modernHeaderProjection"] = {
                "invalidToolCount": filtered_count,
                "policy": "invalid-x-mcp-header-excluded",
            }


def _tool_parameter_header_contracts(tool_definition: dict[str, Any]) -> list[ToolParameterHeader]:
    schema = tool_definition.get("inputSchema")
    if schema is None:
        return []
    if not isinstance(schema, dict):
        raise ValueError("inputSchema 必须是对象")
    contracts: list[ToolParameterHeader] = []
    seen_names: set[str] = set()

    def walk(value: Any, path: tuple[str, ...], statically_reachable: bool) -> None:
        if isinstance(value, list):
            for item in value:
                walk(item, path, False)
            return
        if not isinstance(value, dict):
            return
        if "x-mcp-header" in value:
            raw_name = value.get("x-mcp-header")
            name = str(raw_name or "")
            value_type = str(value.get("type") or "")
            lowered = name.lower()
            if (
                not statically_reachable
                or not path
                or not name
                or not _HEADER_TOKEN.fullmatch(name)
                or lowered in seen_names
                or value_type not in {"string", "integer", "boolean"}
            ):
                raise ValueError("x-mcp-header 注解位置、名称或类型无效")
            seen_names.add(lowered)
            contracts.append(ToolParameterHeader(name=name, path=path, value_type=value_type))

        for key, child in value.items():
            if key == "properties" and statically_reachable:
                if not isinstance(child, dict):
                    raise ValueError("properties 必须是对象")
                for property_name, property_schema in child.items():
                    walk(property_schema, (*path, str(property_name)), True)
            elif key != "x-mcp-header":
                walk(child, path, False)

    walk(schema, (), True)
    return contracts


def _value_at_path(arguments: dict[str, Any], path: tuple[str, ...]) -> Any:
    current: Any = arguments
    for item in path:
        if not isinstance(current, dict) or item not in current:
            return _MISSING
        current = current[item]
    return current


def _tool_header_value(value: Any, contract: ToolParameterHeader) -> str:
    if contract.value_type == "string":
        if not isinstance(value, str):
            raise _header_mismatch(f"参数 {'.'.join(contract.path)} 必须是字符串。")
        return value
    if contract.value_type == "boolean":
        if not isinstance(value, bool):
            raise _header_mismatch(f"参数 {'.'.join(contract.path)} 必须是布尔值。")
        return "true" if value else "false"
    if isinstance(value, bool) or not isinstance(value, int) or not (-(2**53) + 1 <= value <= 2**53 - 1):
        raise _header_mismatch(f"参数 {'.'.join(contract.path)} 必须是安全范围内的整数。")
    return str(value)
