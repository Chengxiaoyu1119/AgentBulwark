from __future__ import annotations

import base64
import binascii
import html
import ipaddress
import math
import re
import socket
import unicodedata
from email.utils import getaddresses
from fnmatch import fnmatchcase
from pathlib import PurePosixPath, PureWindowsPath
from typing import Any, cast
from urllib.parse import unquote, urlsplit, urlunsplit

SUPPORTED_TOOLS = frozenset(
    {
        "file.read",
        "file.write",
        "mail.send",
        "api.call",
        "memory.write",
        "memory.read",
        "env.read",
        "model.respond",
    }
)
ALLOWED_API_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})

# Provider/MCP tool schemas are untrusted input.  A schema validator without a
# recursion or regex budget turns the gateway into a cheap CPU denial-of-service
# endpoint: deeply nested combinators can exhaust Python's stack and a pattern
# such as ``(a+)+`` can make the stdlib regex engine spend unbounded time.
MAX_JSON_SCHEMA_DEPTH = 32
MAX_JSON_SCHEMA_NODES = 2048
MAX_JSON_SCHEMA_PATTERN_LENGTH = 512
MAX_JSON_VALUE_DEPTH = 32
MAX_JSON_VALUE_NODES = 4096
_UNSAFE_SCHEMA_REGEX = re.compile(r"\([^()\n]*[+*{][^()\n]*\)[+*{]")
_BACKREFERENCE_REGEX = re.compile(r"\\(?:[1-9][0-9]*|k<[^>]+>)")

SENSITIVE_PATH_MARKERS = frozenset(
    {
        "confidential",
        "secret",
        "secrets",
        "token",
        "tokens",
        "credential",
        "credentials",
        ".env",
        "private-key",
        "private_key",
    }
)


def canonical_text(value: Any) -> str:
    text = str(value or "")
    for _ in range(3):
        normalized = unicodedata.normalize("NFKC", text)
        decoded = html.unescape(unquote(normalized))
        text = decoded
        if decoded == normalized:
            break
    return unicodedata.normalize("NFKC", text).strip()


def canonical_text_variants(value: Any) -> list[str]:
    """Return bounded security-view variants without rewriting provider data.

    URL/HTML/NFKC normalization catches protocol and markup disguises. A
    base64 variant is added only when a token decodes to mostly printable text;
    arbitrary binary blobs therefore remain data instead of becoming a source
    of broad false positives. Callers use these variants for detection only.
    """
    text = canonical_text(value)
    variants = [text]
    # Unicode format controls (zero-width characters and bidi overrides) are
    # invisible in most Agent UIs but can split a marker such as
    # ``ignore previous`` or ``忽略之前的规则``.  Keep the provider payload
    # unchanged; add a security-only view with those controls removed.
    format_stripped = "".join(char for char in text if unicodedata.category(char) != "Cf")
    if format_stripped != text:
        variants.append(format_stripped)
    token_pattern = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{20,}={0,2}(?![A-Za-z0-9+/=])")
    for token in token_pattern.findall(text)[:32]:
        padded = token + "=" * ((4 - len(token) % 4) % 4)
        try:
            decoded_bytes = base64.b64decode(padded, validate=True)
        except (ValueError, binascii.Error):
            continue
        decoded = decoded_bytes.decode("utf-8", errors="ignore").strip()
        if not decoded or len(decoded) < 8:
            continue
        printable_ratio = sum(char.isprintable() or char.isspace() for char in decoded) / len(decoded)
        if printable_ratio >= 0.85:
            variants.append(decoded)
    return list(dict.fromkeys(variants))


def normalize_tool_call(tool_call: dict[str, Any]) -> dict[str, Any]:
    raw_arguments = tool_call.get("arguments")
    arguments = dict(raw_arguments) if isinstance(raw_arguments, dict) else {}
    tool = canonical_text(tool_call.get("tool")).lower()

    if tool in {"file.read", "file.write"}:
        arguments["path"] = normalize_path(arguments.get("path"))
    elif tool == "mail.send":
        arguments["to"] = normalize_recipients(arguments.get("to"))
    elif tool == "api.call":
        arguments["endpoint"] = normalize_endpoint(arguments.get("endpoint"))
        arguments["method"] = canonical_text(arguments.get("method") or "GET").upper()
    elif tool == "env.read":
        arguments["key"] = canonical_text(arguments.get("key"))

    return {
        "tool": tool,
        "arguments": arguments,
        "risk_hint": canonical_text(tool_call.get("risk_hint")).lower(),
    }


def validate_json_schema_instance(
    value: Any,
    schema: Any,
    *,
    path: str = "arguments",
    _depth: int = 0,
    _budget: dict[str, int] | None = None,
) -> str | None:
    """Validate the security-relevant subset of a JSON Schema recursively.

    Provider and MCP schemas are untrusted inputs, but a declared schema is
    still the contract the gateway must enforce before a tool call crosses the
    execution boundary.  The validator deliberately fails closed for malformed
    combinators and unresolved references instead of silently accepting a
    nested argument that was never declared.
    """
    budget = _budget if _budget is not None else {"nodes": 0}
    budget["nodes"] = int(budget.get("nodes", 0)) + 1
    if _depth > MAX_JSON_SCHEMA_DEPTH:
        return f"{path} 的 schema 嵌套超过 {MAX_JSON_SCHEMA_DEPTH} 层安全上限"
    if budget["nodes"] > MAX_JSON_SCHEMA_NODES:
        return f"{path} 的 schema 节点超过 {MAX_JSON_SCHEMA_NODES} 个安全上限"
    # Python's JSON decoder accepts NaN/Infinity even though they are not JSON
    # numbers.  Reject them before the schema's permissive ``true`` branch can
    # treat the value as valid and create a parser differential downstream.
    if isinstance(value, float) and not math.isfinite(value):
        return f"{path} 不能包含非有限数字"
    if schema is True or schema is None:
        return None
    if schema is False:
        return f"{path} 被 schema 明确禁止"
    if not isinstance(schema, dict):
        return f"{path} 的 schema 不是对象"
    if "$ref" in schema:
        return f"{path} 使用未解析的 schema $ref"

    def _matches(candidate: Any, candidate_schema: Any) -> bool:
        return (
            validate_json_schema_instance(
                candidate,
                candidate_schema,
                path=path,
                _depth=_depth + 1,
                _budget=budget,
            )
            is None
        )

    for keyword in ("allOf", "anyOf", "oneOf"):
        if keyword not in schema:
            continue
        variants = schema.get(keyword)
        if not isinstance(variants, list) or not variants or any(not isinstance(item, (dict, bool)) for item in variants):
            return f"{path} 的 {keyword} schema 无效"
        matches = sum(1 for item in variants if _matches(value, item))
        if keyword == "allOf" and matches != len(variants):
            return f"{path} 不满足 allOf schema"
        if keyword == "anyOf" and matches == 0:
            return f"{path} 不满足 anyOf schema"
        if keyword == "oneOf" and matches != 1:
            return f"{path} 不满足 oneOf schema"

    if "not" in schema and _matches(value, schema.get("not")):
        return f"{path} 命中 schema 的 not 约束"
    if "enum" in schema:
        enum = schema.get("enum")
        if not isinstance(enum, list) or value not in enum:
            return f"{path} 不在 schema enum 允许取值内"
    if "const" in schema and value != schema.get("const"):
        return f"{path} 不符合 schema const 约束"

    expected_type = schema.get("type")
    allowed_types = expected_type if isinstance(expected_type, list) else [expected_type] if expected_type else []
    if allowed_types:
        if any(not isinstance(item, str) for item in allowed_types):
            return f"{path} 的 schema type 无效"
        if not any(_json_schema_type_matches(value, item) for item in allowed_types):
            return f"{path} 类型不符合 schema：期望 {', '.join(allowed_types)}"

    if isinstance(value, dict):
        required = schema.get("required", [])
        if required is not None and (not isinstance(required, list) or any(not isinstance(item, str) for item in required)):
            return f"{path} 的 required schema 无效"
        for name in required or []:
            if name not in value:
                return f"{path} 缺少必填参数：{name}"
        properties = schema.get("properties", {})
        if properties is not None and not isinstance(properties, dict):
            return f"{path} 的 properties schema 无效"
        property_map = properties if isinstance(properties, dict) else {}
        pattern_properties = schema.get("patternProperties", {})
        if pattern_properties is not None and not isinstance(pattern_properties, dict):
            return f"{path} 的 patternProperties schema 无效"
        compiled_patterns: list[tuple[re.Pattern[str], Any]] = []
        for pattern, pattern_schema in (pattern_properties or {}).items():
            if not isinstance(pattern, str) or not isinstance(pattern_schema, (dict, bool)):
                return f"{path} 的 patternProperties schema 无效"
            compiled, pattern_issue = _compile_schema_regex(pattern, path)
            if pattern_issue:
                return pattern_issue
            assert compiled is not None
            compiled_patterns.append((compiled, pattern_schema))
        additional = schema.get("additionalProperties", True)
        if not isinstance(additional, (dict, bool)):
            return f"{path} 的 additionalProperties schema 无效"
        for name, item in value.items():
            child_path = f"{path}.{name}"
            child_schema = property_map.get(name)
            matched_pattern = False
            for pattern, pattern_schema in compiled_patterns:
                if pattern.search(str(name)):
                    matched_pattern = True
                    issue = validate_json_schema_instance(
                        item,
                        pattern_schema,
                        path=child_path,
                        _depth=_depth + 1,
                        _budget=budget,
                    )
                    if issue:
                        return issue
            if child_schema is not None:
                issue = validate_json_schema_instance(
                    item,
                    child_schema,
                    path=child_path,
                    _depth=_depth + 1,
                    _budget=budget,
                )
                if issue:
                    return issue
            elif not matched_pattern:
                if additional is False:
                    return f"{path} 包含未声明参数：{name}"
                if isinstance(additional, dict):
                    issue = validate_json_schema_instance(
                        item,
                        additional,
                        path=child_path,
                        _depth=_depth + 1,
                        _budget=budget,
                    )
                    if issue:
                        return issue
        min_properties = schema.get("minProperties")
        max_properties = schema.get("maxProperties")
        if isinstance(min_properties, int) and len(value) < min_properties:
            return f"{path} 参数数量少于 schema minProperties"
        if isinstance(max_properties, int) and len(value) > max_properties:
            return f"{path} 参数数量超过 schema maxProperties"

    if isinstance(value, list):
        items = schema.get("items")
        if isinstance(items, (dict, bool)):
            for index, item in enumerate(value):
                issue = validate_json_schema_instance(
                    item,
                    items,
                    path=f"{path}[{index}]",
                    _depth=_depth + 1,
                    _budget=budget,
                )
                if issue:
                    return issue
        elif items is not None:
            return f"{path} 的 items schema 无效"
        min_items = schema.get("minItems")
        max_items = schema.get("maxItems")
        if isinstance(min_items, int) and len(value) < min_items:
            return f"{path} 数组长度小于 schema minItems"
        if isinstance(max_items, int) and len(value) > max_items:
            return f"{path} 数组长度超过 schema maxItems"

    if isinstance(value, str):
        min_length = schema.get("minLength")
        max_length = schema.get("maxLength")
        if isinstance(min_length, int) and len(value) < min_length:
            return f"{path} 字符串长度小于 schema minLength"
        if isinstance(max_length, int) and len(value) > max_length:
            return f"{path} 字符串长度超过 schema maxLength"
        pattern = schema.get("pattern")
        if pattern is not None:
            if not isinstance(pattern, str):
                return f"{path} 的 pattern schema 无效"
            compiled, pattern_issue = _compile_schema_regex(pattern, path)
            if pattern_issue:
                return pattern_issue
            assert compiled is not None
            try:
                matched = compiled.search(value)
            except re.error:
                return f"{path} 的 pattern 正则无效"
            if matched is None:
                return f"{path} 不符合 schema pattern"

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        minimum = schema.get("minimum")
        maximum = schema.get("maximum")
        if isinstance(minimum, (int, float)) and value < minimum:
            return f"{path} 小于 schema minimum"
        if isinstance(maximum, (int, float)) and value > maximum:
            return f"{path} 超过 schema maximum"
    return None


def validate_json_value_limits(
    value: Any,
    *,
    path: str = "value",
    max_depth: int = MAX_JSON_VALUE_DEPTH,
    max_nodes: int = MAX_JSON_VALUE_NODES,
) -> str | None:
    """Bound an untrusted JSON value without recursing through Python frames.

    Tool arguments and provider extensions are attacker-controlled JSON. The
    schema validator is only entered when a schema exists; a deep value with
    no schema would otherwise reach scanners, serializers, or downstream SDKs
    and either exhaust the Python stack or hide a payload below their shallower
    traversal limits. An explicit stack keeps the boundary deterministic even
    for values already materialised by an upstream adapter.
    """

    if max_depth < 0 or max_nodes < 1:
        return f"{path} 的 JSON 深度/节点上限无效"
    stack: list[tuple[Any, str, int]] = [(value, path, 0)]
    visited = 0
    while stack:
        current, current_path, depth = stack.pop()
        visited += 1
        if depth > max_depth:
            return f"{current_path} 的 JSON 嵌套超过 {max_depth} 层安全上限"
        if visited > max_nodes:
            return f"{path} 的 JSON 节点超过 {max_nodes} 个安全上限"
        if isinstance(current, float) and not math.isfinite(current):
            return f"{current_path} 不能包含非有限数字"
        if isinstance(current, dict):
            for key, item in current.items():
                stack.append((item, f"{current_path}.{key}", depth + 1))
        elif isinstance(current, list):
            for index, item in enumerate(current):
                stack.append((item, f"{current_path}[{index}]", depth + 1))
    return None


def _compile_schema_regex(pattern: str, path: str) -> tuple[re.Pattern[str] | None, str | None]:
    """Compile a bounded, non-backreferencing schema regex.

    Python's standard ``re`` engine has no timeout.  Reject the small family of
    nested-quantifier/backreference constructs that are known to turn a short
    schema into catastrophic backtracking, and fail closed for overlong or
    malformed patterns.  This keeps schema validation deterministic on the
    request thread without adding a new regex dependency.
    """
    if len(pattern) > MAX_JSON_SCHEMA_PATTERN_LENGTH:
        return None, f"{path} 的 schema 正则超过 {MAX_JSON_SCHEMA_PATTERN_LENGTH} 个字符安全上限"
    if _UNSAFE_SCHEMA_REGEX.search(pattern) or _BACKREFERENCE_REGEX.search(pattern):
        return None, f"{path} 的 schema 正则包含不安全的回溯构造"
    try:
        return re.compile(pattern), None
    except re.error:
        return None, f"{path} 的 schema 正则无效"


def _json_schema_type_matches(value: Any, expected_type: str) -> bool:
    if expected_type == "null":
        return value is None
    if expected_type == "object":
        return isinstance(value, dict)
    if expected_type == "array":
        return isinstance(value, list)
    if expected_type == "string":
        return isinstance(value, str)
    if expected_type == "boolean":
        return isinstance(value, bool)
    if expected_type == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected_type == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    return False


def normalize_path(value: Any) -> str:
    return canonical_text(value).replace("\\", "/")


def path_is_absolute_or_traversal(value: Any) -> bool:
    path = normalize_path(value)
    if not path:
        return True
    if PurePosixPath(path).is_absolute() or PureWindowsPath(path).is_absolute():
        return True
    if re.match(r"^[a-zA-Z]:", path) or path.startswith("//"):
        return True
    return ".." in PurePosixPath(path).parts


def path_is_sensitive(value: Any, markers: set[str] | frozenset[str] | None = None) -> bool:
    path = normalize_path(value).lower()
    effective_markers = {canonical_text(item).lower() for item in (markers or SENSITIVE_PATH_MARKERS) if canonical_text(item)}
    parts = {part for part in PurePosixPath(path).parts if part not in {"/", ""}}
    for part in parts:
        if part in effective_markers or part.startswith(".env"):
            return True
        tokens = set(filter(None, re.split(r"[._-]+", part)))
        if tokens.intersection(effective_markers):
            return True
    return False


def normalize_endpoint(value: Any) -> str:
    endpoint = canonical_text(value).replace("\\", "/")
    if not endpoint:
        return ""
    parsed = urlsplit(endpoint)
    if parsed.scheme or parsed.netloc:
        # Keep the authority delimiter intact: collapsing all repeated slashes
        # turns ``https://host`` into ``https:/host`` and hides SSRF evidence.
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc
        path = re.sub(r"/{2,}", "/", parsed.path or ("/" if netloc else ""))
        return urlunsplit((scheme, netloc, path, parsed.query, parsed.fragment))
    return re.sub(r"/{2,}", "/", endpoint)


def endpoint_security_reason(
    value: Any,
    sensitive_markers: set[str] | frozenset[str] | None = None,
) -> str | None:
    """Return a fail-closed reason for unsafe Agent HTTP destinations.

    Relative fixture routes remain supported. Absolute destinations are
    restricted to HTTP(S), reject loopback/private/link-local/metadata hosts,
    and reject high-sensitivity paths before any executor can connect.
    """
    endpoint = normalize_endpoint(value)
    if not endpoint:
        return "API endpoint 为空。"
    parsed = urlsplit(endpoint)
    markers = {
        canonical_text(item).lower()
        for item in (sensitive_markers or set())
        if canonical_text(item)
    }
    endpoint_lower = endpoint.lower()
    if parsed.scheme or parsed.netloc:
        if parsed.scheme not in {"http", "https"}:
            return f"API endpoint 使用不允许的协议 `{parsed.scheme or 'unknown'}`。"
        hostname = (parsed.hostname or "").rstrip(".").lower()
        if not hostname:
            return "API endpoint 缺少主机名。"
        if parsed.username or parsed.password:
            return "API endpoint 不允许携带用户信息，避免混淆真实目标主机。"
        if _is_restricted_host(hostname):
            return f"API endpoint 主机 `{hostname}` 属于回环、私网、链路本地或云元数据地址。"
        path_and_query = f"{parsed.path} {parsed.query}".lower()
        if _contains_sensitive_endpoint_marker(path_and_query, markers):
            return f"API endpoint 路径 `{parsed.path or '/'}` 命中高敏资源边界。"
        return None

    # Relative routes are local fixture/API capabilities.  Apply the same
    # high-sensitivity marker check without treating `/api/public/...` as SSRF.
    if _contains_sensitive_endpoint_marker(endpoint_lower, markers):
        return f"API endpoint `{endpoint}` 命中高敏资源边界。"
    return None


def get_agent_api_allowlist(settings: dict[str, Any] | None, agent_id: str) -> list[str] | None:
    """Return the host allowlist bound to an Agent identity.

    ``None`` means the caller did not present an Agent identity and is kept for
    local unit/fixture decisions.  An identified Agent with no matching entry
    receives an empty list, which deliberately fails closed for absolute HTTP
    destinations.  Relative routes never need an external host registration.
    """
    normalized_agent_id = canonical_text(agent_id)
    if not normalized_agent_id:
        return None
    raw_allowlists = (settings or {}).get("agent_api_allowlists")
    if not isinstance(raw_allowlists, dict):
        return []
    raw_targets = raw_allowlists.get(normalized_agent_id, raw_allowlists.get("*", []))
    if not isinstance(raw_targets, list):
        return []
    return [canonical_text(item).lower() for item in raw_targets[:100] if canonical_text(item)]


def get_agent_model_allowlist(settings: dict[str, Any] | None, agent_id: str) -> list[str] | None:
    """Return model identifiers registered for one authenticated Agent.

    ``None`` is reserved for calls without an Agent identity (local/in-process
    compatibility).  An identified Agent with a configured map but no matching
    entry receives an empty list so an operator can fail closed by registering
    the identity explicitly.
    """
    normalized_agent_id = canonical_text(agent_id)
    if not normalized_agent_id:
        return None
    strict_registration = bool((settings or {}).get("require_agent_model_registration", False))
    raw_allowlists = (settings or {}).get("agent_model_allowlists")
    if not isinstance(raw_allowlists, dict):
        return [] if strict_registration else None
    raw_models = raw_allowlists.get(normalized_agent_id, raw_allowlists.get("*"))
    if raw_models is None:
        return [] if strict_registration else None
    if not isinstance(raw_models, list):
        return []
    return [canonical_text(item).lower() for item in raw_models[:100] if canonical_text(item)]


def get_agent_context_allowlist(
    settings: dict[str, Any] | None,
    agent_id: str,
) -> dict[str, list[str]] | None:
    """Return the MCP context scope bound to one Agent identity.

    ``None`` preserves local/in-process compatibility. An identified Agent
    without a matching entry receives an empty scope when production (or an
    operator) enables strict context registration, so a direct
    ``resources/read`` or ``prompts/get`` cannot inherit another Agent's data.
    """
    normalized_agent_id = canonical_text(agent_id)
    if not normalized_agent_id:
        return None
    policy = settings or {}
    strict_registration = bool(policy.get("require_agent_context_registration", False))
    raw_allowlists = policy.get("agent_context_allowlists")
    if not isinstance(raw_allowlists, dict):
        return {} if strict_registration else None
    raw_scope = raw_allowlists.get(normalized_agent_id, raw_allowlists.get("*"))
    if raw_scope is None:
        return {} if strict_registration else None
    if not isinstance(raw_scope, dict):
        return {}
    result: dict[str, list[str]] = {}
    for kind in ("resources", "resource_templates", "prompts"):
        raw_values = raw_scope.get(kind, [])
        if not isinstance(raw_values, list):
            result[kind] = []
            continue
        result[kind] = [str(item).strip()[:512] for item in raw_values[:100] if str(item).strip()]
    return result


def context_allowlist_reason(
    kind: str,
    value: Any,
    allowed_scope: dict[str, list[str]] | None,
) -> str | None:
    """Check one MCP URI/template/prompt name against the Agent scope."""
    if allowed_scope is None:
        return None
    normalized_kind = canonical_text(kind).lower()
    candidate = canonical_text(value)
    allowed = allowed_scope.get(normalized_kind, [])
    if candidate and any(fnmatchcase(candidate, pattern) for pattern in allowed):
        return None
    return f"MCP {normalized_kind or 'context'} 未登记在当前 Agent 的上下文白名单中。"


def get_agent_tool_allowlist(settings: dict[str, Any] | None, agent_id: str) -> list[str] | None:
    """Return the capability names visible to one authenticated Agent.

    ``None`` keeps local/in-process compatibility when capability registration
    is disabled.  Once an Agent identity is present and registration is
    required (or a concrete allowlist exists), an absent binding becomes an
    empty list so discovery and execution fail closed together.
    """
    normalized_agent_id = canonical_text(agent_id)
    if not normalized_agent_id:
        return None
    policy = settings or {}
    strict_registration = bool(policy.get("require_agent_capability_registration", False))
    raw_allowlists = policy.get("agent_tool_allowlists")
    if not isinstance(raw_allowlists, dict):
        return [] if strict_registration else None
    raw_tools = raw_allowlists.get(normalized_agent_id, raw_allowlists.get("*"))
    if raw_tools is None:
        return [] if strict_registration else None
    if not isinstance(raw_tools, list):
        return []
    return [canonical_text(item).lower() for item in raw_tools[:100] if canonical_text(item)]


def model_allowlist_reason(value: Any, allowed_models: list[str] | None) -> str | None:
    """Check a selected provider model against an Agent-bound allowlist."""
    model = canonical_text(value)
    if allowed_models is None:
        return None
    if not model:
        return "透明代理请求缺少 model，无法建立 Agent 模型权限边界。"
    normalized = model.lower()
    if not allowed_models:
        return f"Agent 未登记可用模型 `{model}`。"
    if normalized in {canonical_text(item).lower() for item in allowed_models}:
        return None
    return f"模型 `{model}` 不在当前 Agent 的模型白名单中。"


def endpoint_allowlist_reason(value: Any, allowed_targets: list[str] | None) -> str | None:
    """Check an absolute HTTP(S) endpoint against an Agent-bound allowlist.

    Relative routes are local capabilities and return ``None``.  Entries may
    be exact hosts (``api.example.com``), scheme-qualified origins
    (``https://api.example.com``), optional ports, or an explicit single-level
    wildcard (``*.example.com``).  Paths, queries, fragments and credentials in
    an allowlist entry are rejected as ambiguous configuration.
    """
    endpoint = normalize_endpoint(value)
    parsed = urlsplit(endpoint)
    if not (parsed.scheme or parsed.netloc):
        return None
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return "绝对 API endpoint 未使用带主机名的 HTTP(S) 地址。"
    if parsed.username or parsed.password:
        return "绝对 API endpoint 不允许携带用户信息。"
    if allowed_targets is None:
        return None
    if not allowed_targets:
        return f"Agent 未登记外部 API 主机 `{parsed.hostname}`。"
    if _endpoint_matches_allowlist(endpoint, allowed_targets):
        return None
    return f"外部 API 主机 `{parsed.hostname}` 不在当前 Agent 的目标白名单中。"


def endpoint_matches_allowlist(value: Any, allowed_targets: list[str] | None) -> bool:
    """Public boolean form used by connectors and redirect checks."""
    return endpoint_allowlist_reason(value, allowed_targets) is None


def endpoint_allowlist_target_is_valid(value: Any) -> bool:
    """Validate an operator-provided allowlist target without exposing its parser."""

    return _parse_allowlist_target(value) is not None


def endpoint_allowlist_target_within_scope(value: Any, allowed_targets: list[str] | None) -> bool:
    """Return whether one allowlist target can only narrow a parent scope."""

    candidate = _parse_allowlist_target(value)
    if candidate is None or not allowed_targets:
        return False
    candidate_scheme, candidate_host, candidate_port = candidate
    for raw_parent in allowed_targets:
        parent = _parse_allowlist_target(raw_parent)
        if parent is None:
            continue
        parent_scheme, parent_host, parent_port = parent
        if parent_scheme is not None and candidate_scheme != parent_scheme:
            continue
        if parent_port is not None and candidate_port != parent_port:
            continue
        if _allowlist_host_within_scope(candidate_host, parent_host):
            return True
    return False


def _allowlist_host_within_scope(candidate: str, parent: str) -> bool:
    if parent.startswith("*."):
        parent_base = parent[2:]
        candidate_base = candidate[2:] if candidate.startswith("*.") else candidate
        return candidate_base.endswith(f".{parent_base}") and candidate_base != parent_base
    return not candidate.startswith("*.") and candidate == parent


def _endpoint_matches_allowlist(endpoint: str, allowed_targets: list[str]) -> bool:
    parsed = urlsplit(endpoint)
    hostname = (parsed.hostname or "").rstrip(".").lower()
    try:
        hostname = hostname.encode("idna").decode("ascii")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except (UnicodeError, ValueError):
        return False
    for raw_target in allowed_targets:
        parsed_target = _parse_allowlist_target(raw_target)
        if parsed_target is None:
            continue
        target_scheme, target_host, target_port = parsed_target
        host_matches = (
            hostname.endswith(f".{target_host[2:]}") and hostname != target_host[2:]
            if target_host.startswith("*.")
            else hostname == target_host
        )
        if host_matches and (target_scheme is None or target_scheme == parsed.scheme) and (
            target_port is None or target_port == port
        ):
            return True
    return False


def _parse_allowlist_target(value: Any) -> tuple[str | None, str, int | None] | None:
    raw = canonical_text(value).lower()
    if not raw:
        return None
    parsed = urlsplit(raw if "://" in raw else f"//{raw}")
    if parsed.username or parsed.password or parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        return None
    hostname = (parsed.hostname or "").rstrip(".")
    if not hostname:
        return None
    wildcard = hostname.startswith("*.")
    base_hostname = hostname[2:] if wildcard else hostname
    if not base_hostname or "*" in base_hostname:
        return None
    try:
        normalized_hostname = base_hostname.encode("idna").decode("ascii")
        port = parsed.port
    except (UnicodeError, ValueError):
        return None
    scheme = parsed.scheme or None
    if scheme is not None and scheme not in {"http", "https"}:
        return None
    return scheme, f"*.{normalized_hostname}" if wildcard else normalized_hostname, port


def resolve_public_endpoint(value: Any, allowed_targets: list[str] | None = None) -> list[str]:
    """Resolve an absolute HTTP(S) endpoint and return only public IPs.

    A connector that later opens a socket must use one returned address as its
    pinned destination while retaining the original hostname for Host/SNI;
    resolving once and then connecting by hostname would reintroduce DNS
    rebinding.
    """
    endpoint = normalize_endpoint(value)
    parsed = urlsplit(endpoint)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("网络执行器只接受带主机名的 HTTP(S) endpoint")
    allowlist_reason = endpoint_allowlist_reason(endpoint, allowed_targets)
    if allowlist_reason:
        raise ValueError(allowlist_reason)
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise ValueError("endpoint 端口无效") from exc
    hostname = parsed.hostname.encode("idna").decode("ascii")
    try:
        literal = ipaddress.ip_address(hostname)
    except ValueError:
        literal = None
    if literal is not None:
        _ensure_public_address(literal, hostname)
        return [str(literal)]
    try:
        infos = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"endpoint 域名解析失败：{hostname}") from exc
    addresses: list[str] = []
    for info in infos:
        address = ipaddress.ip_address(info[4][0])
        _ensure_public_address(address, hostname)
        text = str(address)
        if text not in addresses:
            addresses.append(text)
    if not addresses:
        raise ValueError(f"endpoint 没有可用解析地址：{hostname}")
    return addresses


def resolve_public_redirect_chain(
    initial_endpoint: Any,
    redirect_targets: list[Any] | None = None,
    allowed_targets: list[str] | None = None,
) -> list[list[str]]:
    """Resolve every hop of an HTTP redirect chain under the same boundary.

    The gateway's built-in server executor does not follow external redirects,
    but framework adapters can call this helper before accepting a redirect.
    Every hop is checked for HTTP(S), user-info confusion, restricted/private
    addresses, DNS rebinding, and the Agent host allowlist.
    """
    targets = [initial_endpoint, *(redirect_targets or [])]
    if len(targets) > 10:
        raise ValueError("HTTP redirect chain 超过 10 跳")
    return [resolve_public_endpoint(target, allowed_targets=allowed_targets) for target in targets]


def _ensure_public_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address, hostname: str) -> None:
    if not address.is_global:
        raise ValueError(f"endpoint `{hostname}` 解析到非公网地址 `{address}`")


def _contains_sensitive_endpoint_marker(value: str, markers: set[str]) -> bool:
    effective = markers | {"secret", "secrets", "token", "tokens", "credential", "credentials", ".env"}
    for marker in effective:
        if not marker:
            continue
        if marker == ".env" and marker in value:
            return True
        if re.search(rf"(?<![a-z0-9]){re.escape(marker)}(?![a-z0-9])", value, flags=re.IGNORECASE):
            return True
    return False


def _is_restricted_host(hostname: str) -> bool:
    try:
        hostname = hostname.encode("idna").decode("ascii").rstrip(".").lower()
    except UnicodeError:
        # An invalid IDNA host must not be treated as a public destination.
        return True
    metadata_hosts = {
        "metadata.google.internal",
        "metadata.tencentycloud.com",
        "metadata.azure.internal",
        "metadata.azure.com",
        "metadata",
    }
    local_resolution_suffixes = (
        ".localhost",
        ".local",
        ".localdomain",
        ".nip.io",
        ".sslip.io",
        ".xip.io",
        ".localtest.me",
        ".lvh.me",
    )
    if (
        hostname in metadata_hosts
        or hostname == "localhost"
        or any(hostname.endswith(suffix) for suffix in local_resolution_suffixes)
    ):
        return True
    # Single-label names are normally container/cluster/internal names and do
    # not provide a stable public trust boundary for an Agent HTTP tool.
    if "." not in hostname and hostname not in {"localhost"}:
        return True
    try:
        address = _parse_ip_literal(hostname)
    except ValueError:
        address = None
    if address is None:
        return False
    return bool(address.is_loopback or address.is_private or address.is_link_local or address.is_reserved or address.is_unspecified)


def _parse_ip_literal(hostname: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return cast(ipaddress.IPv4Address | ipaddress.IPv6Address, ipaddress.ip_address(hostname))
    except ValueError:
        pass
    # Cover common integer/hex/octal IPv4 spellings used to bypass string
    # filters (e.g. 2130706433, 0x7f000001, 017700000001).
    if re.fullmatch(r"0[xX][0-9a-fA-F]+|0[0-7]+|[0-9]+", hostname):
        raw = hostname
        base = 16 if raw.lower().startswith("0x") else 8 if raw.startswith("0") and len(raw) > 1 else 10
        value = int(raw, base)
        if 0 <= value <= 0xFFFFFFFF:
            return cast(ipaddress.IPv4Address, ipaddress.ip_address(value))
    # ``inet_aton`` accepts legacy dotted-octal, dotted-hex and shortened
    # IPv4 spellings such as ``0177.0.0.1`` or ``127.1``.  They are valid
    # socket addresses but routinely bypass string-based SSRF filters.
    if re.fullmatch(r"[0-9A-Fa-fxX.]+", hostname) and "." in hostname:
        try:
            packed = socket.inet_aton(hostname)
            return cast(ipaddress.IPv4Address, ipaddress.ip_address(packed))
        except (OSError, ValueError):
            pass
    return None


def normalize_recipients(value: Any) -> str:
    if isinstance(value, (list, tuple, set)):
        raw = ", ".join(canonical_text(item) for item in value)
    else:
        raw = canonical_text(value)
    return raw.replace(";", ",").replace("\r", ",").replace("\n", ",")


def mail_recipient_addresses(value: Any) -> list[str]:
    raw = normalize_recipients(value)
    addresses: list[str] = []
    for _, address in getaddresses([raw]):
        normalized = canonical_text(address).lower()
        if normalized and normalized.count("@") == 1:
            local, domain = normalized.rsplit("@", 1)
            if local and domain and "." in domain and not any(char.isspace() for char in normalized):
                addresses.append(normalized)
    return list(dict.fromkeys(addresses))


def recipients_are_internal(value: Any, internal_domains: set[str] | frozenset[str] | None = None) -> bool:
    raw = normalize_recipients(value)
    parsed = getaddresses([raw])
    if not parsed:
        return False
    recipients: list[str] = []
    for _, address in parsed:
        normalized = canonical_text(address).lower()
        if normalized.count("@") != 1:
            return False
        local, domain = normalized.rsplit("@", 1)
        if not local or "." not in domain or any(char.isspace() for char in normalized):
            return False
        recipients.append(normalized)
    domains = {
        canonical_text(item).lower().lstrip("@")
        for item in (internal_domains or {"internal.example"})
        if canonical_text(item)
    }
    return bool(recipients) and bool(domains) and all(address.rsplit("@", 1)[1] in domains for address in recipients)
