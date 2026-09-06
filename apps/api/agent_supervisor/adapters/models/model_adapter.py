from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import threading
import time
import unicodedata
import urllib.error
import urllib.request
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any, Callable, Iterable
from urllib.parse import unquote, urlencode, urlparse

from apps.api.agent_supervisor.domains.governance.tool_contract import canonical_text_variants

from .model_runtime_config import (
    ALLOWED_PROVIDERS,
    PROFILE_IDS,
    PROVIDER_LABELS,
    effective_provider_priority,
    runtime_model_override,
    runtime_provider_priority,
)

DEFAULT_TIMEOUT_SECONDS = 12
DEFAULT_MAX_PROVIDER_RESPONSE_BYTES = 8 * 1024 * 1024
DEFAULT_PROVIDER_DOH_URL = "https://cloudflare-dns.com/dns-query"
DEFAULT_PROVIDER_DOH_TIMEOUT_SECONDS = 5
DEFAULT_PROVIDER_PROBE_TIMEOUT_SECONDS = 8
MAX_REQUEST_MODEL_CHARS = 200
MAX_STREAM_CHOICES = 16
MAX_STREAM_TOOL_CALLS = 32
class ModelProviderUnavailableError(RuntimeError):
    """Raised when a production model request has no usable provider.

    ``gateway_audit`` is filled by the HTTP gateway, not by the Provider
    adapter.  Keeping the evidence on the exception lets the router return a
    structured 502 without leaking the Provider's raw error body.
    """

    def __init__(
        self,
        message: str,
        failures: list[dict[str, str]] | None = None,
        *,
        gateway_audit: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.failures = failures or []
        self.gateway_audit = gateway_audit if isinstance(gateway_audit, dict) else {}


class ModelProviderStreamCancelledError(RuntimeError):
    """Raised when the downstream client closes an active Provider stream."""

    def __init__(self, message: str, *, gateway_audit: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.gateway_audit = gateway_audit if isinstance(gateway_audit, dict) else {}


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Keep Provider redirects from carrying a prompt and API key elsewhere.

    ``urllib.request.urlopen`` follows 301/302/303/307/308 responses by
    default.  That is a dangerous default for a model gateway: a configured
    Provider, reverse proxy, or compromised endpoint could redirect a POST to a
    different host and receive the same Authorization header and full Agent
    context.  A Provider endpoint must be explicit; redirect policy belongs to
    the gateway, not to the remote server.
    """

    def redirect_request(self, req: urllib.request.Request, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """Connect to one fixed DNS snapshot while retaining the original Host."""

    def __init__(self, host: str, addresses: list[str], *, port: int, timeout: float | None) -> None:
        super().__init__(host, port=port, timeout=timeout)
        self._pinned_addresses = tuple(addresses)
        self.connected_address = ""

    def connect(self) -> None:
        last_error: OSError | None = None
        for address in self._pinned_addresses:
            try:
                self.sock = socket.create_connection((address, self.port), self.timeout, None)
                self.connected_address = address
                return
            except OSError as error:
                last_error = error
        raise last_error or OSError("Provider DNS 解析没有可连接地址")


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS variant: fixed destination IP plus original hostname for SNI."""

    def __init__(
        self,
        host: str,
        addresses: list[str],
        *,
        port: int,
        timeout: float | None,
        context: ssl.SSLContext,
        check_hostname: bool | None = None,
    ) -> None:
        super().__init__(
            host,
            port=port,
            timeout=timeout,
            context=context,
            check_hostname=check_hostname,
        )
        self._context = context
        self._pinned_addresses = tuple(addresses)
        self.connected_address = ""

    def connect(self) -> None:
        last_error: OSError | ssl.SSLError | None = None
        for address in self._pinned_addresses:
            raw_socket: socket.socket | None = None
            try:
                raw_socket = socket.create_connection((address, self.port), self.timeout, None)
                self.sock = self._context.wrap_socket(raw_socket, server_hostname=self.host)
                self.connected_address = address
                return
            except (OSError, ssl.SSLError) as error:
                last_error = error
                if raw_socket is not None:
                    raw_socket.close()
        raise last_error or OSError("Provider DNS 解析没有可连接地址")


class _PinnedHTTPHandler(urllib.request.HTTPHandler):
    """urllib handler that never performs a second DNS lookup."""

    def __init__(self, addresses: list[str], *, port: int, resolver: str) -> None:
        super().__init__()
        self._addresses = list(addresses)
        self._port = port
        self._resolver = resolver
        self._last_connection: _PinnedHTTPConnection | None = None

    def _connection(self, host: str, *, timeout: float | None = None, **_: Any) -> _PinnedHTTPConnection:
        connection = _PinnedHTTPConnection(
            _connection_hostname(host),
            self._addresses,
            port=self._port,
            timeout=timeout,
        )
        self._last_connection = connection
        return connection

    def http_open(self, req: urllib.request.Request) -> Any:
        response = self.do_open(self._connection, req)
        _annotate_provider_response(
            response,
            self._addresses,
            self._last_connection,
            resolver=self._resolver,
        )
        return response


class _PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    """HTTPS urllib handler with fixed IP and hostname-preserving TLS."""

    def __init__(self, addresses: list[str], *, port: int, resolver: str) -> None:
        context = ssl.create_default_context()
        super().__init__(context=context, check_hostname=True)
        self._context = context
        self._check_hostname = True
        self._addresses = list(addresses)
        self._port = port
        self._resolver = resolver
        self._last_connection: _PinnedHTTPSConnection | None = None

    def _connection(
        self,
        host: str,
        *,
        timeout: float | None = None,
        context: ssl.SSLContext | None = None,
        check_hostname: bool | None = None,
        **_: Any,
    ) -> _PinnedHTTPSConnection:
        connection = _PinnedHTTPSConnection(
            _connection_hostname(host),
            self._addresses,
            port=self._port,
            timeout=timeout,
            context=context or self._context or ssl.create_default_context(),
            check_hostname=check_hostname,
        )
        self._last_connection = connection
        return connection

    def https_open(self, req: urllib.request.Request) -> Any:
        response = self.do_open(
            self._connection,
            req,
            context=self._context,
            check_hostname=self._check_hostname,
        )
        _annotate_provider_response(
            response,
            self._addresses,
            self._last_connection,
            resolver=self._resolver,
        )
        return response


def _connection_hostname(host: str) -> str:
    """Remove a Request netloc's port before HTTP Host/SNI formatting."""

    value = str(host or "").strip()
    if value.startswith("[") and "]" in value:
        return value[1 : value.index("]")]
    if value.count(":") == 1:
        candidate, port = value.rsplit(":", 1)
        if port.isdigit():
            return candidate
    return value


def _annotate_provider_response(
    response: Any,
    addresses: list[str],
    connection: _PinnedHTTPConnection | _PinnedHTTPSConnection | None,
    *,
    resolver: str,
) -> None:
    """Attach the exact DNS snapshot used by the HTTP connection."""

    try:
        _attach_provider_network_observation(
            response,
            _provider_network_observation_from_addresses(
                getattr(response, "url", ""),
                addresses,
                connection_pinned=True,
                connected_address=getattr(connection, "connected_address", ""),
                resolver=resolver,
            ),
        )
    except (AttributeError, TypeError, ValueError):
        # Lightweight test doubles and unusual response wrappers may reject
        # arbitrary attributes.  The caller falls back to an observation-only
        # DNS check in that case.
        return


_PROVIDER_NETWORK_OBSERVATION_ATTR = "_agent_supervisor_provider_network_observation"


def _provider_network_observation_from_value(value: Any) -> dict[str, Any]:
    """Read a previously attached route observation from a response/error.

    ``urllib`` exposes non-2xx responses as ``HTTPError`` instances and keeps
    the underlying response in ``HTTPError.fp``.  Both objects are deliberately
    treated as untrusted test/transport wrappers; only a dictionary attached by
    this module is copied into the operator-facing probe result.
    """

    observation = getattr(value, _PROVIDER_NETWORK_OBSERVATION_ATTR, None)
    return dict(observation) if isinstance(observation, dict) else {}


def _attach_provider_network_observation(value: Any, observation: dict[str, Any]) -> None:
    """Attach secret-free route evidence without masking transport errors."""

    if not isinstance(observation, dict) or not observation:
        return
    try:
        setattr(value, _PROVIDER_NETWORK_OBSERVATION_ATTR, dict(observation))
    except (AttributeError, TypeError, ValueError):
        # Some urllib/test wrappers use slots and reject arbitrary attributes.
        # The caller can still inspect the exception itself or fall back to an
        # empty observation; never replace the original transport exception.
        return


def _provider_network_observation_from_error(error: Exception) -> dict[str, Any]:
    """Extract route evidence from an exception and its HTTP response body."""

    observation = _provider_network_observation_from_value(error)
    if observation:
        return observation
    response = getattr(error, "fp", None)
    return _provider_network_observation_from_value(response)


def _provider_unresolved_network_observation(
    endpoint: str,
    *,
    resolver: str,
    error: Exception,
) -> dict[str, Any]:
    """Build route evidence when address resolution fails before connecting."""

    try:
        parsed = urlparse(str(endpoint or ""))
    except ValueError:
        parsed = None
    host = (parsed.hostname if parsed is not None else "") or ""
    hostname_hash = hashlib.sha256(host.strip().rstrip(".").lower().encode("utf-8")).hexdigest()[:16] if host else ""
    return {
        "schema_version": "agent-supervisor.provider-network-observation.v1",
        "checked": False,
        "address_classification": "unresolved",
        "verified_public_route": False,
        "resolved_address_count": 0,
        "public_address_count": 0,
        "private_address_count": 0,
        "hostname_hash": hostname_hash,
        "resolver": resolver,
        "connection_pinned": False,
        "connected_address_hash": "",
        "error": type(error).__name__,
    }


def _provider_open(request: urllib.request.Request, *, timeout: float) -> Any:
    """Open one Provider request with one fixed DNS snapshot.

    The previous implementation observed DNS separately from urllib's socket
    connection. A rebinding response could therefore make the evidence say
    "public" while the request actually reached a different address. Resolve
    once, pass that exact list to the connection class, disable implicit proxy
    discovery, and retain the original hostname for Host/SNI semantics.
    """
    parsed = urlparse(request.full_url)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise urllib.error.URLError("Provider endpoint 必须是 HTTP(S) URL")
    try:
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    except ValueError as error:
        raise urllib.error.URLError("Provider endpoint 端口无效") from error
    resolver = _provider_dns_mode()
    try:
        addresses = _resolve_provider_addresses(parsed.hostname, port, resolver=resolver)
    except Exception as error:  # noqa: BLE001 - preserve the original resolver error
        # There is no usable address snapshot when DNS itself fails.  Still
        # attach a bounded, secret-free observation so a probe can distinguish
        # resolution failure from a response-shape failure.
        unresolved_observation = _provider_unresolved_network_observation(
            str(request.full_url),
            resolver=resolver,
            error=error,
        )
        _attach_provider_network_observation(error, unresolved_observation)
        raise
    if not addresses:
        dns_error = urllib.error.URLError("Provider endpoint DNS 解析为空")
        observation = _provider_network_observation_from_addresses(
            request.full_url,
            [],
            resolver=resolver,
        )
        _attach_provider_network_observation(dns_error, observation)
        raise dns_error
    handler = (
        _PinnedHTTPSHandler(addresses, port=port, resolver=resolver)
        if parsed.scheme.lower() == "https"
        else _PinnedHTTPHandler(addresses, port=port, resolver=resolver)
    )
    # Provider HTTP(S) routing is an explicit administrator configuration. Do
    # not let process-wide proxy environment variables silently move a full
    # Agent prompt and API credential to another intermediary.
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirectHandler(), handler)
        return opener.open(request, timeout=timeout)
    except Exception as error:  # noqa: BLE001 - preserve the original transport/HTTP error
        # ``HTTPError`` may already carry the annotation on ``fp``.  Keep that
        # exact response snapshot when present; otherwise attach the addresses
        # pinned for this attempt to both the exception and its response.
        connection = getattr(handler, "_last_connection", None)
        observation = _provider_network_observation_from_addresses(
            request.full_url,
            addresses,
            connection_pinned=True,
            connected_address=getattr(connection, "connected_address", ""),
            resolver=resolver,
        )
        if not _provider_network_observation_from_error(error):
            _attach_provider_network_observation(error, observation)
        response = getattr(error, "fp", None)
        if response is not None and not _provider_network_observation_from_value(response):
            _attach_provider_network_observation(response, observation)
        raise


def provider_endpoint_scope(endpoint: str) -> str:
    """Classify the Provider route without exposing its address.

    Gateway evidence must distinguish a local protocol fixture or local model
    gateway from an externally hosted Provider. This is deliberately a
    syntactic classification: it never resolves DNS and does not claim that a
    public hostname is trustworthy.
    """

    try:
        parsed = urlparse(str(endpoint or ""))
    except ValueError:
        return "invalid-provider-endpoint"
    if parsed.scheme.lower() not in {"http", "https"}:
        return "non-http-provider"
    host = (parsed.hostname or "").strip().rstrip(".").lower()
    if not host:
        return "invalid-provider-endpoint"
    if host == "localhost":
        return "local-network-provider"
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        # A hostname may still resolve to a private address at runtime. Do not
        # overclaim: only literal loopback/private addresses get the local
        # classification here.
        return "external-or-hostname-provider"
    if address.is_loopback or address.is_private or address.is_link_local or address.is_unspecified:
        return "local-network-provider"
    return "external-provider"


def _address_is_public(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Return whether an address is suitable as a public-route observation.

    ``ipaddress.is_private`` alone is not enough for evidence: documentation,
    benchmarking, multicast and otherwise reserved ranges must not be counted
    as proof that a Provider is publicly reachable.
    """

    return not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_unspecified
        or address.is_reserved
        or address.is_multicast
    )


def _provider_network_observation_from_addresses(
    endpoint: str,
    addresses: Iterable[str],
    *,
    connection_pinned: bool = False,
    connected_address: str = "",
    resolver: str = "system",
) -> dict[str, Any]:
    """Build secret-free route evidence from one already-resolved address set."""

    try:
        parsed = urlparse(str(endpoint or ""))
    except ValueError:
        parsed = None
    host = (parsed.hostname if parsed is not None else "") or ""
    hostname_hash = hashlib.sha256(host.strip().rstrip(".").lower().encode("utf-8")).hexdigest()[:16] if host else ""
    parsed_addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for value in addresses:
        try:
            candidate = ipaddress.ip_address(str(value).strip())
        except ValueError:
            continue
        if candidate not in parsed_addresses:
            parsed_addresses.append(candidate)
    public_count = sum(1 for address in parsed_addresses if _address_is_public(address))
    private_count = len(parsed_addresses) - public_count
    if not parsed_addresses:
        classification = "unresolved"
    elif public_count and private_count:
        classification = "mixed"
    elif public_count:
        classification = "public"
    else:
        classification = "private-or-local"
    return {
        "schema_version": "agent-supervisor.provider-network-observation.v1",
        "checked": bool(parsed_addresses),
        "address_classification": classification,
        "verified_public_route": bool(public_count and not private_count),
        "resolved_address_count": len(parsed_addresses),
        "public_address_count": public_count,
        "private_address_count": private_count,
        "hostname_hash": hostname_hash,
        "resolver": resolver,
        "connection_pinned": bool(connection_pinned),
        "connected_address_hash": (
            hashlib.sha256(str(connected_address).encode("utf-8")).hexdigest()[:16] if connected_address else ""
        ),
        "error": "" if parsed_addresses else "unresolved",
    }


def _provider_dns_mode() -> str:
    """Return the explicitly selected resolver for Provider connections."""

    value = os.getenv("AGENT_SUPERVISOR_PROVIDER_DNS_MODE", "system").strip().lower()
    return value if value in {"system", "doh"} else "system"


def _provider_doh_url() -> str:
    """Return a validated HTTPS DNS-over-HTTPS endpoint."""

    candidate = os.getenv("AGENT_SUPERVISOR_PROVIDER_DOH_URL", DEFAULT_PROVIDER_DOH_URL).strip()
    try:
        parsed = urlparse(candidate)
    except ValueError:
        parsed = None
    if parsed is None or parsed.scheme.lower() != "https" or not parsed.hostname:
        return DEFAULT_PROVIDER_DOH_URL
    return candidate.rstrip("?")


def _provider_doh_timeout() -> float:
    raw = os.getenv(
        "AGENT_SUPERVISOR_PROVIDER_DOH_TIMEOUT_SECONDS",
        str(DEFAULT_PROVIDER_DOH_TIMEOUT_SECONDS),
    ).strip()
    try:
        value = float(raw)
    except ValueError:
        return float(DEFAULT_PROVIDER_DOH_TIMEOUT_SECONDS)
    return max(1.0, min(value, 15.0))


def _resolve_provider_addresses_via_doh(host: str) -> list[str]:
    """Resolve a Provider hostname through an explicit DoH endpoint.

    The returned addresses are the same snapshot later used by the pinned
    socket connection. CNAME records are intentionally ignored; only A and
    AAAA answer data can become a connection destination.
    """

    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        return [str(literal)]

    endpoint = _provider_doh_url()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirectHandler())
    addresses: set[str] = set()
    for query_type in ("A", "AAAA"):
        separator = "&" if "?" in endpoint else "?"
        query_url = f"{endpoint}{separator}{urlencode({'name': host, 'type': query_type})}"
        request = urllib.request.Request(
            query_url,
            headers={
                "Accept": "application/dns-json",
                "User-Agent": "agent-supervisor-provider-resolver/1",
            },
            method="GET",
        )
        with opener.open(request, timeout=_provider_doh_timeout()) as response:
            raw = response.read(64 * 1024)
        document = json.loads(raw)
        if not isinstance(document, dict):
            raise ValueError("DoH 响应顶层不是对象")
        answers = document.get("Answer", [])
        if not isinstance(answers, list):
            continue
        expected_type = 1 if query_type == "A" else 28
        for answer in answers:
            if not isinstance(answer, dict) or answer.get("type") != expected_type:
                continue
            data = answer.get("data")
            try:
                address = ipaddress.ip_address(str(data).strip())
            except ValueError:
                continue
            addresses.add(str(address))
    if not addresses:
        raise OSError("DoH 解析没有返回 A/AAAA 地址")
    return sorted(addresses)


def _resolve_provider_addresses(host: str, port: int, *, resolver: str | None = None) -> list[str]:
    """Resolve a Provider hostname once for the actual outbound connection."""

    selected_resolver = resolver or _provider_dns_mode()
    if selected_resolver == "doh":
        return _resolve_provider_addresses_via_doh(host)

    raw_results = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    addresses: set[str] = set()
    for item in raw_results:
        try:
            candidate = str(item[4][0]).strip()
            ipaddress.ip_address(candidate)
        except (IndexError, KeyError, TypeError, ValueError):
            continue
        addresses.add(candidate)
    return sorted(addresses)


@lru_cache(maxsize=64)
def _provider_network_observation_cached(endpoint: str, resolver: str) -> dict[str, Any]:
    """Resolve one configured Provider route into secret-free evidence.

    This is an observation only.  It does not alter the HTTP connection or
    claim that the resolved address belongs to a particular vendor.  The
    endpoint is administrator configuration, not Agent input; the result is
    cached for the lifetime of the API process so a request does not perform a
    second DNS lookup on every round.
    """

    try:
        parsed = urlparse(str(endpoint or ""))
    except ValueError:
        return {
            "schema_version": "agent-supervisor.provider-network-observation.v1",
            "checked": False,
            "address_classification": "invalid",
            "verified_public_route": False,
            "resolved_address_count": 0,
            "public_address_count": 0,
            "private_address_count": 0,
            "hostname_hash": "",
            "resolver": resolver,
            "error": "invalid-endpoint",
        }
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return {
            "schema_version": "agent-supervisor.provider-network-observation.v1",
            "checked": False,
            "address_classification": "non-http",
            "verified_public_route": False,
            "resolved_address_count": 0,
            "public_address_count": 0,
            "private_address_count": 0,
            "hostname_hash": "",
            "resolver": resolver,
            "error": "non-http-or-missing-host",
        }

    host = parsed.hostname.strip().rstrip(".").lower()
    hostname_hash = hashlib.sha256(host.encode("utf-8")).hexdigest()[:16]
    try:
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        addresses = _resolve_provider_addresses(host, port, resolver=resolver)
    except (OSError, ValueError, urllib.error.URLError, TimeoutError) as error:
        return {
            "schema_version": "agent-supervisor.provider-network-observation.v1",
            "checked": False,
            "address_classification": "unresolved",
            "verified_public_route": False,
            "resolved_address_count": 0,
            "public_address_count": 0,
            "private_address_count": 0,
            "hostname_hash": hostname_hash,
            "resolver": resolver,
            "error": type(error).__name__,
        }

    result = _provider_network_observation_from_addresses(endpoint, addresses, resolver=resolver)
    result["checked"] = True
    result["hostname_hash"] = hostname_hash
    return result


def provider_network_observation(endpoint: str) -> dict[str, Any]:
    """Return cached, non-secret DNS route evidence for a Provider endpoint."""

    return dict(_provider_network_observation_cached(str(endpoint or ""), _provider_dns_mode()))


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _timeout() -> float:
    raw = os.getenv("MODEL_TIMEOUT_SECONDS", str(DEFAULT_TIMEOUT_SECONDS))
    try:
        return max(2.0, float(raw))
    except ValueError:
        return float(DEFAULT_TIMEOUT_SECONDS)


def _max_provider_response_bytes() -> int:
    raw = os.getenv("MODEL_MAX_PROVIDER_RESPONSE_BYTES", str(DEFAULT_MAX_PROVIDER_RESPONSE_BYTES))
    try:
        value = int(raw)
    except ValueError:
        value = DEFAULT_MAX_PROVIDER_RESPONSE_BYTES
    return max(64 * 1024, min(value, 64 * 1024 * 1024))


def _read_bounded_provider_response(response: Any) -> str:
    """Read a provider response with an explicit memory bound.

    Transparent proxying buffers the provider result before tool-call and output
    enforcement.  Without a cap, a provider or compromised upstream can turn a
    single request into unbounded memory growth.  The TypeError fallback keeps
    lightweight test doubles compatible while real HTTP responses use bounded
    ``read`` directly.
    """
    limit = _max_provider_response_bytes()
    headers = getattr(response, "headers", None)
    content_length = None
    if headers is not None:
        try:
            content_length = headers.get("Content-Length")
        except AttributeError:
            content_length = None
    if content_length:
        try:
            if int(content_length) > limit:
                raise ValueError(f"模型供应商响应超过 {limit} 字节上限")
        except ValueError as exc:
            if "上限" in str(exc):
                raise
    try:
        raw_bytes = response.read(limit + 1)
    except TypeError:
        raw_bytes = response.read()
    if isinstance(raw_bytes, str):
        raw = raw_bytes
        if len(raw.encode("utf-8", errors="replace")) > limit:
            raise ValueError(f"模型供应商响应超过 {limit} 字节上限")
        return raw
    if len(raw_bytes) > limit:
        raise ValueError(f"模型供应商响应超过 {limit} 字节上限")
    return bytes(raw_bytes).decode("utf-8", errors="replace")


def _load_provider_json(raw: str) -> Any:
    """Parse one Provider envelope without duplicate-key differentials.

    A compromised or incompatible endpoint can return duplicate JSON keys. The
    gateway must not validate one value while a downstream SDK interprets the
    other, so duplicate objects and non-finite JSON constants fail closed at the
    Provider boundary.
    """

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Provider 响应包含重复 JSON 字段")
            result[key] = value
        return result

    def reject_non_finite(value: str) -> Any:
        raise ValueError(f"Provider 响应包含非有限数字：{value}")

    return json.loads(raw, object_pairs_hook=reject_duplicates, parse_constant=reject_non_finite)


def _first_provider_chat_choice(parsed: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    if not isinstance(parsed, dict):
        raise ValueError("模型供应商响应 JSON 顶层不是对象")
    choices = parsed.get("choices")
    if not isinstance(choices, list) or not choices:
        raise ValueError("模型供应商响应缺少 choices")
    choice = choices[0]
    if not isinstance(choice, dict):
        raise ValueError("模型供应商响应 choice 不是对象")
    message = choice.get("message")
    if not isinstance(message, dict):
        raise ValueError("模型供应商响应 choice.message 不是对象")
    return choice, message


def _provider_message_text(message: dict[str, Any], *, required: bool = False) -> str:
    content = message.get("content")
    if content is None:
        text = ""
    elif isinstance(content, str):
        text = content.strip()
    else:
        raise ValueError("模型供应商响应 message.content 必须是字符串或 null")
    if required and not text:
        raise ValueError("模型供应商响应未返回文本内容")
    return text


def _profile_env(profile: str, name: str, default: str = "") -> str:
    normalized = profile.strip().upper().replace("-", "_")
    if normalized:
        scoped = os.getenv(f"{normalized}_{name}")
        if scoped is not None and scoped.strip():
            return scoped
    return os.getenv(name, default)


def _provider_priority(profile: str = "") -> list[str]:
    normalized = profile.strip().lower()
    scoped_name = profile.strip().upper().replace("-", "_")
    runtime_priority = runtime_provider_priority(normalized)
    if runtime_priority:
        return runtime_priority
    scoped_priority = os.getenv(f"{scoped_name}_MODEL_PROVIDER_PRIORITY") if scoped_name else None
    if scoped_priority and scoped_priority.strip():
        configured = scoped_priority
    elif normalized == "optimizer":
        configured = "zhipu,deepseek,openai-compatible"
    elif normalized == "target":
        configured = "deepseek,zhipu,openai-compatible"
    else:
        configured = os.getenv("MODEL_PROVIDER_PRIORITY", "openai-compatible,deepseek,zhipu")
    return effective_provider_priority(normalized, configured)


def _deepseek_endpoint(profile: str = "") -> str:
    base_url = _profile_env(profile, "DEEPSEEK_BASE_URL", "https://api.deepseek.com").rstrip("/")
    return f"{base_url}/chat/completions"


def _zhipu_endpoint(profile: str = "") -> str:
    return _profile_env(
        profile,
        "ZHIPU_API_URL",
        "https://open.bigmodel.cn/api/paas/v4/chat/completions",
    )


def _openai_compatible_endpoint(profile: str = "") -> str:
    base_url = _profile_env(
        profile,
        "OPENAI_COMPATIBLE_BASE_URL",
        os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1"),
    ).rstrip("/")
    return f"{base_url}/chat/completions"


def provider_status(profile: str = "") -> list[dict]:
    openai_compatible_key = bool(_profile_env(profile, "OPENAI_COMPATIBLE_API_KEY", os.getenv("OPENAI_API_KEY", "")))
    deepseek_key = bool(_profile_env(profile, "DEEPSEEK_API_KEY", ""))
    zhipu_key = bool(_profile_env(profile, "ZHIPU_API_KEY", ""))
    profile_label = profile.strip() or "global"
    openai_compatible_model = runtime_model_override(profile, "openai-compatible") or _profile_env(
        profile,
        "OPENAI_COMPATIBLE_MODEL",
        os.getenv("OPENAI_MODEL", "gpt-4.1-mini"),
    )
    deepseek_model = runtime_model_override(profile, "deepseek") or _profile_env(
        profile,
        "DEEPSEEK_MODEL",
        "deepseek-v4-pro",
    )
    zhipu_model = runtime_model_override(profile, "zhipu") or _profile_env(
        profile,
        "ZHIPU_MODEL",
        "glm-4.6v-flashx",
    )
    return [
        {
            "provider_id": "openai-compatible",
            "profile": profile_label,
            "provider": "OpenAI 兼容接口",
            "configured": openai_compatible_key,
            "model": openai_compatible_model,
            "endpoint": _openai_compatible_endpoint(profile),
            "mode": "real-api" if openai_compatible_key else "unconfigured",
        },
        {
            "provider_id": "deepseek",
            "profile": profile_label,
            "provider": "DeepSeek",
            "configured": deepseek_key,
            "model": deepseek_model,
            "endpoint": _deepseek_endpoint(profile),
            "mode": "real-api" if deepseek_key else "unconfigured",
        },
        {
            "provider_id": "zhipu",
            "profile": profile_label,
            "provider": "智谱",
            "configured": zhipu_key,
            "model": zhipu_model,
            "endpoint": _zhipu_endpoint(profile),
            "mode": "real-api" if zhipu_key else "unconfigured",
        },
    ]


def normalize_provider_selector(value: str) -> str:
    """Normalize a Provider selector to a stable id."""
    normalized = str(value or "").strip().lower()
    if not normalized:
        return ""
    if normalized in ALLOWED_PROVIDERS:
        return normalized
    for provider_id, label in PROVIDER_LABELS.items():
        if normalized == str(label).strip().lower():
            return provider_id
    aliases = {
        "openai": "openai-compatible",
        "openai compatible": "openai-compatible",
        "openai兼容": "openai-compatible",
        "openai 兼容接口": "openai-compatible",
        "deep seek": "deepseek",
        "zhipuai": "zhipu",
        "glm": "zhipu",
    }
    return aliases.get(normalized, "")


def _safe_error_message(error: Exception) -> str:
    """Return a bounded, non-reflective Provider failure description.

    Provider error bodies are untrusted model-adjacent input.  A compatible
    endpoint can echo the submitted prompt, credentials, or an instruction in
    an HTTP error body; returning that body through ``provider_failures`` would
    create a second prompt-injection channel even though no completion was
    produced.  Keep the operator-useful class/status and leave the raw failure
    available only to the local process diagnostics.
    """
    if isinstance(error, urllib.error.HTTPError):
        return f"Provider HTTP 请求失败（状态 {int(error.code)}）"
    if _is_provider_timeout_error(error):
        return "Provider 请求超时"
    if isinstance(error, urllib.error.URLError):
        return "Provider 网络连接失败"
    if isinstance(error, ValueError):
        # Preserve stable categories used by the console/tests without echoing
        # the exception text (which can include a Provider response body).
        message = str(error).lower()
        if "超过" in message or "上限" in message or "size" in message or "bytes" in message:
            return "Provider 响应超过网关大小上限"
        if "json" in message or "响应" in message or "choice" in message:
            return "Provider 响应格式校验失败"
        return "Provider 请求参数或响应校验失败"
    return "Provider 请求失败"


def _provider_error_retryable(error: Exception) -> bool:
    """Only retry another provider for transport/throttle/server failures.

    Authentication, request-shape, and policy errors must not fan a user's
    prompt out to every configured provider.
    """
    if isinstance(error, urllib.error.HTTPError):
        return error.code in {408, 425, 429} or error.code >= 500
    return isinstance(error, (urllib.error.URLError, TimeoutError, socket.timeout))


def _proxy_provider_failover_enabled() -> bool:
    """Require an explicit opt-in before sending one prompt to another provider.

    A transport timeout does not prove that the first provider did not receive
    the request.  Silent failover would therefore duplicate private prompts and
    tool schemas across vendors.  Production transparent proxying stays
    single-provider by default; operators can opt in after accepting that
    privacy trade-off.
    """
    return _env_bool("AGENT_SUPERVISOR_PROXY_ALLOW_PROVIDER_FAILOVER", False)


def _payload_hash(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()
def _provider_probe_timeout() -> float:
    raw = os.getenv(
        "MODEL_PROVIDER_PROBE_TIMEOUT_SECONDS",
        str(DEFAULT_PROVIDER_PROBE_TIMEOUT_SECONDS),
    ).strip()
    try:
        value = float(raw)
    except ValueError:
        value = float(DEFAULT_PROVIDER_PROBE_TIMEOUT_SECONDS)
    return max(1.0, min(value, 15.0))


def _is_provider_timeout_error(error: Exception) -> bool:
    """Recognize socket timeouts after urllib wraps them in URLError."""

    if isinstance(error, (socket.timeout, TimeoutError)):
        return True
    if isinstance(error, urllib.error.URLError):
        return isinstance(getattr(error, "reason", None), (socket.timeout, TimeoutError))
    return False


def _provider_probe_failure_code(error: Exception) -> str:
    if isinstance(error, urllib.error.HTTPError):
        if error.code in {401, 403}:
            return "authentication-failed"
        if error.code == 429:
            return "rate-limited"
        if error.code >= 500:
            return "provider-error"
        return "http-error"
    if _is_provider_timeout_error(error):
        return "timeout"
    if isinstance(error, urllib.error.URLError):
        return "network-error"
    if isinstance(error, ValueError):
        return "invalid-response"
    return "probe-error"


def probe_provider(profile: str = "target", provider_id: str = "") -> dict[str, Any]:
    """Perform one explicit, low-output request against one configured Provider.

    Configuration discovery only answers whether a key exists.  This probe
    sends a one-token chat request through the same pinned transport as normal
    traffic, then returns hashes and bounded metadata rather than Provider
    content.  It never falls back to another Provider or the local simulator.
    """

    normalized_profile = str(profile or "").strip().lower()
    if normalized_profile not in PROFILE_IDS:
        raise ValueError("Provider 探针 profile 无效")
    normalized_provider = normalize_provider_selector(provider_id)
    if normalized_provider not in ALLOWED_PROVIDERS:
        raise ValueError("Provider 探针 provider_id 无效")

    configs = list(_iter_configured_providers(normalized_profile, provider_id=normalized_provider))
    base: dict[str, Any] = {
        "schema_version": "agent-supervisor.provider-probe.v1",
        "profile": normalized_profile,
        "provider_id": normalized_provider,
        "provider": PROVIDER_LABELS.get(normalized_provider, normalized_provider),
        "status": "unconfigured",
        "configured": False,
        "model": "",
        "endpoint_scope": "",
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "latency_ms": None,
        "http_status": None,
        "request_hash": "",
        "response_hash": "",
        "network_observation": {},
        "error_code": "not-configured",
        "error": "当前 profile 未配置该 Provider 凭证。",
    }
    if not configs:
        return base

    config = configs[0]
    model = str(config.get("model") or "").strip()
    endpoint = str(config.get("endpoint") or "").strip()
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": "health check"}],
        "temperature": 0,
        "max_tokens": 1,
        "stream": False,
    }
    request_hash = _payload_hash(payload)
    request = urllib.request.Request(
        endpoint,
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {config['api_key']}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    started = time.perf_counter()
    base.update(
        {
            "configured": True,
            "model": model,
            "endpoint_scope": provider_endpoint_scope(endpoint),
            "request_hash": request_hash,
            "error_code": "",
            "error": "",
        }
    )
    try:
        with _provider_open(request, timeout=_provider_probe_timeout()) as response:
            base["http_status"] = int(getattr(response, "status", 0) or 0) or None
            # Capture the route as soon as the response exists.  Reading the
            # body or validating JSON can fail, but those failures must not
            # erase the exact DNS snapshot and pinned connection evidence.
            base["network_observation"] = _provider_network_observation_from_value(response)
            raw = _read_bounded_provider_response(response)
            parsed = _load_provider_json(raw)
            _first_provider_chat_choice(parsed)
        base.update(
            {
                "status": "healthy",
                "response_hash": hashlib.sha256(raw.encode("utf-8")).hexdigest(),
                "latency_ms": round((time.perf_counter() - started) * 1000, 2),
            }
        )
        return base
    except Exception as error:  # noqa: BLE001 - return a bounded operator result
        if isinstance(error, urllib.error.HTTPError):
            try:
                base["http_status"] = int(error.code)
            except (AttributeError, TypeError, ValueError):
                pass
        if not base["network_observation"]:
            base["network_observation"] = _provider_network_observation_from_error(error)
        base.update(
            {
                "status": "unhealthy",
                "error_code": _provider_probe_failure_code(error),
                "error": _safe_error_message(error),
                "latency_ms": round((time.perf_counter() - started) * 1000, 2),
            }
        )
        return base


def _stream_cancelled(cancel_event: Any) -> bool:
    return bool(cancel_event is not None and callable(getattr(cancel_event, "is_set", None)) and cancel_event.is_set())


def _read_provider_sse_event(
    response: Any,
    *,
    cancel_event: Any = None,
) -> Iterable[tuple[str, bytes]]:
    """Yield bounded SSE data payloads together with the exact wire bytes.

    Chat Completions streaming uses ordinary Server-Sent Events.  Parsing the
    framing here, instead of splitting arbitrary TCP chunks in the gateway,
    keeps JSON objects intact and lets the caller assemble tool arguments only
    after every delta has arrived.
    """

    limit = _max_provider_response_bytes()
    total_bytes = 0
    data_lines: list[str] = []
    while True:
        if _stream_cancelled(cancel_event):
            raise ModelProviderStreamCancelledError("下游客户端已取消模型流。")
        try:
            raw_line = response.readline(limit + 1)
        except TypeError:
            raw_line = response.readline()
        if raw_line in {b"", ""}:
            if data_lines:
                yield "\n".join(data_lines), b""
            return
        encoded_line = raw_line.encode("utf-8") if isinstance(raw_line, str) else bytes(raw_line)
        total_bytes += len(encoded_line)
        if total_bytes > limit:
            raise ValueError(f"模型供应商流式响应超过 {limit} 字节上限")
        if len(encoded_line) > limit:
            raise ValueError(f"模型供应商流式响应单帧超过 {limit} 字节上限")
        try:
            line = encoded_line.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("模型供应商流式响应不是有效 UTF-8") from exc
        line = line.rstrip("\r\n")
        if not line:
            if data_lines:
                yield "\n".join(data_lines), encoded_line
                data_lines = []
            else:
                yield "", encoded_line
            continue
        if line.startswith(":"):
            yield "", encoded_line
            continue
        if line.startswith("data:"):
            data_lines.append(line[5:].lstrip(" "))
            yield "", encoded_line
            continue
        if line.startswith(("event:", "id:", "retry:")):
            yield "", encoded_line
            continue
        raise ValueError("模型供应商流式响应包含无效 SSE 字段")


def _append_stream_text(container: dict[str, Any], key: str, value: Any) -> None:
    if value is None:
        return
    if not isinstance(value, str):
        raise ValueError(f"模型供应商流式 delta.{key} 必须是字符串或 null")
    container[key] = str(container.get(key) or "") + value


def _merge_stream_tool_calls(message: dict[str, Any], value: Any) -> None:
    if not isinstance(value, list):
        raise ValueError("模型供应商流式 delta.tool_calls 必须是数组")
    tool_calls = message.setdefault("tool_calls", [])
    if not isinstance(tool_calls, list):
        raise ValueError("模型供应商流式工具调用聚合状态无效")
    for item in value:
        if not isinstance(item, dict):
            raise ValueError("模型供应商流式 tool_call 必须是对象")
        raw_index = item.get("index")
        if not isinstance(raw_index, int) or isinstance(raw_index, bool) or raw_index < 0 or raw_index >= MAX_STREAM_TOOL_CALLS:
            raise ValueError("模型供应商流式 tool_call.index 无效")
        while len(tool_calls) <= raw_index:
            tool_calls.append({"id": "", "type": "function", "function": {"name": "", "arguments": ""}})
        target = tool_calls[raw_index]
        raw_id = item.get("id")
        if raw_id is not None:
            if not isinstance(raw_id, str):
                raise ValueError("模型供应商流式 tool_call.id 必须是字符串")
            target["id"] = str(target.get("id") or "") + raw_id
        raw_type = item.get("type")
        if raw_type is not None:
            if raw_type != "function":
                raise ValueError("模型供应商流式 tool_call.type 只支持 function")
            target["type"] = "function"
        function = item.get("function")
        if function is not None:
            if not isinstance(function, dict):
                raise ValueError("模型供应商流式 tool_call.function 必须是对象")
            target_function = target.setdefault("function", {})
            _append_stream_text(target_function, "name", function.get("name"))
            _append_stream_text(target_function, "arguments", function.get("arguments"))


def _merge_stream_function_call(message: dict[str, Any], value: Any) -> None:
    if not isinstance(value, dict):
        raise ValueError("模型供应商流式 delta.function_call 必须是对象")
    target = message.setdefault("function_call", {})
    if not isinstance(target, dict):
        raise ValueError("模型供应商流式 function_call 聚合状态无效")
    _append_stream_text(target, "name", value.get("name"))
    _append_stream_text(target, "arguments", value.get("arguments"))


def _consume_openai_chat_completion_stream(
    response: Any,
    *,
    on_chunk: Callable[[dict[str, Any]], None],
    cancel_event: Any = None,
) -> tuple[dict[str, Any], str, int]:
    """Consume Provider SSE, emit validated chunks, and build one final envelope."""

    response_hash = hashlib.sha256()
    choice_states: dict[int, dict[str, Any]] = {}
    response_envelope: dict[str, Any] = {"object": "chat.completion", "choices": []}
    extensions: list[dict[str, Any]] = []
    saw_done = False
    chunk_count = 0
    pending_data = ""

    for data, wire_bytes in _read_provider_sse_event(response, cancel_event=cancel_event):
        response_hash.update(wire_bytes)
        if not data:
            continue
        pending_data = data
        if data == "[DONE]":
            saw_done = True
            break
        chunk = _load_provider_json(data)
        if not isinstance(chunk, dict):
            raise ValueError("模型供应商流式事件 JSON 顶层不是对象")
        chunk_count += 1
        if chunk_count > 100_000:
            raise ValueError("模型供应商流式事件数量超过安全上限")
        raw_choices = chunk.get("choices")
        if not isinstance(raw_choices, list):
            raise ValueError("模型供应商流式事件缺少 choices 数组")
        if len(raw_choices) > MAX_STREAM_CHOICES:
            raise ValueError("模型供应商流式事件 choices 超过安全上限")

        for key in ("id", "created", "model", "system_fingerprint", "service_tier"):
            if key in chunk and key not in response_envelope:
                response_envelope[key] = chunk[key]
        if isinstance(chunk.get("usage"), dict):
            response_envelope["usage"] = chunk["usage"]
        extension = {key: value for key, value in chunk.items() if key not in {"id", "object", "created", "model", "choices", "usage"}}
        if extension:
            extensions.append(extension)

        for raw_choice in raw_choices:
            if not isinstance(raw_choice, dict):
                raise ValueError("模型供应商流式 choice 必须是对象")
            index = raw_choice.get("index")
            if not isinstance(index, int) or isinstance(index, bool) or index < 0 or index >= MAX_STREAM_CHOICES:
                raise ValueError("模型供应商流式 choice.index 无效")
            state = choice_states.setdefault(
                index,
                {"index": index, "message": {"role": "assistant", "content": ""}, "finish_reason": None},
            )
            delta = raw_choice.get("delta")
            if not isinstance(delta, dict):
                raise ValueError("模型供应商流式 choice.delta 必须是对象")
            message = state["message"]
            role = delta.get("role")
            if role is not None:
                if role != "assistant":
                    raise ValueError("模型供应商流式 delta.role 必须是 assistant")
                message["role"] = "assistant"
            _append_stream_text(message, "content", delta.get("content"))
            _append_stream_text(message, "refusal", delta.get("refusal"))
            for reasoning_key in ("reasoning_content", "reasoning", "analysis"):
                _append_stream_text(message, reasoning_key, delta.get(reasoning_key))
            if "tool_calls" in delta:
                _merge_stream_tool_calls(message, delta["tool_calls"])
            if "function_call" in delta:
                _merge_stream_function_call(message, delta["function_call"])
            if raw_choice.get("finish_reason") is not None:
                state["finish_reason"] = raw_choice["finish_reason"]
            if "logprobs" in raw_choice:
                state["logprobs"] = raw_choice["logprobs"]
        on_chunk(chunk)

    if not saw_done:
        suffix = f"（最后事件：{pending_data[:40]}）" if pending_data else ""
        raise ValueError(f"模型供应商流式响应在 [DONE] 前中断{suffix}")
    if not choice_states:
        raise ValueError("模型供应商流式响应没有生成任何 choice")
    response_envelope["choices"] = [choice_states[index] for index in sorted(choice_states)]
    if extensions:
        response_envelope["stream_extensions"] = extensions
    return response_envelope, response_hash.hexdigest(), chunk_count


def forward_openai_chat_completion(
    payload: dict[str, Any],
    *,
    provider_profile: str = "target",
    model_override: str = "",
    stream_callback: Callable[[dict[str, Any]], None] | None = None,
    stream_cancel_event: Any = None,
) -> dict[str, Any]:
    """Forward an OpenAI-compatible request without changing its prompt contract.

    The proxy security boundary must not rebuild messages, discard tool schemas, or
    silently switch to the local simulator.  This function sends the caller's
    standard OpenAI fields as-is (apart from the internal ``agent_supervisor``
    extension and the selected model) and returns provider evidence separately.
    """
    if not isinstance(payload, dict):
        raise ValueError("OpenAI 兼容请求必须是 JSON 对象")
    messages = payload.get("messages")
    if not isinstance(messages, list) or not messages:
        raise ValueError("OpenAI 兼容请求必须包含非空 messages 数组")

    outbound = dict(payload)
    outbound.pop("agent_supervisor", None)
    outbound["stream"] = stream_callback is not None
    failures: list[dict[str, str]] = []

    raw_model = payload.get("model")
    requested_model = str(model_override or raw_model or "").strip()
    if not requested_model:
        raise ValueError("OpenAI 兼容请求必须包含非空 model 字符串")
    if not model_override and not isinstance(raw_model, str):
        raise ValueError("OpenAI 兼容请求必须包含非空 model 字符串")
    if len(requested_model) > MAX_REQUEST_MODEL_CHARS:
        raise ValueError(f"model 不能超过 {MAX_REQUEST_MODEL_CHARS} 个字符")
    for config in _iter_configured_providers(provider_profile, requested_model=requested_model):
        outbound_for_provider = dict(outbound)
        outbound_for_provider["model"] = model_override or str(payload.get("model") or config["model"])
        request = urllib.request.Request(
            config["endpoint"],
            data=json.dumps(outbound_for_provider, ensure_ascii=False).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {config['api_key']}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        provider_stream_started = False
        try:
            with _provider_open(request, timeout=_timeout()) as response:
                observed_network = getattr(response, "_agent_supervisor_provider_network_observation", None)
                if stream_callback is not None:
                    headers = getattr(response, "headers", None)
                    content_type = str(headers.get("Content-Type") or "") if headers is not None else ""
                    if not content_type.lower().startswith("text/event-stream"):
                        raise ValueError("模型供应商未返回 text/event-stream 流式响应")

                    def observe_chunk(chunk: dict[str, Any]) -> None:
                        nonlocal provider_stream_started
                        provider_stream_started = True
                        stream_callback(chunk)

                    stream_finished = threading.Event()

                    def close_provider_on_cancel(
                        finished: threading.Event = stream_finished,
                        provider_response: Any = response,
                    ) -> None:
                        while not finished.wait(0.1):
                            if _stream_cancelled(stream_cancel_event):
                                try:
                                    provider_response.close()
                                except (AttributeError, OSError, ValueError):
                                    pass
                                return

                    cancel_watcher = threading.Thread(
                        target=close_provider_on_cancel,
                        daemon=True,
                        name="provider-stream-cancel",
                    )
                    cancel_watcher.start()
                    try:
                        parsed, provider_response_hash, provider_chunk_count = _consume_openai_chat_completion_stream(
                            response,
                            on_chunk=observe_chunk,
                            cancel_event=stream_cancel_event,
                        )
                    finally:
                        stream_finished.set()
                    raw = ""
                else:
                    raw = _read_bounded_provider_response(response)
                    parsed = _load_provider_json(raw)
                    provider_response_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()
                    provider_chunk_count = 0
            if not isinstance(parsed, dict):
                raise ValueError("模型供应商返回的 JSON 顶层不是对象")
            choices = parsed.get("choices")
            if not isinstance(choices, list) or not choices:
                raise ValueError("模型供应商响应缺少 choices")
            evidence = {
                "request_hash": _payload_hash(outbound_for_provider),
                "provider_response_hash": provider_response_hash,
                "provider_response_id": str(parsed.get("id") or ""),
                "provider_created": parsed.get("created"),
                "system_fingerprint": str(parsed.get("system_fingerprint") or ""),
                "provider_streamed": stream_callback is not None,
                "provider_stream_chunk_count": provider_chunk_count,
            }
            if not isinstance(observed_network, dict):
                observed_network = provider_network_observation(config["endpoint"])
            return {
                "response": parsed,
                "provider": config["provider"],
                "model": outbound_for_provider["model"],
                "provider_endpoint_scope": provider_endpoint_scope(config["endpoint"]),
                "provider_network_observation": observed_network,
                "mode": "real-api",
                "provider_failures": failures,
                **evidence,
            }
        except ModelProviderStreamCancelledError:
            raise
        except Exception as error:  # noqa: BLE001 - try the next configured provider
            if _stream_cancelled(stream_cancel_event):
                raise ModelProviderStreamCancelledError("下游客户端已取消模型流。") from error
            failures.append(
                {
                    "provider": config["provider"],
                    "model": outbound_for_provider["model"],
                    "error": _safe_error_message(error),
                }
            )
            if provider_stream_started or not _provider_error_retryable(error) or not _proxy_provider_failover_enabled():
                break

    if failures:
        raise ModelProviderUnavailableError("没有可用的 LLM 供应商，透明代理未执行本地模拟降级。", failures)
    if requested_model and any(item.get("configured") for item in provider_status(provider_profile)):
        raise ModelProviderUnavailableError(
            f"请求模型 `{requested_model}` 未绑定到当前透明代理的已配置 Provider；"
            "请使用 /v1/models 返回的唯一模型 ID，或只保留一个兼容 Provider。",
            [],
        )
    raise ModelProviderUnavailableError(
        "未配置透明代理的 LLM 供应商，请配置目标 Provider API Key。",
        [],
    )


def _iter_configured_providers(
    profile: str = "",
    *,
    requested_model: str = "",
    provider_id: str = "",
) -> Iterable[dict]:
    configs = {
        "openai-compatible": {
            "provider": "OpenAI 兼容接口",
            "api_key": _profile_env(profile, "OPENAI_COMPATIBLE_API_KEY", os.getenv("OPENAI_API_KEY", "")),
            "model": runtime_model_override(profile, "openai-compatible")
            or _profile_env(profile, "OPENAI_COMPATIBLE_MODEL", os.getenv("OPENAI_MODEL", "gpt-4.1-mini")),
            "endpoint": _openai_compatible_endpoint(profile),
        },
        "deepseek": {
            "provider": "DeepSeek",
            "api_key": _profile_env(profile, "DEEPSEEK_API_KEY", ""),
            "model": runtime_model_override(profile, "deepseek") or _profile_env(profile, "DEEPSEEK_MODEL", "deepseek-v4-pro"),
            "endpoint": _deepseek_endpoint(profile),
        },
        "zhipu": {
            "provider": "智谱",
            "api_key": _profile_env(profile, "ZHIPU_API_KEY", ""),
            "model": runtime_model_override(profile, "zhipu") or _profile_env(profile, "ZHIPU_MODEL", "glm-4.6v-flashx"),
            "endpoint": _zhipu_endpoint(profile),
        },
    }
    selected_provider_id = normalize_provider_selector(provider_id) if provider_id else ""
    configured: list[dict[str, Any]] = []
    for key in _provider_priority(profile):
        if selected_provider_id and key != selected_provider_id:
            continue
        config = configs.get(key)
        if config and config["api_key"]:
            config["provider_id"] = key
            config["profile"] = profile.strip() or "global"
            configured.append(config)

    # A transparent gateway must not send ``model=MODEL_B`` to whichever
    # provider happens to be first in the priority list.  That can leak the
    # prompt to the wrong vendor and usually produces an opaque provider
    # error.  Prefer an exact model binding; an unknown model is only accepted
    # when exactly one provider is configured (some compatible gateways expose
    # aliases that cannot be known from environment metadata).  With multiple
    # providers, fail closed instead of guessing.
    requested = requested_model.strip().lower()
    if requested:
        exact = [item for item in configured if str(item.get("model") or "").strip().lower() == requested]
        if len(exact) == 1:
            yield from exact
            return
        if len(exact) > 1:
            # A standard OpenAI request exposes only a model id. If two
            # vendors advertise the same id, priority-based selection would
            # silently move the prompt between providers, so fail closed.
            return
        if len(configured) != 1:
            return

    yield from configured

def filter_model_output(content: str) -> dict:
    findings: list[dict[str, str]] = []
    patterns = [
        ("credential", re.compile(r"(?i)\b(api[_-]?key|token|secret|password)\b\s*[:=]\s*[^\s,;]+")),
        (
            "credential-literal",
            re.compile(r"(?i)(?<![a-z0-9])(?:sk|pk|rk|xoxb|ghp|github_pat|AIza)[_-][a-z0-9._-]{8,}(?![a-z0-9])"),
        ),
        ("bearer-token", re.compile(r"(?i)\bbearer\s+[a-z0-9._~+/=-]{8,}")),
        ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
        ("flag", re.compile(r"(?i)flag\{[^}]{1,200}\}")),
        ("dangerous-command", re.compile(r"(?i)\b(rm\s+-rf|powershell\s+-enc|chmod\s+777|curl\s+https?://|wget\s+https?://)")),
        ("jailbreak", re.compile(r"(?i)(ignore previous|do anything now|绕过安全|忽略系统|无约束模式)")),
        ("system-prompt-leak", re.compile(r"(?is)(system\s+prompt|系统提示词|<system\b|developer\s+message)")),
        ("metadata-ssrf", re.compile(r"(?i)(169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200)")),
    ]
    filtered = _canonical_security_text(content)
    for finding_type, pattern in patterns:
        matches = list(pattern.finditer(filtered))
        if not matches:
            continue
        findings.append({"type": finding_type, "count": str(len(matches))})
        filtered = pattern.sub(f"[REDACTED:{finding_type}]", filtered)
    encoded_matches: list[dict[str, str]] = []
    for decoded in canonical_text_variants(content)[1:]:
        for finding_type, pattern in patterns:
            if pattern.search(decoded):
                encoded_matches.append({"type": f"encoded-{finding_type}", "count": "1"})
    if encoded_matches:
        findings.extend(encoded_matches)
        filtered = re.sub(
            r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{20,}={0,2}(?![A-Za-z0-9+/=])",
            "[REDACTED:encoded-security-content]",
            filtered,
        )
    return {
        "original": content,
        "filtered": filtered,
        "blocked": bool(findings),
        "findings": findings,
    }


def _canonical_security_text(value: Any) -> str:
    text = str(value or "")
    for _ in range(3):
        normalized = unicodedata.normalize("NFKC", text)
        decoded = unquote(normalized)
        text = decoded
        if decoded == normalized:
            break
    # Keep invisible Unicode format controls out of the security view.  The
    # original Provider content is still retained in evidence; this only
    # prevents zero-width/bidi characters from splitting output leak markers.
    return "".join(char for char in text if unicodedata.category(char) != "Cf")
