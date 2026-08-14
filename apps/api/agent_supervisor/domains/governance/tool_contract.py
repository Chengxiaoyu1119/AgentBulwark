from __future__ import annotations

import re
import unicodedata
from email.utils import getaddresses
from pathlib import PurePosixPath, PureWindowsPath
from typing import Any
from urllib.parse import unquote

SUPPORTED_TOOLS = frozenset(
    {
        "file.read",
        "file.write",
        "mail.send",
        "api.call",
        "code.run",
        "memory.write",
        "memory.read",
        "env.read",
        "model.respond",
    }
)

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
        decoded = unquote(normalized)
        text = decoded
        if decoded == normalized:
            break
    return unicodedata.normalize("NFKC", text).strip()


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
    elif tool == "code.run":
        arguments["command"] = canonical_text(arguments.get("command"))
    elif tool == "env.read":
        arguments["key"] = canonical_text(arguments.get("key"))

    return {
        "tool": tool,
        "arguments": arguments,
        "risk_hint": canonical_text(tool_call.get("risk_hint")).lower(),
    }


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
    return re.sub(r"/{2,}", "/", endpoint)


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
