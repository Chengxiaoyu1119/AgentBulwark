from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from apps.api.agent_supervisor.domains.governance.tool_contract import SUPPORTED_TOOLS, normalize_tool_call
from apps.api.agent_supervisor.storage.data import get_policy_settings


@dataclass(frozen=True)
class ToolResolution:
    original_tool_call: dict[str, Any]
    effective_tool_call: dict[str, Any]
    mapped: bool
    mapping: dict[str, Any] | None = None

    @property
    def original_tool(self) -> str:
        return str(self.original_tool_call.get("tool", ""))

    @property
    def capability(self) -> str:
        return str(self.effective_tool_call.get("tool", ""))


def resolve_tool_call(tool_call: dict[str, Any], agent_id: str = "") -> ToolResolution:
    """Resolve an administrator-configured custom tool into a standard capability."""
    original = normalize_tool_call(tool_call)
    settings = get_policy_settings()
    raw_registry = settings.get("agent_tool_mappings", {})
    if not isinstance(raw_registry, dict):
        return ToolResolution(original, original, False)

    merged_registry: dict[str, Any] = {}
    wildcard = raw_registry.get("*")
    if isinstance(wildcard, dict):
        merged_registry.update(wildcard)
    scoped = raw_registry.get(agent_id)
    if isinstance(scoped, dict):
        merged_registry.update(scoped)

    raw_mapping = merged_registry.get(original["tool"])
    if not isinstance(raw_mapping, dict):
        return ToolResolution(original, original, False)

    capability = str(raw_mapping.get("capability", "")).strip().lower()
    if capability not in SUPPORTED_TOOLS:
        raise ValueError(f"工具 `{original['tool']}` 的标准能力映射无效：{capability or 'empty'}")

    original_arguments = original.get("arguments", {})
    if not isinstance(original_arguments, dict):
        original_arguments = {}
    required = raw_mapping.get("required_arguments", [])
    required_arguments = [str(item) for item in required] if isinstance(required, list) else []
    missing = [
        name
        for name in required_arguments
        if name not in original_arguments or original_arguments.get(name) is None or original_arguments.get(name) == ""
    ]
    if missing:
        raise ValueError(f"工具 `{original['tool']}` 缺少必填参数：{', '.join(missing)}")

    effective_arguments = dict(original_arguments)
    raw_argument_mapping = raw_mapping.get("argument_mapping", {})
    argument_mapping = raw_argument_mapping if isinstance(raw_argument_mapping, dict) else {}
    for source_name, target_name in argument_mapping.items():
        source = str(source_name)
        target = str(target_name)
        if source in original_arguments and target:
            effective_arguments[target] = original_arguments[source]

    effective = normalize_tool_call(
        {
            "tool": capability,
            "arguments": effective_arguments,
            "risk_hint": str(raw_mapping.get("risk_hint") or original.get("risk_hint", "")),
        }
    )
    mapping = {
        "agent_id": agent_id or "*",
        "original_tool": original["tool"],
        "capability": capability,
        "argument_mapping": {str(key): str(value) for key, value in argument_mapping.items()},
        "required_arguments": required_arguments,
        "risk_hint": str(raw_mapping.get("risk_hint", "")),
        "description": str(raw_mapping.get("description", "")),
    }
    return ToolResolution(original, effective, True, mapping)
