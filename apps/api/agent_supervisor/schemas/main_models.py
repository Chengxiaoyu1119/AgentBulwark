import json
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

MAX_TOOL_CALL_BYTES = 64 * 1024
MAX_TOOL_CALL_DEPTH = 8
MAX_TOOL_CALL_OBJECT_FIELDS = 100
MAX_TOOL_CALL_ARRAY_ITEMS = 100
ToolCapability = Literal[
    "file.read",
    "file.write",
    "mail.send",
    "api.call",
    "memory.write",
    "memory.read",
    "env.read",
    "model.respond",
]
ModelProviderId = Literal["openai-compatible", "deepseek", "zhipu"]
ModelProfileId = Literal["global", "optimizer", "target"]


def _validate_tool_call(value: dict[str, Any]) -> dict[str, Any]:
    try:
        encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("tool_call 必须是可序列化的 JSON 对象") from exc
    if len(encoded) > MAX_TOOL_CALL_BYTES:
        raise ValueError(f"tool_call 序列化后不能超过 {MAX_TOOL_CALL_BYTES} 字节")
    _validate_tool_call_node(value, depth=1)
    return value


def _validate_tool_call_node(value: Any, *, depth: int) -> None:
    if depth > MAX_TOOL_CALL_DEPTH:
        raise ValueError(f"tool_call 嵌套深度不能超过 {MAX_TOOL_CALL_DEPTH} 层")
    if isinstance(value, dict):
        if len(value) > MAX_TOOL_CALL_OBJECT_FIELDS:
            raise ValueError(f"tool_call 单个对象不能超过 {MAX_TOOL_CALL_OBJECT_FIELDS} 个字段")
        for item in value.values():
            _validate_tool_call_node(item, depth=depth + 1)
    elif isinstance(value, (list, tuple)):
        if len(value) > MAX_TOOL_CALL_ARRAY_ITEMS:
            raise ValueError(f"tool_call 单个数组不能超过 {MAX_TOOL_CALL_ARRAY_ITEMS} 项")
        for item in value:
            _validate_tool_call_node(item, depth=depth + 1)


class PolicyUpdate(BaseModel):
    enabled: bool | None = None
    name: str | None = Field(default=None, max_length=120)
    description: str | None = Field(default=None, max_length=1000)
    decision: Literal["允许", "拒绝", "询问", "隔离"] | None = None
    layer: str | None = Field(default=None, max_length=80)
    risk_controls: list[str] | None = Field(default=None, max_length=20)
    operator: str = Field(default="security-admin", max_length=80)
    comment: str = Field(default="", max_length=500)


class AgentToolMappingConfig(BaseModel):
    capability: ToolCapability
    argument_mapping: dict[str, str] = Field(default_factory=dict, max_length=100)
    required_arguments: list[str] = Field(default_factory=list, max_length=100)
    risk_hint: str = Field(default="", max_length=160)
    description: str = Field(default="", max_length=500)


class PolicySettingsUpdate(BaseModel):
    anomaly_review_threshold: int | None = Field(default=None, ge=1, le=100)
    anomaly_reject_threshold: int | None = Field(default=None, ge=1, le=100)
    approval_sla_minutes: int | None = Field(default=None, ge=1, le=1440)
    high_risk_auto_escalation: bool | None = None
    require_agent_capability_registration: bool | None = None
    require_agent_model_registration: bool | None = None
    require_agent_context_registration: bool | None = None
    internal_email_domains: list[str] | None = Field(default=None, max_length=50)
    sensitive_path_markers: list[str] | None = Field(default=None, max_length=100)
    sensitive_api_markers: list[str] | None = Field(default=None, max_length=100)
    agent_tool_allowlists: dict[str, list[str]] | None = None
    agent_api_allowlists: dict[str, list[str]] | None = None
    agent_model_allowlists: dict[str, list[str]] | None = None
    agent_context_allowlists: dict[str, dict[str, list[str]]] | None = None
    agent_tool_mappings: dict[str, dict[str, AgentToolMappingConfig]] | None = None
    operator: str = Field(default="security-admin", max_length=80)
    comment: str = Field(default="", max_length=500)


class AgentRegistrationCreate(BaseModel):
    agent_id: str = Field(..., min_length=1, max_length=160, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
    display_name: str = Field(default="", max_length=120)


class PolicyLifecycleRequest(BaseModel):
    settings: PolicySettingsUpdate | None = None
    policies: dict[str, PolicyUpdate] | None = Field(default=None, max_length=100)
    comment: str = Field(default="", max_length=500)


class AgentToolEvent(BaseModel):
    conversation_id: str = Field(default="conversation", max_length=160)
    agent_id: str = Field(default="agent", max_length=160)
    agent_role: str = Field(default="agent", max_length=80)
    source_app: str = Field(default="agent", max_length=120)
    model_input: str = Field(default="", max_length=20000)
    model_output: str = Field(default="", max_length=20000)
    tool_call: dict[str, Any]
    context_sources: list[str] = Field(default_factory=list, max_length=20)
    guard_enabled: bool = True

    _tool_call_within_limits = field_validator("tool_call")(_validate_tool_call)


class ExecutionReceiptRequest(BaseModel):
    receipt_id: str = Field(..., min_length=1, max_length=160)
    agent_id: str = Field(..., min_length=1, max_length=160)
    tool_call: dict[str, Any]
    status: Literal["completed", "failed", "not_executed"]
    execution_target: Literal["real", "external", "local-runtime", "none"]
    result_hash: str = Field(default="", max_length=128)
    duration_ms: float = Field(default=0, ge=0, le=86_400_000)
    error: str = Field(default="", max_length=2000)

    _tool_call_within_limits = field_validator("tool_call")(_validate_tool_call)


class ApprovalDecisionRequest(BaseModel):
    action: Literal["approve", "reject", "批准", "驳回"]
    operator: str = Field(default="operator", max_length=80)
    comment: str = Field(..., min_length=1, max_length=2000)


class ApprovalExecutionClaimRequest(BaseModel):
    agent_id: str = Field(..., min_length=1, max_length=160)
    tool_call: dict[str, Any]

    _tool_call_within_limits = field_validator("tool_call")(_validate_tool_call)


class ApprovalExecutionCompleteRequest(BaseModel):
    agent_id: str = Field(..., min_length=1, max_length=160)
    claim_id: str = Field(..., min_length=1, max_length=160)
    succeeded: bool
    result_hash: str = Field(default="", max_length=128)


class GatewayToolExecutionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_id: str = Field(..., min_length=1, max_length=160)
    session_id: str = Field(..., min_length=1, max_length=160)
    provider_call_id: str = Field(default="", max_length=160)


class ModelProfileRuntimeConfigUpdate(BaseModel):
    provider_priority: list[ModelProviderId] | None = Field(default=None, min_length=1, max_length=3)
    model_overrides: dict[ModelProviderId, str] | None = None


class ModelRuntimeConfigUpdate(BaseModel):
    real_api_enabled: bool | None = None
    profiles: dict[ModelProfileId, ModelProfileRuntimeConfigUpdate] | None = None


class ModelProviderProbeRequest(BaseModel):
    profile: ModelProfileId = "target"
    provider_id: ModelProviderId
