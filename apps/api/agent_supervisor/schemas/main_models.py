import json
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

MAX_TOOL_CALL_BYTES = 64 * 1024
MAX_TOOL_CALL_DEPTH = 8
MAX_TOOL_CALL_OBJECT_FIELDS = 100
MAX_TOOL_CALL_ARRAY_ITEMS = 100
ToolCapability = Literal[
    "file.read",
    "file.write",
    "mail.send",
    "api.call",
    "code.run",
    "memory.write",
    "memory.read",
    "env.read",
    "model.respond",
]


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


class RunRequest(BaseModel):
    scenario_id: str = Field(..., max_length=120)
    guard_enabled: bool = True


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
    internal_email_domains: list[str] | None = Field(default=None, max_length=50)
    sensitive_path_markers: list[str] | None = Field(default=None, max_length=100)
    sensitive_api_markers: list[str] | None = Field(default=None, max_length=100)
    agent_tool_allowlists: dict[str, list[str]] | None = None
    agent_tool_mappings: dict[str, dict[str, AgentToolMappingConfig]] | None = None
    operator: str = Field(default="security-admin", max_length=80)
    comment: str = Field(default="", max_length=500)


class BatchCompareRequest(BaseModel):
    scenario_ids: list[str] | None = Field(default=None, max_length=100)


class AttackChainRunRequest(BaseModel):
    guard_enabled: bool = True


class AgentToolEvent(BaseModel):
    conversation_id: str = Field(default="demo-conversation", max_length=160)
    agent_id: str = Field(default="target-agent", max_length=160)
    agent_role: str = Field(default="target-agent", max_length=80)
    source_app: str = Field(default="generic-agent", max_length=120)
    model_input: str = Field(default="", max_length=20000)
    model_output: str = Field(default="", max_length=20000)
    tool_call: dict[str, Any]
    context_sources: list[str] = Field(default_factory=list, max_length=20)
    guard_enabled: bool = True
    execute_in_sandbox: bool = False

    _tool_call_within_limits = field_validator("tool_call")(_validate_tool_call)


class ExecutionReceiptRequest(BaseModel):
    receipt_id: str = Field(..., min_length=1, max_length=160)
    agent_id: str = Field(..., min_length=1, max_length=160)
    tool_call: dict[str, Any]
    status: Literal["completed", "failed", "not_executed"]
    execution_target: Literal["real", "sandbox", "none"]
    result_hash: str = Field(default="", max_length=128)
    duration_ms: float = Field(default=0, ge=0, le=86_400_000)
    error: str = Field(default="", max_length=2000)

    _tool_call_within_limits = field_validator("tool_call")(_validate_tool_call)


class ModelDrivenAgentRequest(BaseModel):
    task: str = Field(..., min_length=1, max_length=4000)
    force_real_model: bool = False
    target_model: str = Field(default="", max_length=160)


class BatchAgentToolEvents(BaseModel):
    events: list[AgentToolEvent] = Field(..., min_length=1, max_length=50)
    guard_enabled: bool = True
    execute_in_sandbox: bool = False


class AttackLabRunRequest(BaseModel):
    surface_id: str = Field(..., max_length=80)
    attack_input: str = Field(default="", max_length=12000)
    target_model: str = Field(default="", max_length=160)
    execute_in_sandbox: bool = True
    planner_mode: Literal["fixed", "model"] = "fixed"
    force_real_model: bool = False
    options: dict[str, Any] = Field(default_factory=dict)


class CustomAttackCompareRequest(BaseModel):
    """A user-authored tool call executed against two identical local fixtures."""

    payload: str = Field(default="", max_length=20000)
    tool: str = Field(..., min_length=1, max_length=160)
    arguments: dict[str, Any] = Field(default_factory=dict)
    command: str = Field(default="", max_length=4000)
    agent_id: str = Field(default="custom-attack-agent", min_length=1, max_length=160)
    agent_role: str = Field(default="attacker", min_length=1, max_length=160)
    context_sources: list[str] = Field(default_factory=lambda: ["user-payload"], max_length=20)
    execution_mode: Literal["sandbox", "external_receipt"] = "sandbox"

    @field_validator("arguments")
    @classmethod
    def _arguments_within_limits(cls, value: dict[str, Any]) -> dict[str, Any]:
        _validate_tool_call({"tool": "custom", "arguments": value})
        return value

    @field_validator("tool")
    @classmethod
    def _tool_name_normalized(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not normalized:
            raise ValueError("tool 不能为空")
        return normalized


class CustomAttackChainRequest(CustomAttackCompareRequest):
    """A caller-authored tool call continued as a guarded multi-Agent chain stage."""

    execution_mode: Literal["sandbox"] = "sandbox"
    source_comparison_id: str = Field(..., min_length=1, max_length=160)


class JailbreakRedteamRequest(BaseModel):
    task: str = Field(default="", max_length=4000)
    block_terms: str = Field(default="绕过,忽略,无约束,token,secret,flag", max_length=1000)
    target_model: str = Field(default="", max_length=160)
    force_real_model: bool = False
    variant_limit: int = Field(default=5, ge=1, le=6)


class DualModelJailbreakRequest(BaseModel):
    task: str = Field(default="", max_length=4000)
    block_terms: str = Field(default="绕过,忽略,无约束,token,secret,flag", max_length=1000)
    optimizer_model: str = Field(default="", max_length=160)
    target_model: str = Field(default="", max_length=160)
    optimizer_provider_profile: str = Field(default="optimizer", max_length=40)
    target_provider_profile: str = Field(default="target", max_length=40)
    optimizer_role: str = Field(default="", max_length=3000)
    force_real_optimizer: bool = True
    force_real_target: bool = True
    iteration_count: int = Field(default=1, ge=1, le=5)


class RefusalRewriteEvasionRequest(BaseModel):
    task: str = Field(default="", max_length=4000)
    refusal_terms: str = Field(default="抱歉,不能帮助你,无法协助你,不能提供,无法提供,i can't,i cannot,cannot assist", max_length=1000)
    optimizer_model: str = Field(default="", max_length=160)
    target_model: str = Field(default="", max_length=160)
    optimizer_provider_profile: str = Field(default="optimizer", max_length=40)
    target_provider_profile: str = Field(default="target", max_length=40)
    optimizer_role: str = Field(default="", max_length=3000)
    force_real_optimizer: bool = True
    force_real_target: bool = True
    iteration_count: int = Field(default=1, ge=1, le=5)


class AttackTestsetRunRequest(BaseModel):
    surface_id: str = Field(default="all", max_length=80)
    sample_ids: list[str] = Field(default_factory=list, max_length=50)
    sample_overrides: dict[str, dict[str, Any]] = Field(default_factory=dict)
    execute_in_sandbox: bool = True
    planner_mode: Literal["fixed", "model"] = "fixed"
    force_real_model: bool = False


class AuthorizedTargetRunRequest(BaseModel):
    target_url: str = Field(..., max_length=1000)
    attack_input: str = Field(default="", max_length=8000)
    surface_id: str = Field(default="prompt-injection", max_length=80)
    target_type: str = Field(default="openai-compatible", max_length=80)
    target_model: str = Field(default="authorized-target-model", max_length=160)
    authorization_confirmed: bool = False
    authorization_note: str = Field(default="", max_length=1200)
    bearer_token: str = Field(default="", max_length=2000)


class LearningLabRunRequest(BaseModel):
    scenario_id: str = Field(default="system-prompt-leak", max_length=80)
    attack_input: str = Field(default="", max_length=8000)
    execute_in_sandbox: bool = True


class ApprovalDecisionRequest(BaseModel):
    action: Literal["approve", "reject", "批准", "驳回"]
    operator: str = Field(default="operator", max_length=80)
    comment: str = Field(..., min_length=1, max_length=2000)
    execute_in_sandbox: bool = False


class ApprovalExecutionClaimRequest(BaseModel):
    agent_id: str = Field(..., min_length=1, max_length=160)
    tool_call: dict[str, Any]

    _tool_call_within_limits = field_validator("tool_call")(_validate_tool_call)


class ApprovalExecutionCompleteRequest(BaseModel):
    agent_id: str = Field(..., min_length=1, max_length=160)
    claim_id: str = Field(..., min_length=1, max_length=160)
    succeeded: bool
    result_hash: str = Field(default="", max_length=128)


class RealModelEvaluationRequest(BaseModel):
    force_real: bool = True


class ModelProfileRuntimeConfigUpdate(BaseModel):
    provider_priority: list[str] | None = None
    model_overrides: dict[str, str] | None = None


class ModelRuntimeConfigUpdate(BaseModel):
    real_api_enabled: bool | None = None
    profiles: dict[str, ModelProfileRuntimeConfigUpdate] | None = None
