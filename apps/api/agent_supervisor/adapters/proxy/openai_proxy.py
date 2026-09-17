from __future__ import annotations

import hashlib
import json
import math
import os
import queue
import re
import threading
import time
from copy import deepcopy
from typing import Any, Callable, Iterable
from uuid import uuid4

from apps.api.agent_supervisor.adapters.models.model_adapter import (
    ModelProviderStreamCancelledError,
    ModelProviderUnavailableError,
    filter_model_output,
    forward_openai_chat_completion,
)
from apps.api.agent_supervisor.adapters.proxy.proxy_security import proxy_server_observed_receipts_required
from apps.api.agent_supervisor.adapters.proxy.resource_governance import (
    ProxyResourceLimitError,
    ResourceLease,
    ResourcePlan,
    acquire_resource_lease,
    estimate_request_plan,
    resource_governance_enabled,
)
from apps.api.agent_supervisor.domains.evidence.gateway_evidence import (
    gateway_code_fingerprint,
    gateway_runtime_evidence,
    gateway_source_fingerprint,
)
from apps.api.agent_supervisor.domains.governance.integrity import (
    audit_hash,
    audit_signature_required,
    verify_audit_signature,
)
from apps.api.agent_supervisor.domains.governance.redaction import sanitize_model_visible_tool_result
from apps.api.agent_supervisor.domains.governance.skill_scanner import (
    VERDICT_QUARANTINE,
    context_scan_enabled,
    scan_text,
    scan_tool_definition,
    skill_scan_enabled,
)
from apps.api.agent_supervisor.domains.governance.supervisor import GuardDecision, decide
from apps.api.agent_supervisor.domains.governance.task_profiles import (
    normalize_task_id,
    resolve_task_profile,
    task_audit_context,
)
from apps.api.agent_supervisor.domains.governance.tool_contract import (
    get_agent_model_allowlist,
    get_agent_tool_allowlist,
    model_allowlist_reason,
    validate_json_schema_instance,
    validate_json_value_limits,
)
from apps.api.agent_supervisor.domains.runtime.agent_credentials import can_execute_managed_tools
from apps.api.agent_supervisor.domains.runtime.events import evaluate_agent_event
from apps.api.agent_supervisor.domains.runtime.execution_receipts import (
    ExecutionReceiptConflictError,
    claim_execution_receipt_use,
    tool_call_hash,
    tool_result_hash,
    verify_execution_receipt,
)
from apps.api.agent_supervisor.domains.runtime.gateway_execution import execute_gateway_tool_call
from apps.api.agent_supervisor.storage.data import get_policy_settings
from apps.api.agent_supervisor.storage.database import load_audit_log, load_execution_receipt

CONTROL_DECISIONS = {"拒绝", "询问", "隔离"}


class ProxyPolicyRejectionError(ValueError):
    """A pre-Provider policy rejection with durable gateway evidence."""

    def __init__(self, message: str, *, gateway_audit: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.gateway_audit = gateway_audit if isinstance(gateway_audit, dict) else {}


class GatewayStreamFinalizationError(RuntimeError):
    """A post-Provider stream consistency failure with durable evidence."""

    def __init__(self, *, gateway_audit: dict[str, Any] | None = None) -> None:
        super().__init__("网关流式终态校验失败。")
        self.gateway_audit = gateway_audit if isinstance(gateway_audit, dict) else {}


PROXY_TOOL_NAME_MAP = {
    "file_read": "file.read",
    "file_write": "file.write",
    "mail_send": "mail.send",
    "api_call": "api.call",
    "memory_write": "memory.write",
    "memory_read": "memory.read",
    "env_read": "env.read",
    "model_respond": "model.respond",
}
PROXY_ALLOWED_MESSAGE_ROLES = {"system", "developer", "user", "assistant", "tool", "function"}
# Only the standard Chat Completions message fields are forwarded to a
# Provider.  An otherwise harmless-looking vendor extension on a message can
# still be interpreted as a hidden instruction by a compatible endpoint, so it
# must not cross the trust boundary merely because the text scanner did not
# classify it as an attack.
PROXY_PROVIDER_MESSAGE_FIELDS = frozenset(
    {"role", "content", "name", "tool_calls", "function_call", "tool_call_id", "audio", "refusal"}
)
# Tool definitions and tool-call history are nested model-visible protocol
# objects.  A top-level request allowlist is not enough: a compatible Provider
# may interpret an otherwise unknown nested key as a hidden instruction or
# routing control.  Keep the standard OpenAI fields and project everything else
# out before the outbound call.
PROXY_PROVIDER_TOOL_FIELDS = frozenset({"type", "function"})
PROXY_PROVIDER_FUNCTION_FIELDS = frozenset({"name", "description", "parameters", "strict"})
PROXY_PROVIDER_TOOL_CALL_FIELDS = frozenset({"id", "type", "function"})
PROXY_PROVIDER_TOOL_CALL_FUNCTION_FIELDS = frozenset({"name", "arguments"})
PROXY_PROVIDER_CONTENT_PART_FIELDS = {
    "text": frozenset({"type", "text"}),
    "input_text": frozenset({"type", "text"}),
    "refusal": frozenset({"type", "refusal"}),
    "image_url": frozenset({"type", "image_url"}),
    "input_image": frozenset({"type", "image_url", "detail"}),
    "input_audio": frozenset({"type", "input_audio"}),
    "audio": frozenset({"type", "audio", "transcript"}),
}
# The top-level content-part allowlist is not sufficient for multimodal
# blocks: ``image_url``/``input_audio``/``audio`` are nested objects whose
# vendor extensions can otherwise become a second model-visible instruction
# channel.  Keep only the fields defined by the OpenAI-compatible contracts and
# bound opaque media references before they cross either gateway boundary.
PROXY_PROVIDER_IMAGE_FIELDS = frozenset({"url", "detail"})
PROXY_PROVIDER_INPUT_AUDIO_FIELDS = frozenset({"data", "format"})
PROXY_PROVIDER_AUDIO_FIELDS = frozenset({"id", "data", "expires_at"})
# Chat message ``audio`` and top-level audio output configuration are standard
# OpenAI-compatible fields, but compatible providers frequently accept vendor
# extensions inside them.  Those nested values are still caller-controlled and
# may become a hidden prompt/routing channel, so keep two deliberately narrow
# shapes instead of passing the objects through unchanged.
PROXY_PROVIDER_MESSAGE_AUDIO_FIELDS = frozenset({"id"})
PROXY_PROVIDER_AUDIO_CONFIG_FIELDS = frozenset({"voice", "format"})
PROXY_MAX_MEDIA_REFERENCE_CHARS = 1_000_000
# Only fields from the Chat Completions contract are allowed to cross the
# Provider boundary.  An OpenAI-compatible server may accept arbitrary JSON
# extensions, but a security gateway must not forward an unknown top-level
# field that could become a hidden system/prompt channel at the Provider.
# ``agent_supervisor`` is an internal control envelope and is removed below.
PROXY_PROVIDER_REQUEST_FIELDS = frozenset(
    {
        "model",
        "messages",
        "tools",
        "tool_choice",
        "stream",
        "stream_options",
        "n",
        "temperature",
        "top_p",
        "top_k",
        "max_tokens",
        "max_completion_tokens",
        "max_output_tokens",
        "stop",
        "presence_penalty",
        "frequency_penalty",
        "logit_bias",
        "user",
        "seed",
        "response_format",
        "response_modalities",
        "modalities",
        "audio",
        "prediction",
        "reasoning_effort",
        # DeepSeek V4 exposes a structured thinking control for its
        # OpenAI-compatible endpoint.  It is projected below to a bounded
        # shape; arbitrary vendor fields remain outside the Provider boundary.
        "thinking",
        "parallel_tool_calls",
        "service_tier",
        "store",
        "metadata",
        "prompt_cache_key",
        "safety_identifier",
        "functions",
        "function_call",
        "verbosity",
        "web_search_options",
        "include",
    }
)
PROXY_MAX_MESSAGES = 64
PROXY_MAX_TOOLS = 64
PROXY_MAX_MODEL_CHARS = 200
PROXY_MAX_SUPERVISOR_EXTENSION_CHARS = 64_000
PROXY_MAX_MESSAGE_CHARS = 40_000
PROXY_MAX_TOTAL_TEXT_CHARS = 240_000
PROXY_MAX_TOOL_NAME_CHARS = 160
PROXY_MAX_TOOL_DESCRIPTION_CHARS = 8_000
PROXY_MAX_TOOL_SCHEMA_CHARS = 32_000
PROXY_MAX_TOOL_ARGUMENT_CHARS = 32_000
PROXY_MAX_TOOL_CALLS_PER_MESSAGE = 32
PROXY_MAX_TOTAL_STRUCTURED_CHARS = 240_000
PROXY_MAX_CONTENT_PARTS = 128
PROXY_MAX_REQUEST_CHARS = 4 * 1024 * 1024
# FastAPI has already materialized the JSON request by the time this module
# receives it.  Per-message/schema limits are not enough: standard top-level
# fields such as ``logit_bias`` or ``metadata`` can still contain NaN,
# excessive nesting, or a very large node graph and would otherwise be
# serialized back to the Provider with a different parser's semantics.  Keep
# one whole-request JSON value budget at the trust boundary as well.
PROXY_MAX_REQUEST_JSON_NODES = 16_384
PROXY_MAX_TOOL_CALL_ID_CHARS = 256
PROXY_MAX_MESSAGE_NAME_CHARS = 160
PROXY_MAX_PROVIDER_CHOICES = 16
PROXY_MAX_PROVIDER_TOOL_CALLS = 32
PROXY_MAX_USAGE_VALUE = 10_000_000
# Request-side generation controls are part of the gateway's resource
# boundary.  Without these limits an authenticated Agent can submit a valid
# OpenAI-shaped request that asks a Provider for unbounded fan-out or output.
PROXY_MAX_COMPLETIONS = 16
PROXY_MAX_OUTPUT_TOKENS = 64_000
PROXY_MAX_TEMPERATURE = 2.0
PROXY_MAX_TOP_P = 1.0
PROXY_AUDIT_EXCERPT_CHARS = 4_000
PROXY_TOOL_RECEIPTS_ENV = "AGENT_SUPERVISOR_PROXY_REQUIRE_TOOL_RECEIPTS"
# These standard request fields are not chat messages, but compatible
# Providers may copy their free-form text or JSON schema descriptions into a
# prompt or routing context.  Keep them in the same pre-Provider trust scan;
# fields such as model/temperature remain protocol controls rather than text
# context.
PROXY_PROVIDER_CONTEXT_FIELDS = frozenset(
    {"metadata", "prediction", "response_format", "web_search_options", "include"}
)
# These fields are part of the OpenAI-compatible request contract, but several
# providers copy their free-form values into the model context.  Keep the
# projection deliberately small so an extension nested below an otherwise
# valid top-level field cannot become a second instruction channel upstream.
PROXY_PROVIDER_METADATA_VALUE_CHARS = 512
PROXY_PROVIDER_METADATA_ITEMS = 64
PROXY_PROVIDER_INCLUDE_ITEMS = 64
PROXY_PROVIDER_INCLUDE_ITEM_CHARS = 160
PROXY_PROVIDER_SEARCH_OPTION_FIELDS = frozenset({"search_context_size"})
PROXY_PROVIDER_THINKING_TYPES = frozenset({"enabled", "disabled"})
PROXY_PROVIDER_THINKING_FIELDS = frozenset({"type", "budget_tokens"})
PROXY_PROVIDER_TOP_LEVEL_OUTPUT_FIELDS = (
    "output",
    "output_text",
    "reasoning_content",
    "reasoning",
    "thinking",
    "analysis",
    "refusal",
    "annotations",
)
PROXY_PROVIDER_CHOICE_OUTPUT_FIELDS = (
    "text",
    "reasoning_content",
    "reasoning",
    "thinking",
    "analysis",
    "refusal",
    "annotations",
    "audio",
    "logprobs",
)
# When a Provider response is blocked, only these protocol fields are safe to
# keep beside the gateway-generated assistant message.  Vendor extensions are
# untrusted model-visible channels and must not survive a block by hiding in a
# field that the scanner does not know by name.
PROXY_BLOCKED_CHOICE_FIELDS = frozenset({"index", "message", "finish_reason"})
PROXY_BLOCKED_RESPONSE_FIELDS = frozenset({"id", "object", "created", "model", "choices"})
# The transparent endpoint speaks the OpenAI Chat Completions contract.  A
# Provider may return vendor metadata, but unknown fields are not part of that
# contract and can become a hidden model-visible instruction channel.  Keep a
# deliberately small protocol allowlist after output inspection has completed.
PROXY_RESPONSE_FIELDS = frozenset(
    {
        "id",
        "object",
        "created",
        "model",
        "choices",
        "usage",
        "system_fingerprint",
        "service_tier",
    }
)
PROXY_CHOICE_FIELDS = frozenset({"index", "message", "finish_reason", "text", "logprobs"})
PROXY_MESSAGE_FIELDS = frozenset(
    {
        "role",
        "content",
        "tool_calls",
        "function_call",
        "name",
        "tool_call_id",
        "reasoning_content",
        "reasoning",
        "thinking",
        "analysis",
        "refusal",
    }
)
PROXY_TOOL_CALL_FIELDS = frozenset({"id", "type", "function"})
PROXY_FUNCTION_FIELDS = frozenset({"name", "arguments"})
PROXY_USAGE_FIELDS = frozenset(
    {
        "prompt_tokens",
        "completion_tokens",
        "total_tokens",
        "prompt_tokens_details",
        "completion_tokens_details",
        "audio_tokens",
        "reasoning_tokens",
        "accepted_prediction_tokens",
        "rejected_prediction_tokens",
    }
)
PROXY_USAGE_DETAIL_FIELDS = frozenset(
    {
        "cached_tokens",
        "audio_tokens",
        "reasoning_tokens",
        "accepted_prediction_tokens",
        "rejected_prediction_tokens",
    }
)
PROXY_SAFE_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$")
PROXY_SAFE_METADATA_PATH_RE = re.compile(r"^[A-Za-z0-9_.\[\]-]{1,200}$")
# Metadata paths are exposed in the ``agent_supervisor`` response extension.
# Keep ordinary vendor field names useful for diagnostics, but never reflect an
# arbitrary Provider-controlled key (which can itself contain prompt text) into
# a downstream Agent-visible field.  The fallback is a stable digest so the
# signed audit record remains the source of the original name without creating
# a second instruction channel in the response envelope.
PROXY_SAFE_METADATA_KEY_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.:-]{0,119}$")
PROXY_ALLOWED_FINISH_REASONS = frozenset(
    {"stop", "length", "tool_calls", "function_call", "content_filter", "null", ""}
)


def _bounded_usage_value(value: Any) -> bool:
    """Return whether one Provider usage counter is finite and bounded."""

    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    if isinstance(value, float) and not math.isfinite(value):
        return False
    return 0 <= value <= PROXY_MAX_USAGE_VALUE


def _proxy_payload_hash(payload: dict[str, Any]) -> str:
    serialized = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def prepare_openai_provider_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Return the bounded standard request that is allowed to reach a Provider.

    The caller's request hash is calculated before this projection so the
    audit still binds the complete submitted request.  The Provider request
    hash is calculated after the projection, making any stripped extension
    visible as a deliberate gateway boundary transformation instead of an
    implicit pass-through.
    """

    if not isinstance(payload, dict):
        raise ValueError("OpenAI 兼容请求必须是 JSON 对象")
    # This helper is intentionally safe when called outside the normal
    # completion path (for example by an adapter or a regression test).  The
    # public path performs the full contract validation below, but a direct
    # projection must not turn non-finite values or an over-deep object into a
    # Provider request merely because it skipped that caller.
    request_value_issue = validate_json_value_limits(
        payload,
        path="request",
        max_nodes=PROXY_MAX_REQUEST_JSON_NODES,
    )
    if request_value_issue:
        raise ValueError(request_value_issue)
    provider_payload = {
        key: value
        for key, value in payload.items()
        if key in PROXY_PROVIDER_REQUEST_FIELDS
    }
    provider_payload.pop("agent_supervisor", None)
    messages = provider_payload.get("messages")
    if isinstance(messages, list):
        provider_payload["messages"] = _project_provider_messages(messages)
    tools = provider_payload.get("tools")
    if isinstance(tools, list):
        provider_payload["tools"] = _project_provider_tools(tools)
    functions = provider_payload.get("functions")
    if isinstance(functions, list):
        provider_payload["functions"] = _project_provider_functions(functions)
    if "tool_choice" in provider_payload:
        provider_payload["tool_choice"] = _project_provider_tool_choice(provider_payload["tool_choice"])
    if "function_call" in provider_payload:
        # Legacy OpenAI clients use ``function_call`` as a top-level selector.
        # It is still model-visible control data, so an otherwise valid request
        # must not forward vendor fields such as ``description`` or ``metadata``
        # as a second prompt channel.
        provider_payload["function_call"] = _project_provider_function_selector(
            provider_payload["function_call"]
        )
    if "thinking" in provider_payload:
        projected_thinking = _project_provider_thinking(provider_payload.get("thinking"))
        if projected_thinking:
            provider_payload["thinking"] = projected_thinking
        else:
            # DeepSeek's thinking control is structured protocol metadata, not
            # a free-form prompt channel.  Drop malformed values rather than
            # forwarding an ambiguous vendor object upstream.
            provider_payload.pop("thinking", None)
    _project_provider_context_fields(provider_payload)
    return provider_payload


def _project_provider_context_fields(provider_payload: dict[str, Any]) -> None:
    """Project standard free-form request fields before the Provider call.

    ``metadata`` and the newer context-like fields are not authentication
    boundaries.  A compatible Provider may feed their values into a prompt,
    tracing instruction, or search planner.  Passing nested vendor objects
    through unchanged would therefore undo the message/tool projection above.
    The caller's original payload remains hashed and audited; only this copy
    is narrowed for the outbound request.
    """

    if "metadata" in provider_payload:
        raw_metadata = provider_payload.get("metadata")
        if isinstance(raw_metadata, dict):
            projected_metadata: dict[str, str] = {}
            for raw_key, raw_value in list(raw_metadata.items())[:PROXY_PROVIDER_METADATA_ITEMS]:
                key = str(raw_key)
                if not PROXY_SAFE_METADATA_KEY_RE.fullmatch(key):
                    continue
                if isinstance(raw_value, bool):
                    value = "true" if raw_value else "false"
                elif isinstance(raw_value, (str, int, float)) and not isinstance(raw_value, bool):
                    if isinstance(raw_value, float) and not math.isfinite(raw_value):
                        continue
                    value = str(raw_value)
                else:
                    # Nested metadata is the ambiguous part of the contract:
                    # it is not needed for standard tracing and can carry an
                    # opaque provider instruction.  Drop it at the boundary.
                    continue
                if len(value) <= PROXY_PROVIDER_METADATA_VALUE_CHARS:
                    projected_metadata[key] = value
            if projected_metadata:
                provider_payload["metadata"] = projected_metadata
            else:
                provider_payload.pop("metadata", None)
        else:
            provider_payload.pop("metadata", None)

    if "audio" in provider_payload:
        projected_audio = _project_provider_audio_config(provider_payload.get("audio"))
        if projected_audio:
            provider_payload["audio"] = projected_audio
        else:
            # An invalid/empty audio configuration has no safe meaning at the
            # Provider boundary.  Drop it instead of forwarding a vendor
            # extension object that could be interpreted as hidden control.
            provider_payload.pop("audio", None)

    if "include" in provider_payload:
        raw_include = provider_payload.get("include")
        if isinstance(raw_include, list):
            provider_payload["include"] = [
                item.strip()[:PROXY_PROVIDER_INCLUDE_ITEM_CHARS]
                for item in raw_include[:PROXY_PROVIDER_INCLUDE_ITEMS]
                if isinstance(item, str)
                and item.strip()
                and PROXY_SAFE_IDENTIFIER_RE.fullmatch(item.strip())
            ]
        else:
            provider_payload.pop("include", None)

    if "prediction" in provider_payload:
        raw_prediction = provider_payload.get("prediction")
        if isinstance(raw_prediction, dict):
            projected_prediction: dict[str, Any] = {}
            prediction_type = raw_prediction.get("type")
            if isinstance(prediction_type, str) and prediction_type.strip():
                projected_prediction["type"] = prediction_type.strip()[:64]
            if "content" in raw_prediction:
                content = raw_prediction.get("content")
                if isinstance(content, str) and len(content) <= PROXY_MAX_MESSAGE_CHARS:
                    projected_prediction["content"] = content
                elif isinstance(content, list):
                    projected_prediction["content"] = _project_provider_content_parts(content)
            if projected_prediction:
                provider_payload["prediction"] = projected_prediction
            else:
                provider_payload.pop("prediction", None)
        else:
            provider_payload.pop("prediction", None)

    if "response_format" in provider_payload:
        raw_response_format = provider_payload.get("response_format")
        if isinstance(raw_response_format, dict):
            projected_response_format: dict[str, Any] = {}
            format_type = raw_response_format.get("type")
            if isinstance(format_type, str) and format_type in {"text", "json_object", "json_schema"}:
                projected_response_format["type"] = format_type
            if format_type == "json_schema" and isinstance(raw_response_format.get("json_schema"), dict):
                schema = raw_response_format["json_schema"]
                projected_schema = {
                    key: deepcopy(value)
                    for key, value in schema.items()
                    if key in {"name", "description", "schema", "strict"}
                }
                if projected_schema:
                    provider_payload_schema_issue = validate_json_value_limits(
                        projected_schema,
                        path="response_format.json_schema",
                    )
                    if not provider_payload_schema_issue:
                        projected_response_format["json_schema"] = projected_schema
            if projected_response_format:
                provider_payload["response_format"] = projected_response_format
            else:
                provider_payload.pop("response_format", None)
        else:
            provider_payload.pop("response_format", None)

    if "web_search_options" in provider_payload:
        raw_search_options = provider_payload.get("web_search_options")
        if isinstance(raw_search_options, dict):
            provider_payload["web_search_options"] = {
                key: deepcopy(value)
                for key, value in raw_search_options.items()
                if key in PROXY_PROVIDER_SEARCH_OPTION_FIELDS
                and isinstance(value, str)
                and len(value) <= 64
            }
            if not provider_payload["web_search_options"]:
                provider_payload.pop("web_search_options", None)
        else:
            provider_payload.pop("web_search_options", None)


def _project_provider_messages(messages: list[Any]) -> list[Any]:
    """Keep only standard message fields before an outbound Provider call.

    The original request remains the source for hashes, validation and audit
    evidence.  The Provider receives a deep copy so an extension field cannot
    become a second hidden prompt channel after the input guard has passed.
    """

    projected: list[Any] = []
    for message in messages:
        if not isinstance(message, dict):
            projected.append(message)
            continue
        projected_message = {
            key: deepcopy(value)
            for key, value in message.items()
            if key in PROXY_PROVIDER_MESSAGE_FIELDS
        }
        if isinstance(projected_message.get("content"), list):
            projected_message["content"] = _project_provider_content_parts(projected_message["content"])
        if isinstance(projected_message.get("tool_calls"), list):
            projected_message["tool_calls"] = _project_provider_tool_calls(projected_message["tool_calls"])
        if isinstance(projected_message.get("function_call"), dict):
            projected_message["function_call"] = _project_provider_function_call(projected_message["function_call"])
        if "audio" in projected_message:
            projected_audio = _project_provider_message_audio(projected_message.get("audio"))
            if projected_audio:
                projected_message["audio"] = projected_audio
            else:
                projected_message.pop("audio", None)
        projected.append(projected_message)
    return projected


def _project_provider_message_audio(value: Any) -> dict[str, str] | None:
    """Project an assistant message's audio reference to its standard shape."""

    if not isinstance(value, dict):
        return None
    raw_id = value.get("id")
    if not isinstance(raw_id, str) or not raw_id.strip() or len(raw_id) > PROXY_MAX_MEDIA_REFERENCE_CHARS:
        return None
    return {"id": raw_id}


def _project_provider_audio_config(value: Any) -> dict[str, str] | None:
    """Project top-level audio generation settings without vendor extensions."""

    if not isinstance(value, dict):
        return None
    projected: dict[str, str] = {}
    for field_name in PROXY_PROVIDER_AUDIO_CONFIG_FIELDS:
        raw_value = value.get(field_name)
        if isinstance(raw_value, str) and raw_value.strip() and len(raw_value) <= 128:
            projected[field_name] = raw_value.strip()
    return projected or None


def _project_provider_content_parts(parts: list[Any]) -> list[Any]:
    """Project multimodal content blocks to their standard fields."""

    projected: list[Any] = []
    for part in parts:
        if not isinstance(part, dict):
            projected.append(part)
            continue
        projected.append(_project_provider_content_part(part))
    return projected


def _project_provider_content_part(part: dict[str, Any]) -> dict[str, Any]:
    """Project one content block, including nested multimodal objects.

    OpenAI-compatible providers commonly accept arbitrary keys inside media
    objects even when the outer content part looks standard.  Those keys are
    still caller/provider-controlled data and can be copied into a downstream
    Agent context by an SDK.  Keep the supported protocol fields only; invalid
    required media values are left for the response validator to reject rather
    than being silently converted into executable-looking content.
    """

    part_type = str(part.get("type") or "").strip().lower()
    allowed = PROXY_PROVIDER_CONTENT_PART_FIELDS.get(part_type, frozenset({"type"}))
    projected = {key: deepcopy(value) for key, value in part.items() if key in allowed}

    if part_type in {"image_url", "input_image"} and "image_url" in projected:
        raw_image = projected.get("image_url")
        if isinstance(raw_image, dict):
            projected["image_url"] = {
                key: deepcopy(value)
                for key, value in raw_image.items()
                if key in PROXY_PROVIDER_IMAGE_FIELDS
                and (
                    key != "url"
                    or (isinstance(value, str) and len(value) <= PROXY_MAX_MEDIA_REFERENCE_CHARS)
                )
            }
        elif not isinstance(raw_image, str) or len(raw_image) > PROXY_MAX_MEDIA_REFERENCE_CHARS:
            projected.pop("image_url", None)
        if "detail" in projected and projected.get("detail") not in {"auto", "low", "high"}:
            projected.pop("detail", None)

    if part_type == "input_audio" and "input_audio" in projected:
        raw_audio = projected.get("input_audio")
        if isinstance(raw_audio, dict):
            projected["input_audio"] = {
                key: deepcopy(value)
                for key, value in raw_audio.items()
                if key in PROXY_PROVIDER_INPUT_AUDIO_FIELDS
                and (
                    key == "format"
                    or (isinstance(value, str) and len(value) <= PROXY_MAX_MEDIA_REFERENCE_CHARS)
                )
            }
        else:
            projected.pop("input_audio", None)

    if part_type == "audio" and "audio" in projected:
        raw_audio = projected.get("audio")
        if isinstance(raw_audio, dict):
            projected["audio"] = {
                key: deepcopy(value)
                for key, value in raw_audio.items()
                if key in PROXY_PROVIDER_AUDIO_FIELDS
                and (
                    key == "expires_at"
                    or (isinstance(value, str) and len(value) <= PROXY_MAX_MEDIA_REFERENCE_CHARS)
                )
            }
        else:
            projected.pop("audio", None)
    if "transcript" in projected and (
        not isinstance(projected.get("transcript"), str)
        or len(str(projected.get("transcript"))) > PROXY_MAX_MESSAGE_CHARS
    ):
        projected.pop("transcript", None)
    return projected


def _normalize_provider_content(value: Any, *, path: str) -> tuple[Any, str, list[str]]:
    """Validate and project Provider message content before it reaches an Agent.

    The request path already bounds caller content, but Provider responses are a
    separate untrusted boundary.  A compatible endpoint can return an object,
    an unknown multimodal block, or an oversized nested value in ``message.content``.
    Passing that shape through would make the gateway claim an OpenAI-compatible
    response while handing downstream SDKs a second, unbounded data channel.
    """

    if value is None:
        return None, "", []
    if isinstance(value, str):
        if len(value) > PROXY_MAX_MESSAGE_CHARS:
            return value, f"{path} 超过 {PROXY_MAX_MESSAGE_CHARS} 个字符", []
        return value, "", []
    if not isinstance(value, list):
        return value, f"{path} 必须是字符串、内容块数组或 null", []
    if len(value) > PROXY_MAX_CONTENT_PARTS:
        return value, f"{path} 内容块不能超过 {PROXY_MAX_CONTENT_PARTS} 个", []

    normalized: list[Any] = []
    normalizations: list[str] = []
    total_chars = 0
    for index, part in enumerate(value):
        item_path = f"{path}[{index}]"
        if not isinstance(part, dict):
            return value, f"{item_path} 必须是对象", normalizations
        part_type = str(part.get("type") or "").strip().lower()
        allowed = PROXY_PROVIDER_CONTENT_PART_FIELDS.get(part_type)
        if allowed is None:
            return value, f"{item_path}.type 不支持：{part_type or 'empty'}", normalizations
        value_issue = validate_json_value_limits(part, path=item_path)
        if value_issue:
            return value, value_issue, normalizations
        projected = _project_provider_content_part(part)
        if projected != part:
            normalizations.append(item_path)
        if part_type in {"text", "input_text"}:
            text = projected.get("text")
            if not isinstance(text, str):
                return value, f"{item_path}.text 必须是字符串", normalizations
            total_chars += len(text)
        elif part_type == "refusal":
            refusal = projected.get("refusal")
            if not isinstance(refusal, str):
                return value, f"{item_path}.refusal 必须是字符串", normalizations
            total_chars += len(refusal)
        elif part_type in {"image_url", "input_image"}:
            image = projected.get("image_url")
            if isinstance(image, str):
                if not image or len(image) > PROXY_MAX_MEDIA_REFERENCE_CHARS:
                    return value, f"{item_path}.image_url 超过媒体引用安全上限", normalizations
                total_chars += len(image)
            elif isinstance(image, dict):
                url = image.get("url")
                if not isinstance(url, str) or not url or len(url) > PROXY_MAX_MEDIA_REFERENCE_CHARS:
                    return value, f"{item_path}.image_url.url 必须是有限字符串", normalizations
                detail = image.get("detail")
                if detail is not None and detail not in {"auto", "low", "high"}:
                    return value, f"{item_path}.image_url.detail 不受支持", normalizations
                total_chars += len(json.dumps(projected, ensure_ascii=False, default=str, separators=(",", ":")))
            else:
                return value, f"{item_path}.image_url 缺少有效媒体引用", normalizations
        elif part_type == "input_audio":
            audio = projected.get("input_audio")
            if not isinstance(audio, dict):
                return value, f"{item_path}.input_audio 必须是对象", normalizations
            data = audio.get("data")
            audio_format = audio.get("format")
            if not isinstance(data, str) or not data or len(data) > PROXY_MAX_MEDIA_REFERENCE_CHARS:
                return value, f"{item_path}.input_audio.data 必须是有限字符串", normalizations
            if not isinstance(audio_format, str) or not audio_format.strip() or len(audio_format) > 32:
                return value, f"{item_path}.input_audio.format 必须是有限字符串", normalizations
            total_chars += len(data) + len(audio_format)
        elif part_type == "audio":
            audio = projected.get("audio")
            if audio is not None and not isinstance(audio, dict):
                return value, f"{item_path}.audio 必须是对象", normalizations
            if isinstance(audio, dict):
                for field_name in ("id", "data"):
                    field_value = audio.get(field_name)
                    if field_value is not None and (
                        not isinstance(field_value, str)
                        or len(field_value) > PROXY_MAX_MEDIA_REFERENCE_CHARS
                    ):
                        return value, f"{item_path}.audio.{field_name} 必须是有限字符串", normalizations
                expires_at = audio.get("expires_at")
                if expires_at is not None and (
                    isinstance(expires_at, bool) or not isinstance(expires_at, (int, float))
                ):
                    return value, f"{item_path}.audio.expires_at 必须是数字", normalizations
            total_chars += len(json.dumps(projected, ensure_ascii=False, default=str, separators=(",", ":")))
        else:
            total_chars += len(json.dumps(projected, ensure_ascii=False, default=str, separators=(",", ":")))
        normalized.append(projected)
    if total_chars > PROXY_MAX_MESSAGE_CHARS:
        return value, f"{path} 总文本超过 {PROXY_MAX_MESSAGE_CHARS} 个字符", normalizations
    return normalized, "", normalizations


def _project_provider_function_call(function_call: dict[str, Any]) -> dict[str, Any]:
    return {
        key: deepcopy(value)
        for key, value in function_call.items()
        if key in PROXY_PROVIDER_TOOL_CALL_FUNCTION_FIELDS
    }


def _project_provider_function_selector(value: Any) -> Any:
    """Project the legacy top-level ``function_call`` selector.

    Message-level function calls use ``name`` and ``arguments``; the top-level
    legacy selector only permits ``auto``, ``none`` or an object containing
    ``name``.  Keeping this projection separate prevents accidentally exposing
    the message-call ``arguments`` field as a provider control extension.
    """

    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        name = value.get("name")
        return {"name": deepcopy(name)} if isinstance(name, str) else {}
    return deepcopy(value)


def _project_provider_thinking(value: Any) -> dict[str, Any]:
    """Keep only the bounded DeepSeek-compatible thinking control."""

    if not isinstance(value, dict):
        return {}
    thinking_type = value.get("type")
    if not isinstance(thinking_type, str) or thinking_type not in PROXY_PROVIDER_THINKING_TYPES:
        return {}
    projected: dict[str, Any] = {"type": thinking_type}
    budget_tokens = value.get("budget_tokens")
    if (
        isinstance(budget_tokens, int)
        and not isinstance(budget_tokens, bool)
        and 1 <= budget_tokens <= PROXY_MAX_OUTPUT_TOKENS
    ):
        projected["budget_tokens"] = budget_tokens
    return projected


def _project_provider_tool_calls(tool_calls: list[Any]) -> list[Any]:
    projected: list[Any] = []
    for call in tool_calls:
        if not isinstance(call, dict):
            projected.append(call)
            continue
        item = {
            key: deepcopy(value)
            for key, value in call.items()
            if key in PROXY_PROVIDER_TOOL_CALL_FIELDS
        }
        if isinstance(item.get("function"), dict):
            item["function"] = _project_provider_function_call(item["function"])
        projected.append(item)
    return projected


def _project_provider_tools(tools: list[Any]) -> list[Any]:
    """Project caller tool definitions before they cross the Provider boundary."""

    projected: list[Any] = []
    for tool in tools:
        if not isinstance(tool, dict):
            projected.append(tool)
            continue
        item = {key: deepcopy(value) for key, value in tool.items() if key in PROXY_PROVIDER_TOOL_FIELDS}
        function = item.get("function")
        if isinstance(function, dict):
            item["function"] = {
                key: deepcopy(value)
                for key, value in function.items()
                if key in PROXY_PROVIDER_FUNCTION_FIELDS
            }
        projected.append(item)
    return projected


def _project_provider_functions(functions: list[Any]) -> list[Any]:
    """Project legacy ``functions`` definitions to the same safe subset."""

    projected: list[Any] = []
    for function in functions:
        if not isinstance(function, dict):
            projected.append(function)
            continue
        projected.append(
            {
                key: deepcopy(value)
                for key, value in function.items()
                if key in PROXY_PROVIDER_FUNCTION_FIELDS
            }
        )
    return projected


def _project_provider_tool_choice(value: Any) -> Any:
    if not isinstance(value, dict):
        return deepcopy(value)
    projected = {key: deepcopy(item) for key, item in value.items() if key in {"type", "function"}}
    function = projected.get("function")
    if isinstance(function, dict):
        projected["function"] = {
            key: deepcopy(item) for key, item in function.items() if key == "name"
        }
    return projected


def _stripped_provider_tool_fields(payload: dict[str, Any]) -> list[str]:
    """Return bounded paths for nested tool fields removed before forwarding."""

    stripped: list[str] = []
    for field_name in ("tools", "functions"):
        raw_items = payload.get(field_name)
        if not isinstance(raw_items, list):
            continue
        for index, item in enumerate(raw_items):
            if not isinstance(item, dict):
                continue
            allowed = PROXY_PROVIDER_TOOL_FIELDS if field_name == "tools" else PROXY_PROVIDER_FUNCTION_FIELDS
            for key in item:
                if key not in allowed:
                    stripped.append(f"{field_name}[{index}].{_safe_metadata_key(key)}")
            function = item.get("function") if field_name == "tools" else item
            if field_name == "tools" and isinstance(function, dict):
                for key in function:
                    if key not in PROXY_PROVIDER_FUNCTION_FIELDS:
                        stripped.append(f"tools[{index}].function.{_safe_metadata_key(key)}")
            if len(stripped) >= 128:
                return stripped[:128]
    return stripped[:128]


def _proxy_declared_tool_items(
    payload: dict[str, Any],
) -> list[tuple[str, int, dict[str, Any], dict[str, Any]]]:
    """Project modern ``tools`` and legacy ``functions`` into one view.

    OpenAI-compatible clients still use the deprecated ``functions`` field.
    The Provider payload must preserve the caller's original shape, but every
    gateway decision (definition scanning, capability allowlists and response
    schema validation) needs the same canonical function view.  Returning the
    source and index keeps audit findings attributable without mutating the
    request or leaking a synthetic shape upstream.
    """

    items: list[tuple[str, int, dict[str, Any], dict[str, Any]]] = []
    raw_tools = payload.get("tools")
    if isinstance(raw_tools, list):
        for index, raw_tool in enumerate(raw_tools):
            if not isinstance(raw_tool, dict):
                continue
            function = raw_tool.get("function") if raw_tool.get("type") == "function" else raw_tool
            if isinstance(function, dict):
                items.append(("tools", index, raw_tool, function))

    raw_functions = payload.get("functions")
    if isinstance(raw_functions, list):
        for index, function in enumerate(raw_functions):
            if not isinstance(function, dict):
                continue
            # Keep a standard envelope for scanners; the original legacy
            # function object remains untouched in the forwarded payload.
            items.append(("functions", index, {"type": "function", "function": function}, function))
    return items


def _stripped_provider_request_fields(payload: dict[str, Any]) -> list[str]:
    if not isinstance(payload, dict):
        return []
    stripped = [
        _safe_metadata_key(key)
        for key in payload
        if key not in PROXY_PROVIDER_REQUEST_FIELDS and key != "agent_supervisor"
    ]
    raw_audio = payload.get("audio")
    if isinstance(raw_audio, dict):
        stripped.extend(
            f"audio.{_safe_metadata_key(key)}"
            for key in raw_audio
            if key not in PROXY_PROVIDER_AUDIO_CONFIG_FIELDS
        )
    return sorted(dict.fromkeys(stripped))[:128]


def _stripped_provider_message_fields(messages: list[Any]) -> list[str]:
    """Return bounded paths for non-standard message fields removed upstream."""

    stripped: list[str] = []
    for index, message in enumerate(messages):
        if not isinstance(message, dict):
            continue
        for key in message:
            if key not in PROXY_PROVIDER_MESSAGE_FIELDS:
                stripped.append(f"messages[{index}].{_safe_metadata_key(key)}")
                if len(stripped) >= 128:
                    return stripped
        raw_message_audio = message.get("audio")
        if isinstance(raw_message_audio, dict):
            for key in raw_message_audio:
                if key not in PROXY_PROVIDER_MESSAGE_AUDIO_FIELDS:
                    stripped.append(f"messages[{index}].audio.{_safe_metadata_key(key)}")
                    if len(stripped) >= 128:
                        return stripped
        content = message.get("content")
        if isinstance(content, list):
            for part_index, part in enumerate(content):
                if not isinstance(part, dict):
                    continue
                part_type = str(part.get("type") or "").strip().lower()
                allowed = PROXY_PROVIDER_CONTENT_PART_FIELDS.get(part_type, frozenset({"type"}))
                for key in part:
                    if key not in allowed:
                        stripped.append(f"messages[{index}].content[{part_index}].{_safe_metadata_key(key)}")
                        if len(stripped) >= 128:
                            return stripped
                nested_field_sets = {
                    "image_url": PROXY_PROVIDER_IMAGE_FIELDS,
                    "input_audio": PROXY_PROVIDER_INPUT_AUDIO_FIELDS,
                    "audio": PROXY_PROVIDER_AUDIO_FIELDS,
                }
                for nested_name, nested_allowed in nested_field_sets.items():
                    nested = part.get(nested_name)
                    if not isinstance(nested, dict):
                        continue
                    for key in nested:
                        if key not in nested_allowed:
                            stripped.append(
                                f"messages[{index}].content[{part_index}].{nested_name}.{_safe_metadata_key(key)}"
                            )
                            if len(stripped) >= 128:
                                return stripped
        raw_calls = message.get("tool_calls")
        if isinstance(raw_calls, list):
            for call_index, call in enumerate(raw_calls):
                if not isinstance(call, dict):
                    continue
                for key in call:
                    if key not in PROXY_PROVIDER_TOOL_CALL_FIELDS:
                        stripped.append(
                            f"messages[{index}].tool_calls[{call_index}].{_safe_metadata_key(key)}"
                        )
                        if len(stripped) >= 128:
                            return stripped
                function = call.get("function")
                if isinstance(function, dict):
                    for key in function:
                        if key not in PROXY_PROVIDER_TOOL_CALL_FUNCTION_FIELDS:
                            stripped.append(
                                f"messages[{index}].tool_calls[{call_index}].function.{_safe_metadata_key(key)}"
                            )
                            if len(stripped) >= 128:
                                return stripped
        legacy_call = message.get("function_call")
        if isinstance(legacy_call, dict):
            for key in legacy_call:
                if key not in PROXY_PROVIDER_TOOL_CALL_FUNCTION_FIELDS:
                    stripped.append(f"messages[{index}].function_call.{_safe_metadata_key(key)}")
                    if len(stripped) >= 128:
                        return stripped
    return stripped


def _safe_model_label(value: Any, *, fallback: str = "", max_chars: int = PROXY_MAX_MODEL_CHARS) -> str:
    """Bound a model/provider label before it enters an Agent-visible envelope."""

    candidate = re.sub(r"[\x00-\x1f\x7f]", "", str(value or "")).strip()
    if not candidate:
        return str(fallback or "")[:max_chars]
    return candidate[:max_chars]


def _gateway_evidence_metadata() -> dict[str, str]:
    """Bind response evidence to the API process startup snapshot."""

    evidence = gateway_runtime_evidence()
    snapshot = evidence.get("snapshot") if isinstance(evidence.get("snapshot"), dict) else None
    source_fingerprint = str(evidence.get("source_fingerprint") or "")
    code_fingerprint = str(evidence.get("code_fingerprint") or "")
    if not source_fingerprint and snapshot is not None:
        source_fingerprint = gateway_source_fingerprint(snapshot)
    if not code_fingerprint and snapshot is not None:
        code_fingerprint = gateway_code_fingerprint(snapshot)
    return {
        "gateway_evidence_fingerprint": str(evidence.get("fingerprint") or ""),
        "gateway_source_fingerprint": source_fingerprint,
        "gateway_code_fingerprint": code_fingerprint,
        "gateway_runtime_started_at": str(evidence.get("started_at") or ""),
    }


def _apply_execution_contract_metadata(metadata: dict[str, Any]) -> None:
    """Add explicit execution facts without conflating boundary and blocking.

    ``decision_enforced_before_tool_execution`` is retained for older clients,
    but a true value on an allowed request used to be easy to misread as a
    block.  The four fields below are intentionally orthogonal:

    * ``execution_boundary_checked`` — the gateway evaluated the boundary;
    * ``blocked_before_execution`` — this request was stopped before a tool;
    * ``execution_allowed`` — the final decision permits the call;
    * ``execution_observed`` — the supervisor has a server-observed receipt.
    """

    decision = str(metadata.get("decision") or "")
    controlled = decision in CONTROL_DECISIONS
    raw_executions = metadata.get("managed_tool_executions")
    observed_receipts = metadata.get("tool_receipts_server_observed")
    observed = bool(
        isinstance(raw_executions, list)
        and any(
            isinstance(item, dict)
            and item.get("execution_observed_by_server") is True
            for item in raw_executions
        )
    ) or (isinstance(observed_receipts, int) and not isinstance(observed_receipts, bool) and observed_receipts > 0)
    if metadata.get("execution_observed_by_server") is True:
        observed = True
    boundary = str(metadata.get("execution_boundary") or "").strip()
    boundary_checked = bool(boundary) and (
        "request_guard" in metadata
        or "request_stage" in metadata
        or "gateway_contract_evidence" in metadata
        or "execution_mode" in metadata
    )
    blocked_before = controlled and not observed and str(metadata.get("execution_outcome") or "") in {
        "blocked-before-execution",
        "blocked-before-provider",
        "not-executed",
        "",
    }
    # An explicitly incomplete managed execution crossed the boundary even if
    # the final response is isolated, so it must not claim a pre-execution
    # block.
    if str(metadata.get("managed_status") or "") == "execution-incomplete":
        blocked_before = False
    metadata.update(
        {
            "execution_boundary_checked": boundary_checked,
            "blocked_before_execution": blocked_before,
            "execution_allowed": decision == "允许",
            "execution_observed": observed,
            # Compatibility field: its semantics now match the precise block
            # fact instead of being populated with a default true value.
            "decision_enforced_before_tool_execution": blocked_before,
        }
    )


def _validate_proxy_request(payload: dict[str, Any]) -> None:
    """Validate the parts of the OpenAI contract that affect the security boundary.

    Provider-specific fields remain pass-through, but messages, tool definitions,
    and their sizes must be bounded before a request can reach a model provider.
    """
    if not isinstance(payload, dict):
        raise ValueError("OpenAI 兼容请求必须是 JSON 对象")
    try:
        serialized_size = len(
            json.dumps(payload, ensure_ascii=False, default=str, separators=(",", ":")).encode("utf-8")
        )
    except (TypeError, ValueError, RecursionError) as exc:
        raise ValueError("OpenAI 兼容请求无法序列化") from exc
    if serialized_size > PROXY_MAX_REQUEST_CHARS:
        raise ValueError(f"OpenAI 兼容请求超过 {PROXY_MAX_REQUEST_CHARS} 字节安全上限")
    model = payload.get("model")
    if not isinstance(model, str) or not model.strip():
        raise ValueError("OpenAI 兼容请求必须包含非空 model 字符串")
    if len(model.strip()) > PROXY_MAX_MODEL_CHARS:
        raise ValueError(f"model 不能超过 {PROXY_MAX_MODEL_CHARS} 个字符")
    if _safe_model_label(model) != model.strip():
        raise ValueError("model 不能包含控制字符")
    if "stream" in payload and not isinstance(payload.get("stream"), bool):
        raise ValueError("stream 必须是布尔值")
    stream_options = payload.get("stream_options")
    if stream_options is not None:
        if payload.get("stream") is not True:
            raise ValueError("stream_options 仅可在 stream=true 时使用")
        if not isinstance(stream_options, dict):
            raise ValueError("stream_options 必须是对象")
        supported_stream_options = {"include_usage", "include_obfuscation"}
        unknown_stream_options = sorted(set(stream_options) - supported_stream_options)
        if unknown_stream_options:
            raise ValueError(f"stream_options 包含不支持的字段：{', '.join(unknown_stream_options)}")
        for option_name, option_value in stream_options.items():
            if not isinstance(option_value, bool):
                raise ValueError(f"stream_options.{option_name} 必须是布尔值")
    _validate_generation_controls(payload)
    # Validate the complete materialized JSON tree, not only messages and tool
    # schemas.  Otherwise a valid-looking top-level field (for example
    # ``logit_bias``) could carry NaN/Infinity or a deep/large object through
    # the projection and be interpreted differently by the Provider.  Keep the
    # dedicated generation-control errors above as the more actionable contract
    # message for temperature/top_p and the other bounded knobs.
    request_value_issue = validate_json_value_limits(
        payload,
        path="request",
        max_nodes=PROXY_MAX_REQUEST_JSON_NODES,
    )
    if request_value_issue:
        raise ValueError(request_value_issue)
    supervisor_extension = payload.get("agent_supervisor")
    if supervisor_extension is not None:
        if not isinstance(supervisor_extension, dict):
            raise ValueError("agent_supervisor 必须是对象")
        try:
            extension_size = len(
                json.dumps(supervisor_extension, ensure_ascii=False, default=str, separators=(",", ":"))
            )
        except (TypeError, ValueError, RecursionError) as exc:
            raise ValueError("agent_supervisor 扩展无法序列化") from exc
        if extension_size > PROXY_MAX_SUPERVISOR_EXTENSION_CHARS:
            raise ValueError(
                f"agent_supervisor 扩展不能超过 {PROXY_MAX_SUPERVISOR_EXTENSION_CHARS} 个字符"
            )
        _validate_supervisor_extension(supervisor_extension)
    messages = payload.get("messages")
    if not isinstance(messages, list) or not messages:
        raise ValueError("OpenAI 兼容请求必须包含非空 messages 数组")
    if len(messages) > PROXY_MAX_MESSAGES:
        raise ValueError(f"messages 数量不能超过 {PROXY_MAX_MESSAGES}")
    total_text = 0
    for index, message in enumerate(messages):
        if not isinstance(message, dict):
            raise ValueError(f"messages[{index}] 必须是对象")
        message_value_issue = validate_json_value_limits(message, path=f"messages[{index}]")
        if message_value_issue:
            raise ValueError(message_value_issue)
        role = str(message.get("role") or "").strip().lower()
        if role not in PROXY_ALLOWED_MESSAGE_ROLES:
            raise ValueError(f"messages[{index}] 使用不支持的 role：{role or 'empty'}")
        if "name" in message:
            name = message.get("name")
            if (
                not isinstance(name, str)
                or len(name) > PROXY_MAX_MESSAGE_NAME_CHARS
                or (name and not PROXY_SAFE_IDENTIFIER_RE.fullmatch(name))
            ):
                raise ValueError(f"messages[{index}].name 长度或类型无效")
        raw_content = message.get("content")
        if raw_content is not None and not isinstance(raw_content, (str, list)):
            raise ValueError(f"messages[{index}].content 必须是字符串、内容块数组或 null")
        if isinstance(raw_content, list):
            if len(raw_content) > PROXY_MAX_CONTENT_PARTS:
                raise ValueError(f"messages[{index}].content 内容块不能超过 {PROXY_MAX_CONTENT_PARTS} 个")
            for part_index, part in enumerate(raw_content):
                if not isinstance(part, dict):
                    raise ValueError(f"messages[{index}].content[{part_index}] 必须是对象")
        content = _content_to_text(message.get("content"))
        if len(content) > PROXY_MAX_MESSAGE_CHARS:
            raise ValueError(f"messages[{index}] 内容超过 {PROXY_MAX_MESSAGE_CHARS} 个字符")
        total_text += len(content)
        extension_text = _message_extension_text(message)
        if len(extension_text) > PROXY_MAX_MESSAGE_CHARS:
            raise ValueError(f"messages[{index}] 的扩展字段超过 {PROXY_MAX_MESSAGE_CHARS} 个字符")
        total_text += len(extension_text)
    if total_text > PROXY_MAX_TOTAL_TEXT_CHARS:
        raise ValueError(f"消息总文本不能超过 {PROXY_MAX_TOTAL_TEXT_CHARS} 个字符")
    provider_context_text = _provider_context_text(payload)
    if len(provider_context_text) > PROXY_MAX_TOTAL_TEXT_CHARS:
        raise ValueError(f"Provider 上下文字段超过 {PROXY_MAX_TOTAL_TEXT_CHARS} 个字符")
    structured_chars = _validate_proxy_message_contract(messages)
    if structured_chars > PROXY_MAX_TOTAL_STRUCTURED_CHARS:
        raise ValueError(f"消息中的工具调用结构不能超过 {PROXY_MAX_TOTAL_STRUCTURED_CHARS} 个字符")

    raw_tools = payload.get("tools")
    if raw_tools is not None and not isinstance(raw_tools, list):
        raise ValueError("tools 必须是数组")
    if isinstance(raw_tools, list) and len(raw_tools) > PROXY_MAX_TOOLS:
        raise ValueError(f"tools 数量不能超过 {PROXY_MAX_TOOLS}")
    raw_functions = payload.get("functions")
    if raw_functions is not None and not isinstance(raw_functions, list):
        raise ValueError("functions 必须是数组")
    if isinstance(raw_functions, list) and len(raw_functions) > PROXY_MAX_TOOLS:
        raise ValueError(f"functions 数量不能超过 {PROXY_MAX_TOOLS}")
    if raw_tools is None and raw_functions is None:
        _validate_tool_choice(payload.get("tool_choice"), set())
        return
    names: set[str] = set()
    definitions: list[tuple[str, int, dict[str, Any], dict[str, Any]]] = []
    if isinstance(raw_tools, list):
        for index, raw_tool in enumerate(raw_tools):
            if not isinstance(raw_tool, dict):
                raise ValueError(f"tools[{index}] 必须是对象")
            if raw_tool.get("type") != "function":
                raise ValueError("tools[{0}].type 仅支持 function；其他工具类型没有经过网关执行契约校验".format(index))
            function = raw_tool.get("function")
            if not isinstance(function, dict):
                raise ValueError(f"tools[{index}] 缺少 function 定义")
            definitions.append(("tools", index, raw_tool, function))
    if isinstance(raw_functions, list):
        for index, function in enumerate(raw_functions):
            if not isinstance(function, dict):
                raise ValueError(f"functions[{index}] 必须是对象")
            definitions.append(("functions", index, {"type": "function", "function": function}, function))

    for source, index, _raw_definition, function in definitions:
        field_name = f"{source}[{index}]"
        if not isinstance(function, dict):
            raise ValueError(f"{field_name} 缺少 function 定义")
        name = str(function.get("name") or "").strip()
        # Tool names are protocol identifiers, but malformed human-readable
        # names must still reach the tool-description scanner so the gateway
        # can return a redacted quarantine decision instead of reflecting an
        # HTTP validation error.  Reject only control/bidi/zero-width format
        # characters here; clean non-protocol names are quarantined below.
        if not name or len(name) > PROXY_MAX_TOOL_NAME_CHARS or any(
            ord(char) < 0x20
            or ord(char) == 0x7F
            or 0x200B <= ord(char) <= 0x200F
            or 0x202A <= ord(char) <= 0x202E
            or 0x2060 <= ord(char) <= 0x2064
            or 0x2066 <= ord(char) <= 0x2069
            or ord(char) == 0xFEFF
            for char in name
        ):
            raise ValueError(f"{field_name} 的 function.name 无效")
        if name in names:
            raise ValueError(f"{source} 包含重复 function.name：{name}")
        names.add(name)
        description = function.get("description")
        if description is not None and len(str(description)) > PROXY_MAX_TOOL_DESCRIPTION_CHARS:
            raise ValueError(f"工具 {name} 的 description 超过 {PROXY_MAX_TOOL_DESCRIPTION_CHARS} 个字符")
        parameters = function.get("parameters")
        if parameters is not None and not isinstance(parameters, dict):
            raise ValueError(f"工具 {name} 的 parameters 必须是对象")
        if parameters is not None:
            value_issue = validate_json_value_limits(parameters, path=f"{field_name}.parameters")
            if value_issue:
                raise ValueError(value_issue)
            try:
                schema_size = len(json.dumps(parameters, ensure_ascii=False, default=str, separators=(",", ":")))
            except (TypeError, ValueError, RecursionError) as exc:
                raise ValueError(f"工具 {name} 的 parameters schema 无法序列化") from exc
            if schema_size > PROXY_MAX_TOOL_SCHEMA_CHARS:
                raise ValueError(f"工具 {name} 的 parameters schema 超过 {PROXY_MAX_TOOL_SCHEMA_CHARS} 个字符")

    legacy_selector = payload.get("function_call")
    if legacy_selector is not None:
        if isinstance(legacy_selector, str):
            if legacy_selector not in {"auto", "none"}:
                raise ValueError("function_call 必须是 auto、none 或包含 name 的对象")
        elif isinstance(legacy_selector, dict):
            selector_name = legacy_selector.get("name")
            if (
                not isinstance(selector_name, str)
                or not selector_name.strip()
                or len(selector_name.strip()) > PROXY_MAX_TOOL_NAME_CHARS
                or not PROXY_SAFE_IDENTIFIER_RE.fullmatch(selector_name.strip())
            ):
                raise ValueError("function_call.name 无效")
            if selector_name.strip() not in names:
                raise ValueError("function_call.name 未在 tools 或 functions 中声明")
        else:
            raise ValueError("function_call 必须是 auto、none 或包含 name 的对象")

    _validate_tool_choice(payload.get("tool_choice"), names)


def _validate_tool_choice(value: Any, declared_names: set[str]) -> None:
    """Validate modern tool selection before it reaches a Provider.

    ``tool_choice`` is a protocol control rather than a tool execution, but a
    malformed or undeclared selector can make a compatible Provider invent a
    capability that the response gate cannot bind to a caller declaration.
    """

    if value is None:
        return
    if isinstance(value, str):
        if value not in {"auto", "none", "required"}:
            raise ValueError("tool_choice 必须是 auto、none、required 或 function 对象")
        return
    if not isinstance(value, dict):
        raise ValueError("tool_choice 必须是字符串或 function 对象")
    if value.get("type") != "function":
        raise ValueError("tool_choice.type 必须是 function")
    function = value.get("function")
    if not isinstance(function, dict):
        raise ValueError("tool_choice.function 必须是对象")
    name = function.get("name")
    if (
        not isinstance(name, str)
        or not name.strip()
        or len(name.strip()) > PROXY_MAX_TOOL_NAME_CHARS
        or not PROXY_SAFE_IDENTIFIER_RE.fullmatch(name.strip())
    ):
        raise ValueError("tool_choice.function.name 无效")
    if name.strip() not in declared_names:
        raise ValueError("tool_choice.function.name 未在 tools 或 functions 中声明")


def validate_openai_proxy_request(payload: dict[str, Any]) -> None:
    """Validate an OpenAI request before a comparison endpoint sends a baseline.

    The normal completion path performs this validation internally.  The
    comparison path needs the same contract check before intentionally sending
    an unprotected observation request, so it must not duplicate the rules.
    """

    _validate_proxy_request(payload)


def _validate_generation_controls(payload: dict[str, Any]) -> None:
    """Bound provider generation knobs before the request leaves the gateway.

    These values are not security policy decisions, but they are still an
    attack surface: ``n`` multiplies provider work and token budgets directly
    affect latency and spend.  Validate them here so every proxy mode shares
    the same finite contract, including streaming and managed requests.
    """

    raw_n = payload.get("n")
    if raw_n is not None:
        if isinstance(raw_n, bool) or not isinstance(raw_n, int):
            raise ValueError("n 必须是整数")
        if raw_n < 1 or raw_n > PROXY_MAX_COMPLETIONS:
            raise ValueError(f"n 必须在 1 到 {PROXY_MAX_COMPLETIONS} 之间")

    raw_max_tokens = payload.get("max_tokens")
    raw_max_completion_tokens = payload.get("max_completion_tokens")
    raw_max_output_tokens = payload.get("max_output_tokens")
    configured_output_limits = [
        ("max_tokens", raw_max_tokens),
        ("max_completion_tokens", raw_max_completion_tokens),
        ("max_output_tokens", raw_max_output_tokens),
    ]
    if sum(value is not None for _, value in configured_output_limits) > 1:
        raise ValueError("max_tokens、max_completion_tokens 与 max_output_tokens 只能设置一个，不能同时设置")
    for field_name, raw_value in (
        ("max_tokens", raw_max_tokens),
        ("max_completion_tokens", raw_max_completion_tokens),
        ("max_output_tokens", raw_max_output_tokens),
    ):
        if raw_value is None:
            continue
        if isinstance(raw_value, bool) or not isinstance(raw_value, int):
            raise ValueError(f"{field_name} 必须是整数")
        if raw_value < 1 or raw_value > PROXY_MAX_OUTPUT_TOKENS:
            raise ValueError(f"{field_name} 必须在 1 到 {PROXY_MAX_OUTPUT_TOKENS} 之间")

    raw_temperature = payload.get("temperature")
    if raw_temperature is not None:
        _validate_generation_float("temperature", raw_temperature, minimum=0.0, maximum=PROXY_MAX_TEMPERATURE)
    raw_top_p = payload.get("top_p")
    if raw_top_p is not None:
        _validate_generation_float("top_p", raw_top_p, minimum=0.0, maximum=PROXY_MAX_TOP_P)


def _validate_supervisor_extension(options: dict[str, Any]) -> None:
    """Validate boundary-changing extension fields without silently coercing typos."""

    if "mode" in options:
        _validated_proxy_mode(options)
    for field_name in ("agent_id", "session_id", "task_id"):
        value = options.get(field_name)
        if value is None:
            continue
        if not isinstance(value, str) or len(value.strip()) > 160 or any(ord(char) < 0x20 for char in value):
            raise ValueError(f"agent_supervisor.{field_name} 长度或类型无效")
    if "max_tool_rounds" in options:
        value = options.get("max_tool_rounds")
        if isinstance(value, bool) or not isinstance(value, int) or value < 1 or value > 8:
            raise ValueError("agent_supervisor.max_tool_rounds 必须是 1 到 8 的整数")
    value = options.get("target_provider_profile")
    if value is not None and (
        not isinstance(value, str)
        or len(value.strip()) > 40
        or not PROXY_SAFE_IDENTIFIER_RE.fullmatch(value.strip())
    ):
        raise ValueError("agent_supervisor.target_provider_profile 格式无效")
    value = options.get("target_model")
    if value is not None and (not isinstance(value, str) or not value.strip() or _safe_model_label(value) != value.strip()):
        raise ValueError("agent_supervisor.target_model 格式无效")
    raw_receipts = options.get("tool_receipts")
    if raw_receipts is None:
        return
    if not isinstance(raw_receipts, dict) or len(raw_receipts) > PROXY_MAX_PROVIDER_TOOL_CALLS:
        raise ValueError("agent_supervisor.tool_receipts 必须是有限的对象")
    for raw_call_id, raw_reference in raw_receipts.items():
        call_id = str(raw_call_id).strip()
        reference = raw_reference.get("audit_id") if isinstance(raw_reference, dict) else raw_reference
        audit_id = str(reference or "").strip()
        if not PROXY_SAFE_IDENTIFIER_RE.fullmatch(call_id) or not PROXY_SAFE_IDENTIFIER_RE.fullmatch(audit_id):
            raise ValueError("agent_supervisor.tool_receipts 包含无效调用或审计 ID")


def _validate_generation_float(field_name: str, value: Any, *, minimum: float, maximum: float) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)):
        raise ValueError(f"{field_name} 必须是有限数字")
    numeric = float(value)
    if numeric < minimum or numeric > maximum:
        raise ValueError(f"{field_name} 必须在 {minimum:g} 到 {maximum:g} 之间")


def _validate_proxy_message_contract(messages: list[Any]) -> int:
    """Validate tool-result provenance before the conversation reaches a provider.

    A caller can otherwise forge a ``tool`` message and make an arbitrary string
    look like a trusted tool result.  The check intentionally stays within the
    OpenAI-compatible message contract: it does not inspect model semantics, it
    only requires every tool result to refer to a preceding assistant call.
    """
    pending_tool_calls: set[str] = set()
    pending_function_calls: list[str] = []
    seen_tool_call_ids: set[str] = set()
    structured_chars = 0
    for index, message in enumerate(messages):
        if not isinstance(message, dict):
            continue
        role = str(message.get("role") or "").strip().lower()
        if role == "assistant":
            raw_tool_calls = message.get("tool_calls")
            if raw_tool_calls is not None:
                if not isinstance(raw_tool_calls, list):
                    raise ValueError(f"messages[{index}].tool_calls 必须是数组")
                if "function_call" in message:
                    raise ValueError(f"messages[{index}] 不得同时包含 tool_calls 与 function_call")
                if len(raw_tool_calls) > PROXY_MAX_TOOL_CALLS_PER_MESSAGE:
                    raise ValueError(
                        f"messages[{index}].tool_calls 不能超过 {PROXY_MAX_TOOL_CALLS_PER_MESSAGE} 个"
                    )
                for call_index, call in enumerate(raw_tool_calls):
                    if not isinstance(call, dict):
                        raise ValueError(f"messages[{index}].tool_calls[{call_index}] 必须是对象")
                    call_id = str(call.get("id") or "").strip()
                    if not call_id or len(call_id) > PROXY_MAX_TOOL_CALL_ID_CHARS or not PROXY_SAFE_IDENTIFIER_RE.fullmatch(call_id):
                        raise ValueError(f"messages[{index}].tool_calls[{call_index}] 缺少有效调用 ID")
                    if call_id in seen_tool_call_ids:
                        raise ValueError(f"请求包含重复 tool_call ID：{call_id}")
                    function = call.get("function")
                    if not isinstance(function, dict):
                        raise ValueError(f"messages[{index}].tool_calls[{call_index}] 缺少 function.name")
                    function_name = function.get("name")
                    if not isinstance(function_name, str) or not function_name.strip():
                        raise ValueError(f"messages[{index}].tool_calls[{call_index}] 缺少 function.name")
                    if len(function_name) > PROXY_MAX_TOOL_NAME_CHARS or not PROXY_SAFE_IDENTIFIER_RE.fullmatch(function_name):
                        raise ValueError(f"messages[{index}].tool_calls[{call_index}] 的 function.name 超出长度限制")
                    raw_arguments = function.get("arguments", {})
                    if not isinstance(raw_arguments, str):
                        value_issue = validate_json_value_limits(
                            raw_arguments,
                            path=f"messages[{index}].tool_calls[{call_index}].arguments",
                        )
                        if value_issue:
                            raise ValueError(value_issue)
                    argument_text = (
                        raw_arguments
                        if isinstance(raw_arguments, str)
                        else json.dumps(raw_arguments, ensure_ascii=False, default=str, separators=(",", ":"))
                    )
                    if len(argument_text) > PROXY_MAX_TOOL_ARGUMENT_CHARS:
                        raise ValueError(
                            f"messages[{index}].tool_calls[{call_index}] 的 arguments 超过 {PROXY_MAX_TOOL_ARGUMENT_CHARS} 个字符"
                        )
                    structured_chars += len(function_name) + len(argument_text)
                    seen_tool_call_ids.add(call_id)
                    pending_tool_calls.add(call_id)
            legacy_call = message.get("function_call")
            if legacy_call is not None and (
                not isinstance(legacy_call, dict) or not str(legacy_call.get("name") or "").strip()
            ):
                raise ValueError(f"messages[{index}].function_call 缺少 function.name")
            if isinstance(legacy_call, dict):
                function_name = legacy_call.get("name")
                if not isinstance(function_name, str) or not function_name.strip():
                    raise ValueError(f"messages[{index}].function_call 缺少 function.name")
                if len(function_name) > PROXY_MAX_TOOL_NAME_CHARS or not PROXY_SAFE_IDENTIFIER_RE.fullmatch(function_name):
                    raise ValueError(f"messages[{index}].function_call 的 name 超出长度限制")
                raw_arguments = legacy_call.get("arguments", {})
                if not isinstance(raw_arguments, str):
                    value_issue = validate_json_value_limits(
                        raw_arguments,
                        path=f"messages[{index}].function_call.arguments",
                    )
                    if value_issue:
                        raise ValueError(value_issue)
                argument_text = (
                    raw_arguments
                    if isinstance(raw_arguments, str)
                    else json.dumps(raw_arguments, ensure_ascii=False, default=str, separators=(",", ":"))
                )
                if len(argument_text) > PROXY_MAX_TOOL_ARGUMENT_CHARS:
                    raise ValueError(
                        f"messages[{index}].function_call 的 arguments 超过 {PROXY_MAX_TOOL_ARGUMENT_CHARS} 个字符"
                    )
                structured_chars += len(function_name) + len(argument_text)
                pending_function_calls.append(function_name.strip())
        elif role == "tool":
            call_id = str(message.get("tool_call_id") or "").strip()
            if not call_id or len(call_id) > PROXY_MAX_TOOL_CALL_ID_CHARS or not PROXY_SAFE_IDENTIFIER_RE.fullmatch(call_id):
                raise ValueError(f"messages[{index}] 的 tool_call_id 无效")
            if call_id not in pending_tool_calls:
                raise ValueError(f"messages[{index}] 的 tool_call_id 未对应前序 assistant tool_call")
            pending_tool_calls.remove(call_id)
        elif role == "function":
            function_name = str(message.get("name") or "").strip()
            if not function_name:
                raise ValueError(f"messages[{index}] 的 function 消息缺少 name")
            if function_name not in pending_function_calls:
                raise ValueError(f"messages[{index}] 的 function 消息未对应前序 assistant function_call")
            pending_function_calls.remove(function_name)
    return structured_chars


def _proxy_tool_receipts_required(security_context: dict[str, Any] | None) -> bool:
    """Require an execution receipt for tool results on authenticated HTTP calls.

    The network proxy defaults to the stronger contract because a caller can
    forge a ``tool`` message even when its preceding assistant call was genuine.
    """
    return security_context is not None and (
        _env_bool(PROXY_TOOL_RECEIPTS_ENV, True) or proxy_server_observed_receipts_required()
    )


def _proxy_session_id(
    options: dict[str, Any],
    security_context: dict[str, Any] | None,
    request_id: str,
) -> tuple[str, bool]:
    """Resolve a stable Agent conversation id for multi-turn evidence.

    The HTTP header is preferred because it is outside the model payload and is
    attached to the authenticated request.  The body option remains available
    for SDKs that cannot set custom headers.  A missing id falls back to the
    request id, which keeps single-turn compatibility but is marked as such in
    the response metadata.
    """
    context_value = str(security_context.get("session_id") or "").strip() if isinstance(security_context, dict) else ""
    body_value = str(options.get("session_id") or "").strip()
    for source, candidate in (("请求头", context_value), ("请求体", body_value)):
        if candidate and (len(candidate) > 160 or not PROXY_SAFE_IDENTIFIER_RE.fullmatch(candidate)):
            raise ValueError(f"代理 session_id（{source}）长度或格式无效")
    if context_value and body_value and context_value != body_value:
        raise ValueError("代理请求头与请求体中的 session_id 不一致")
    candidate = context_value or body_value
    return candidate or request_id, bool(candidate)


def _proxy_task_id(
    options: dict[str, Any],
    security_context: dict[str, Any] | None,
) -> tuple[str, bool]:
    """Resolve an out-of-model task identifier without forwarding it upstream."""

    header_value = security_context.get("task_id") if isinstance(security_context, dict) else ""
    body_value = options.get("task_id")
    try:
        header_task_id = normalize_task_id(header_value)
        body_task_id = normalize_task_id(body_value)
    except ValueError as exc:
        raise ValueError(f"代理 task_id（请求头或请求体）{exc}") from exc
    if header_task_id and body_task_id and header_task_id != body_task_id:
        raise ValueError("X-Agent-Task-ID 与 agent_supervisor.task_id 不一致")
    task_id = header_task_id or body_task_id
    return task_id, bool(task_id)


def _task_response_metadata(binding: Any, *, provided: bool) -> dict[str, Any]:
    context = task_audit_context(binding)
    return {
        "task_id": context["task_id"],
        "task_profile_fingerprint": context["task_profile_fingerprint"],
        "policy_revision": context["policy_revision"],
        "task_scope": context["task_scope"],
        "task_profile_enforced": bool(context["task_profile_required"]),
        "task_id_provided": provided,
    }


def _validate_proxy_tool_receipts(
    messages: list[Any],
    options: dict[str, Any],
    *,
    agent_id: str,
    session_id: str,
    request_hash: str,
    require_server_observed: bool,
) -> dict[str, int]:
    raw_receipts = options.get("tool_receipts")
    if not isinstance(raw_receipts, dict):
        raw_receipts = {}

    provider_calls: dict[str, tuple[dict[str, Any] | None, str]] = {}
    pending_provider_call_ids: set[str] = set()
    summary = {"verified": 0, "server_observed": 0, "caller_declared": 0}
    for message in messages:
        if not isinstance(message, dict):
            continue
        role = str(message.get("role") or "").strip().lower()
        if role == "assistant":
            raw_calls = message.get("tool_calls")
            if not isinstance(raw_calls, list):
                continue
            for raw_call in raw_calls:
                call_id = str(raw_call.get("id") or "").strip() if isinstance(raw_call, dict) else ""
                parsed, issue = _parse_transparent_tool_call(raw_call)
                provider_calls[call_id] = (parsed, issue)
                if call_id:
                    pending_provider_call_ids.add(call_id)
            continue
        if role == "function":
            raise ValueError("透明代理的严格回执模式暂不接受 legacy function 消息，请使用 role=tool/tool_call_id")
        if role != "tool":
            continue

        call_id = str(message.get("tool_call_id") or "").strip()
        reference = raw_receipts.get(call_id)
        audit_id = str(reference.get("audit_id") if isinstance(reference, dict) else reference or "").strip()
        if not audit_id:
            raise ValueError(f"tool_call_id {call_id} 缺少 agent_supervisor.tool_receipts 回执绑定")
        parsed, issue = provider_calls.get(call_id, (None, "未找到前序 assistant tool_call"))
        if issue or parsed is None:
            raise ValueError(f"tool_call_id {call_id} 的原始工具调用无效：{issue or 'unknown'}")
        audit_log = load_audit_log(audit_id)
        receipt = load_execution_receipt(audit_id)
        if not audit_log or not receipt:
            raise ValueError(f"tool_call_id {call_id} 的执行回执不存在：{audit_id}")
        stored_audit_hash = str(audit_log.get("audit_hash") or "")
        if not stored_audit_hash or stored_audit_hash != audit_hash(audit_log):
            raise ValueError(f"tool_call_id {call_id} 的原始审计记录完整性校验失败")
        stored_audit_signature = str(audit_log.get("audit_signature") or "")
        if audit_signature_required() and not stored_audit_signature:
            raise ValueError(f"tool_call_id {call_id} 的原始审计记录缺少必需的 HMAC 签名")
        if stored_audit_signature and not verify_audit_signature(stored_audit_hash, stored_audit_signature):
            raise ValueError(f"tool_call_id {call_id} 的原始审计签名校验失败")
        if str(audit_log.get("agent_id") or "") != agent_id or str(receipt.get("agent_id") or "") != agent_id:
            raise ValueError(f"tool_call_id {call_id} 的执行回执不属于当前 Agent")
        stage_context = audit_log.get("stage_context")
        if not isinstance(stage_context, dict):
            raise ValueError(f"tool_call_id {call_id} 的执行回执缺少 Provider 调用上下文")
        expected_session = str(stage_context.get("session_id") or "").strip()
        if expected_session != session_id:
            raise ValueError(f"tool_call_id {call_id} 的执行回执不属于当前 Agent 会话")
        expected_call_id = str(stage_context.get("provider_call_id") or "").strip()
        if expected_call_id != call_id:
            raise ValueError(f"tool_call_id {call_id} 的执行回执未绑定原始 Provider 调用")
        if str(audit_log.get("source_app") or "") != "openai-compatible-proxy":
            raise ValueError(f"tool_call_id {call_id} 的执行回执来源不是当前 OpenAI 网关")
        expected_tool_hash = tool_call_hash({"tool": parsed["tool"], "arguments": parsed["arguments"]})
        if str(audit_log.get("tool_call_hash") or "") != expected_tool_hash:
            raise ValueError(f"tool_call_id {call_id} 的执行回执与工具参数不一致")
        audit_hash_value = str(audit_log.get("audit_hash") or "")
        if not audit_hash_value or str(receipt.get("audit_hash") or "") != audit_hash_value:
            raise ValueError(f"tool_call_id {call_id} 的执行回执未绑定当前审计记录")
        if str(receipt.get("tool_call_hash") or "") != expected_tool_hash or not verify_execution_receipt(receipt):
            raise ValueError(f"tool_call_id {call_id} 的执行回执完整性校验失败")
        if str(receipt.get("status") or "") not in {"completed", "failed"}:
            raise ValueError(f"tool_call_id {call_id} 的执行回执未证明工具已完成或失败")
        if str(receipt.get("result_hash") or "") != tool_result_hash(message.get("content")):
            raise ValueError(f"tool_call_id {call_id} 的工具结果与执行回执 result_hash 不一致")
        server_observed = (
            str(receipt.get("execution_evidence") or "") == "server-observed"
            and receipt.get("execution_observed_by_server") is True
        )
        if require_server_observed and not server_observed:
            raise ValueError(
                f"tool_call_id {call_id} 的执行回执仅为调用方声明；当前安全配置要求服务端观察证据"
            )
        try:
            claim_execution_receipt_use(
                audit_id=audit_id,
                agent_id=agent_id,
                session_id=session_id,
                request_hash=request_hash,
                receipt_hash=str(receipt.get("receipt_hash") or ""),
            )
        except ExecutionReceiptConflictError as exc:
            raise ValueError(str(exc)) from exc
        pending_provider_call_ids.discard(call_id)
        summary["verified"] += 1
        summary["server_observed" if server_observed else "caller_declared"] += 1
    if pending_provider_call_ids:
        # An assistant tool call without a matching, verified tool result is
        # caller-authored execution history.  Forwarding it would let a client
        # assert that a side effect happened (or smuggle a forged tool call into
        # the next Provider turn) without crossing the receipt boundary.
        raise ValueError("存在未绑定执行回执的 assistant tool_call")
    return summary


def _extract_untrusted_prompt(messages: list[Any]) -> str:
    """Return all caller-supplied message content for the pre-provider guard.

    ``system`` and ``developer`` are protocol roles, not an authentication
    boundary.  The gateway cannot know whether a caller forged those roles, so
    every message supplied by the client is inspected before forwarding.
    """
    parts: list[str] = []
    for item in messages:
        if not isinstance(item, dict):
            continue
        role = str(item.get("role") or "").lower()
        if role not in PROXY_ALLOWED_MESSAGE_ROLES:
            continue
        content_parts = [_security_content_to_text(item.get("content"))]
        for field in ("tool_calls", "function_call", "tool_call_id", "name"):
            if field in item:
                content_parts.append(f"{field}={_security_content_to_text(item.get(field))}")
        extension_text = _message_extension_text(item)
        if extension_text:
            content_parts.append(f"message_extensions={extension_text}")
        content = "\n".join(part for part in content_parts if part)
        if content:
            parts.append(f"{role}: {content}")
    return "\n".join(parts)


def _security_content_to_text(content: Any) -> str:
    """Serialize multimodal/tool content so non-text blocks are not invisible to guards."""
    if isinstance(content, str):
        return content
    if content is None:
        return ""
    return json.dumps(content, ensure_ascii=False, default=str, separators=(",", ":"))


def _message_extension_text(message: dict[str, Any]) -> str:
    """Serialize non-standard message fields for the input trust boundary.

    OpenAI-compatible clients and Agent frameworks frequently attach fields
    such as ``metadata``, ``trace`` or ``x-*`` to a message. Those fields are
    not part of the minimum Chat Completions contract, but a Provider may still
    copy them into its prompt. Treat them as untrusted model-visible input so
    an injection cannot hide outside ``content`` or known tool fields.
    """

    standard_fields = {
        "role",
        "content",
        "name",
        "tool_calls",
        "function_call",
        "tool_call_id",
    }
    extensions = {key: value for key, value in message.items() if key not in standard_fields}
    if not extensions:
        return ""
    return json.dumps(extensions, ensure_ascii=False, default=str, sort_keys=True, separators=(",", ":"))


def _provider_context_text(payload: dict[str, Any]) -> str:
    """Serialize free-form standard fields for the pre-Provider trust scan.

    The gateway cannot assume every OpenAI-compatible Provider treats these
    fields as inert metadata.  Detection uses a bounded security view while
    the original payload remains unchanged for a clean request.
    """

    if not isinstance(payload, dict):
        return ""
    parts: list[str] = []
    for field_name in sorted(PROXY_PROVIDER_CONTEXT_FIELDS):
        if field_name not in payload:
            continue
        value = _security_content_to_text(payload.get(field_name))
        if value:
            parts.append(f"{field_name}={value}")
    return "\n".join(parts)


def _proxy_request_guard(
    *,
    payload: dict[str, Any],
    request_id: str,
    conversation_id: str,
    agent_id: str,
    request_hash: str,
    task_context: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Inspect untrusted conversation content before sending it to a provider."""
    messages = payload.get("messages")
    if not isinstance(messages, list):
        return None
    untrusted_parts = [_extract_untrusted_prompt(messages), _provider_context_text(payload)]
    untrusted_prompt = "\n".join(part for part in untrusted_parts if part)
    if not untrusted_prompt:
        return None
    audit_excerpt = _security_excerpt(untrusted_prompt)
    decision: GuardDecision = decide(
        {"tool": "model.respond", "arguments": {"topic": untrusted_prompt[:4_000]}},
        guard_enabled=True,
        prompt=untrusted_prompt,
        context_sources=["openai-compatible-client", "request-message"],
        agent_id=agent_id,
    )
    if decision.decision not in CONTROL_DECISIONS:
        return None
    audit_result = evaluate_agent_event(
        {
            "conversation_id": conversation_id,
            "agent_id": agent_id,
            "agent_role": "openai-compatible-agent",
            "source_app": "openai-compatible-proxy",
            "model_input": audit_excerpt,
            "model_output": "",
            "context_sources": ["openai-compatible-client", "request-message"],
            "tool_call": {
                "tool": "model.respond",
                "arguments": {"topic": untrusted_prompt[:4_000]},
                "risk_hint": "prompt_injection",
            },
            "stage_context": {
                "request_id": request_id,
                "request_hash": request_hash,
                "provider_called": False,
                **(task_context or {}),
            },
        },
        guard_enabled=True,
        execute_managed=False,
        receipt_required=True,
    )
    return {
        "decision": audit_result.get("decision", decision.decision),
        "policy_id": audit_result.get("policy_id", decision.policy_id),
        # Do not echo caller-controlled prompt text through the model-visible
        # response metadata. The full excerpt remains in the signed audit
        # record for operators, while the Agent receives only a boundary fact.
        "reason": _safe_model_boundary_reason("request"),
        "risk_score": audit_result.get("risk_score", decision.risk_score),
        "audit_id": audit_result.get("audit_id", ""),
        "risk_factors": audit_result.get("risk_factors", decision.risk_factors),
        "untrusted_message_excerpt": "原文已隐藏；请通过审计 ID 和请求 Hash 在运营侧复核。",
        "untrusted_message_hash": hashlib.sha256(untrusted_prompt.encode("utf-8")).hexdigest(),
    }


def _proxy_tool_result_guard(
    *,
    messages: list[Any],
    request_id: str,
    conversation_id: str,
    agent_id: str,
    request_hash: str,
    task_context: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """隔离 OpenAI ``role=tool``/``function`` 返回值中的间接提示注入。

    工具结果的 Hash 只证明数据完整性，不证明内容可以被模型当作指令。
    因此在下一轮 Provider 请求前，工具结果仍然必须经过独立的上下文扫描。
    """
    findings: list[dict[str, Any]] = []
    excerpts: list[str] = []
    for index, message in enumerate(messages):
        if not isinstance(message, dict):
            continue
        role = str(message.get("role") or "").strip().lower()
        if role not in {"tool", "function"}:
            continue
        content = _security_content_to_text(message.get("content"))
        if not content:
            continue
        scan = scan_text(content, quarantine_on_truncate=True)
        if scan.verdict == "clean":
            continue
        findings.append(
            {
                "message_index": index,
                "role": role,
                "verdict": scan.verdict,
                "signals": list(scan.signals),
                "content_hash": hashlib.sha256(content.encode("utf-8")).hexdigest(),
            }
        )
        excerpts.append(_security_excerpt(content))

    quarantined = [item for item in findings if item.get("verdict") == VERDICT_QUARANTINE]
    if not quarantined:
        return None
    excerpt = "\n".join(excerpts)[:4_000]
    audit_result = evaluate_agent_event(
        {
            "conversation_id": conversation_id,
            "agent_id": agent_id,
            "agent_role": "openai-compatible-agent",
            "source_app": "openai-compatible-proxy",
            "model_input": excerpt,
            "model_output": "",
            "context_sources": ["openai-compatible-client", "tool-result"],
            "tool_call": {
                "tool": "model.respond",
                "arguments": {"topic": excerpt[:1_000]},
                "risk_hint": "untrusted_tool_return",
            },
            "stage_context": {
                "request_id": request_id,
                "request_hash": request_hash,
                "provider_called": False,
                "tool_result_findings": findings,
                **(task_context or {}),
            },
        },
        guard_enabled=True,
        execute_managed=False,
        receipt_required=True,
    )
    return {
        "decision": audit_result.get("decision", "隔离"),
        "policy_id": audit_result.get("policy_id", "tool-return-trust"),
        # Tool output is attacker-controlled context; never reflect its text
        # through the response metadata that the downstream Agent can parse.
        "reason": _safe_model_boundary_reason("tool-result"),
        "risk_score": audit_result.get("risk_score", 92),
        "risk_factors": audit_result.get("risk_factors", []),
        "audit_id": audit_result.get("audit_id", ""),
        "request_stage": "pre-provider-context",
        "tool_result_scan": findings,
        # Never echo tool-result text back to a model-facing client. The client
        # already supplied the result, while the gateway's response must not
        # turn a quarantined payload into a second model-visible channel.
        "untrusted_message_excerpt": "工具结果原文已隐藏；请使用 tool_result_scan 中的哈希和信号复核。",
    }


def _sanitize_proxy_tool_results(messages: list[Any]) -> tuple[list[Any], list[dict[str, Any]]]:
    """Redact and label tool results before they enter the next Provider turn.

    Receipt validation and the quarantine guard operate on the caller's
    original messages.  This second pass deliberately creates a separate copy
    for the Provider so a clean-looking result containing a credential cannot
    bypass the audit-only redactor, while the original result hash remains
    available for receipt verification.
    """
    forwarded_messages = deepcopy(messages)
    visibility: list[dict[str, Any]] = []
    for index, message in enumerate(forwarded_messages):
        if not isinstance(message, dict):
            continue
        role = str(message.get("role") or "").strip().lower()
        if role not in {"tool", "function"}:
            continue
        result = sanitize_model_visible_tool_result(message.get("content"))
        # A quarantine result is normally stopped by _proxy_tool_result_guard;
        # keep a bounded marker here as defense-in-depth if the scanner changes
        # between the two passes.
        message["content"] = result["model_value"]
        visibility.append(
            {
                "message_index": index,
                "role": role,
                "original_hash": result["original_hash"],
                "model_visible_hash": result["model_visible_hash"],
                "redacted": bool(result["redacted"]),
                "trust": result["trust"],
                "verdict": result["verdict"],
                "signals": result["signals"],
            }
        )
    return forwarded_messages, visibility


def _record_gateway_response_audit(
    *,
    session_id: str,
    agent_id: str,
    request_id: str,
    request_hash: str,
    prompt: str,
    response: dict[str, Any],
    provider_result: dict[str, Any],
    provider_profile: str = "",
    task_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Persist a gateway decision even when the model returned plain text.

    Tool calls and filtered output already create dedicated audit records.  A
    normal provider response used to be returned with hashes but no audit ID,
    which made an otherwise valid gateway probe look incomplete and prevented
    operators from jumping from a benign request to its evidence record.
    ``receipt_required=False`` records the boundary decision without creating a
    caller-owned tool execution receipt requirement.
    """
    return evaluate_agent_event(
        {
            "conversation_id": session_id,
            "agent_id": agent_id,
            "agent_role": "openai-compatible-agent",
            "source_app": "openai-compatible-proxy",
            "model_input": _security_excerpt(prompt),
            "model_output": _response_content_excerpt(response),
            "context_sources": ["openai-compatible-client", "provider-response"],
            "tool_call": {
                "tool": "model.respond",
                "arguments": {"topic": "provider-response"},
            },
            "stage_context": {
                "session_id": session_id,
                "request_id": request_id,
                "provider": provider_result.get("provider", ""),
                "provider_profile": provider_profile or provider_result.get("provider_profile", ""),
                "provider_model": provider_result.get("model", ""),
                "provider_response_id": provider_result.get("provider_response_id", ""),
                "request_hash": request_hash,
                "provider_request_hash": provider_result.get("request_hash", ""),
                "provider_response_hash": provider_result.get("provider_response_hash", ""),
                "provider_called": True,
                **(task_context or {}),
            },
        },
        guard_enabled=True,
        execute_managed=False,
        receipt_required=False,
    )


def _record_gateway_provider_failure_audit(
    *,
    session_id: str,
    agent_id: str,
    request_id: str,
    prompt: str,
    request_hash: str,
    provider_profile: str,
    model: str,
    failures: list[dict[str, str]],
    failure_kind: str = "provider-unavailable",
    provider_called: bool = False,
    provider_attempted: bool | None = None,
    provider_output_exposed: bool = False,
    stream_released_char_count: int = 0,
    related_audit_id: str = "",
    task_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Persist a non-reflective audit when the Provider path cannot complete.

    A 502 is still a security-boundary event: the gateway accepted an Agent
    request, attempted an upstream call (or rejected the model binding), and
    must prove whether any model output reached the caller before the failure.
    The raw upstream body is intentionally excluded; only redacted categories
    and the bounded released-character count are kept in the signed audit row.
    """

    safe_failures = _safe_provider_failures(failures)
    attempted = (
        provider_called or bool(safe_failures)
        if provider_attempted is None
        else bool(provider_attempted)
    )
    released_char_count = _safe_stream_released_char_count(stream_released_char_count)
    output_exposed = bool(provider_output_exposed) or released_char_count > 0
    try:
        return evaluate_agent_event(
            {
                "conversation_id": session_id,
                "agent_id": agent_id,
                "agent_role": "openai-compatible-agent",
                "source_app": "openai-compatible-proxy",
                "model_input": _security_excerpt(prompt),
                "model_output": "",
                "context_sources": ["openai-compatible-client", "provider-failure"],
                "tool_call": {
                    "tool": "model.respond",
                    "arguments": {"topic": "provider-failure"},
                    "risk_hint": failure_kind,
                },
                "stage_context": {
                    "session_id": session_id,
                    "request_id": request_id,
                    "request_hash": request_hash,
                    "provider_profile": provider_profile,
                    "provider_model": _safe_model_label(model),
                    "provider_called": bool(provider_called),
                    "provider_attempted": attempted,
                    "provider_completed": False,
                    "provider_output_exposed": output_exposed,
                    "stream_released_char_count": released_char_count,
                    "provider_failure_kind": failure_kind,
                    "provider_failures": safe_failures,
                    "related_audit_id": _safe_protocol_identifier(related_audit_id),
                    **(task_context or {}),
                },
            },
            guard_enabled=True,
            execute_managed=False,
            receipt_required=False,
        )
    except Exception:
        # Availability evidence must never turn a safe 502 into an opaque 500.
        # The original exception still carries redacted failure categories.
        return {}


def _safe_stream_released_char_count(value: Any) -> int:
    """Return a bounded stream-release count without retaining Provider text."""

    if isinstance(value, bool):
        return 0
    try:
        count = int(value)
    except (TypeError, ValueError, OverflowError):
        return 0
    return max(0, min(count, PROXY_MAX_TOTAL_TEXT_CHARS * PROXY_MAX_PROVIDER_CHOICES))


def _stream_released_char_count(supplier: Callable[[], int] | None) -> int:
    """Read the projector's release count without letting audit collection fail a stream."""

    if supplier is None:
        return 0
    try:
        return _safe_stream_released_char_count(supplier())
    except Exception:
        return 0


def _raise_provider_response_contract_failure(
    *,
    session_id: str,
    agent_id: str,
    request_id: str,
    prompt: str,
    request_hash: str,
    provider_profile: str,
    model: str,
    provider_result: dict[str, Any],
    task_context: dict[str, Any] | None = None,
) -> None:
    """Raise a stable 502-class error for a malformed Provider envelope.

    A malformed response is not an Agent request error and must not be mapped
    to HTTP 400.  Keep the raw contract detail local, persist only a stable
    category, and mark the upstream as attempted so evidence cannot claim a
    pre-Provider block.
    """

    provider = str(provider_result.get("provider") or "unknown")[:120]
    provider_model = str(provider_result.get("model") or model)[:PROXY_MAX_MODEL_CHARS]
    failures = [
        {
            "provider": provider,
            "model": provider_model,
            "error": "Provider 响应格式校验失败",
        }
    ]
    audit = _record_gateway_provider_failure_audit(
        session_id=session_id,
        agent_id=agent_id,
        request_id=request_id,
        prompt=prompt,
        request_hash=request_hash,
        provider_profile=provider_profile,
        model=provider_model,
        failures=failures,
        failure_kind="provider-response-contract",
        provider_called=True,
        provider_attempted=True,
        task_context=task_context,
    )
    raise ModelProviderUnavailableError(
        "模型供应商响应未通过网关协议校验。",
        failures,
        gateway_audit=audit,
    )


def _record_proxy_model_allowlist_audit(
    *,
    session_id: str,
    agent_id: str,
    request_id: str,
    request_hash: str,
    model: str,
    reason: str,
    task_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Persist the model-selection denial before any Provider request."""

    try:
        return evaluate_agent_event(
            {
                "conversation_id": session_id,
                "agent_id": agent_id,
                "agent_role": "openai-compatible-agent",
                "source_app": "openai-compatible-proxy",
                "model_input": "model allowlist policy",
                "model_output": "",
                "context_sources": ["openai-compatible-client", "model-selection", "agent-model-allowlist"],
                "tool_call": {
                    "tool": "model.respond",
                    "arguments": {"topic": "model-selection"},
                    "risk_hint": "model-allowlist",
                },
                "stage_context": {
                    "session_id": session_id,
                    "request_id": request_id,
                    "request_hash": request_hash,
                    "provider_called": False,
                    "model_name_hash": hashlib.sha256(model.encode("utf-8")).hexdigest(),
                    "model_allowlist_rejected": True,
                    "policy_reason_hash": hashlib.sha256(reason.encode("utf-8")).hexdigest(),
                    **(task_context or {}),
                },
            },
            guard_enabled=True,
            execute_managed=False,
            receipt_required=False,
        )
    except Exception:
        return {}


def _record_proxy_task_profile_audit(
    *,
    session_id: str,
    agent_id: str,
    request_id: str,
    request_hash: str,
    task_context: dict[str, Any],
) -> dict[str, Any]:
    """Persist a task-binding rejection before a Provider receives the request."""

    try:
        return evaluate_agent_event(
            {
                "conversation_id": session_id,
                "agent_id": agent_id,
                "agent_role": "openai-compatible-agent",
                "source_app": "openai-compatible-proxy",
                "model_input": "task authorization",
                "model_output": "",
                "context_sources": ["openai-compatible-client", "task-profile"],
                "tool_call": {"tool": "model.respond", "arguments": {"topic": "task-authorization"}},
                "stage_context": {
                    "session_id": session_id,
                    "request_id": request_id,
                    "request_hash": request_hash,
                    "provider_called": False,
                    "task_profile_rejected": True,
                    **task_context,
                },
            },
            guard_enabled=True,
            execute_managed=False,
            receipt_required=False,
        )
    except Exception:
        return {}


def _tool_schema_index(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for _source, _item_index, _raw_definition, function in _proxy_declared_tool_items(payload):
        name = str(function.get("name") or "").strip()
        if name:
            index[name] = function
            mapped = PROXY_TOOL_NAME_MAP.get(name)
            if mapped:
                index[mapped] = function
    return index


def _validate_transparent_tool_call_schema(
    payload: dict[str, Any],
    parsed_call: dict[str, Any],
) -> str:
    external_tool = str(parsed_call.get("external_tool") or "")
    mapped_tool = str(parsed_call.get("tool") or "")
    schema_index = _tool_schema_index(payload)
    if not schema_index or not ({external_tool, mapped_tool} & set(schema_index)):
        return "Provider 返回了请求未声明的工具调用"
    # The Provider may return either the caller's framework name (for example
    # ``file_read``) or the gateway's canonical capability name
    # (``file.read``).  Prefer the exact external name, then fall back to the
    # mapped name; using ``external_tool or mapped_tool`` alone silently skipped
    # validation whenever a canonical tool was declared but an alias was
    # returned.
    schema = schema_index.get(external_tool) or schema_index.get(mapped_tool)
    if not schema:
        return ""
    parameters = schema.get("parameters")
    if parameters is None:
        return ""
    raw_arguments = parsed_call.get("arguments")
    arguments: dict[str, Any] = raw_arguments if isinstance(raw_arguments, dict) else {}
    issue = validate_json_schema_instance(arguments, parameters)
    return issue or ""


def _strip_provider_extensions(response: dict[str, Any]) -> list[str]:
    """Remove Provider-defined fields before an allowed response reaches an Agent.

    Output scanning remains detection-first: callers invoke this helper only
    after every known and unknown Provider text channel has been inspected.  A
    clean unknown field is still not a trusted OpenAI protocol field, so it is
    removed rather than passed through as an opaque instruction or trace.
    """
    removed: list[str] = []

    def strip_keys(container: dict[str, Any], allowed: frozenset[str], path: str) -> None:
        for key in list(container):
            if key in allowed:
                continue
            removed.append(f"{path}.{_safe_metadata_key(key)}")
            container.pop(key, None)

    strip_keys(response, PROXY_RESPONSE_FIELDS, "response")
    usage = response.get("usage")
    if isinstance(usage, dict):
        strip_keys(usage, PROXY_USAGE_FIELDS, "response.usage")
        for key in list(usage):
            if isinstance(key, str) and key.endswith("_details"):
                continue
            value = usage.get(key)
            if not _bounded_usage_value(value):
                removed.append(f"response.usage.{_safe_metadata_key(key)}")
                usage.pop(key, None)
        for detail_name in ("prompt_tokens_details", "completion_tokens_details"):
            details = usage.get(detail_name)
            if details is None:
                continue
            if not isinstance(details, dict):
                removed.append(f"response.usage.{_safe_metadata_key(detail_name)}")
                usage.pop(detail_name, None)
                continue
            strip_keys(details, PROXY_USAGE_DETAIL_FIELDS, f"response.usage.{detail_name}")
            for key in list(details):
                value = details.get(key)
                if not _bounded_usage_value(value):
                    removed.append(f"response.usage.{_safe_metadata_key(detail_name)}.{_safe_metadata_key(key)}")
                    details.pop(key, None)
    elif usage is not None:
        removed.append("response.usage")
        response.pop("usage", None)
    choices = response.get("choices")
    if not isinstance(choices, list):
        return removed
    for choice_index, raw_choice in enumerate(choices[:PROXY_MAX_PROVIDER_CHOICES]):
        if not isinstance(raw_choice, dict):
            continue
        choice_path = f"response.choices[{choice_index}]"
        strip_keys(raw_choice, PROXY_CHOICE_FIELDS, choice_path)
        message = raw_choice.get("message")
        if isinstance(message, dict):
            message_path = f"{choice_path}.message"
            strip_keys(message, PROXY_MESSAGE_FIELDS, message_path)
            raw_tool_calls = message.get("tool_calls")
            if isinstance(raw_tool_calls, list):
                for call_index, raw_call in enumerate(raw_tool_calls[:PROXY_MAX_PROVIDER_TOOL_CALLS]):
                    if not isinstance(raw_call, dict):
                        continue
                    call_path = f"{message_path}.tool_calls[{call_index}]"
                    strip_keys(raw_call, PROXY_TOOL_CALL_FIELDS, call_path)
                    function = raw_call.get("function")
                    if isinstance(function, dict):
                        strip_keys(function, PROXY_FUNCTION_FIELDS, f"{call_path}.function")
            legacy_call = message.get("function_call")
            if isinstance(legacy_call, dict):
                strip_keys(legacy_call, PROXY_FUNCTION_FIELDS, f"{message_path}.function_call")
    return removed


def _strip_provider_reasoning(response: dict[str, Any]) -> list[str]:
    """Hide provider chain-of-thought channels from the downstream Agent.

    Reasoning is still inspected and its hash remains covered by the provider
    evidence, but it is not part of the minimum OpenAI response contract. A
    provider can place sensitive context, credentials, or hidden instructions
    in a clean-looking reasoning field that the normal content filter does not
    classify as a block. Keep exposure opt-in for compatibility integrations.
    """
    if _env_bool("AGENT_SUPERVISOR_PROXY_EXPOSE_REASONING", False):
        return []
    removed: list[str] = []
    reasoning_fields = {"reasoning_content", "reasoning", "thinking", "analysis"}
    for top_level in reasoning_fields:
        if top_level in response:
            response.pop(top_level, None)
            removed.append(f"response.{top_level}")
    choices = response.get("choices")
    if not isinstance(choices, list):
        return removed
    for choice_index, raw_choice in enumerate(choices[:PROXY_MAX_PROVIDER_CHOICES]):
        if not isinstance(raw_choice, dict):
            continue
        for field in reasoning_fields:
            if field in raw_choice:
                raw_choice.pop(field, None)
                removed.append(f"response.choices[{choice_index}].{field}")
        message = raw_choice.get("message")
        if not isinstance(message, dict):
            continue
        for field in reasoning_fields:
            if field in message:
                message.pop(field, None)
                removed.append(f"response.choices[{choice_index}].message.{field}")
    return removed


def run_openai_proxy_completion(
    payload: dict[str, Any],
    *,
    security_context: dict[str, Any] | None = None,
    provider_stream_callback: Callable[[dict[str, Any]], None] | None = None,
    stream_cancel_event: Any = None,
    stream_released_char_count_supplier: Callable[[], int] | None = None,
    request_id_override: str = "",
) -> dict[str, Any]:
    """Run the production-transparent proxy or bounded managed execution.

    The default path forwards the caller's original OpenAI request to a real
    provider, then supervises returned tool calls before exposing them.
    """
    _validate_proxy_request(payload)
    options = payload.get("agent_supervisor") if isinstance(payload, dict) else None
    options = options if isinstance(options, dict) else {}
    mode = _validated_proxy_mode(options)
    _validate_proxy_mode_access(mode, options=options, security_context=security_context)
    if provider_stream_callback is not None and mode != "transparent":
        raise ValueError("真实流式安全链当前只支持 transparent 模式")
    resource_lease: ResourceLease | None = None
    resource_plan = _proxy_resource_plan(payload, security_context=security_context, mode=mode)
    if resource_plan is not None:
        try:
            resource_lease = acquire_resource_lease(resource_plan)
        except ProxyResourceLimitError as error:
            audit_id = _record_proxy_resource_rejection(
                payload,
                security_context=security_context,
                mode=resource_plan.mode,
                plan=resource_plan,
                resource=error.resource,
                limit=error.limit,
                snapshot=error.snapshot,
            )
            error.audit_id = audit_id
            raise

    try:
        if mode == "managed":
            result = _run_managed_proxy_completion(payload, security_context=security_context)
        else:
            result = _run_transparent_proxy_completion(
                payload,
                security_context=security_context,
                provider_stream_callback=provider_stream_callback,
                stream_cancel_event=stream_cancel_event,
                stream_released_char_count_supplier=stream_released_char_count_supplier,
                request_id_override=request_id_override,
            )
    except Exception as error:
        if resource_lease is not None:
            # An exception after reservation may follow a Provider attempt.  A
            # conservative charge prevents an unknown upstream bill from
            # becoming free quota; when the gateway has an immutable audit
            # fact that the request was rejected before the Provider, do not
            # charge Provider quota for a call that never crossed that
            # boundary. Request-shape failures are rejected before this
            # function acquires a lease.
            known_provider_called = _exception_provider_called(error)
            resource_lease.settle(
                actual_tokens=None,
                provider_called=True if known_provider_called is None else known_provider_called,
            )
        raise

    if resource_lease is not None:
        metadata = result.get("agent_supervisor") if isinstance(result, dict) else None
        metadata = metadata if isinstance(metadata, dict) else {}
        actual_tokens = _proxy_result_usage_tokens(result)
        provider_called = metadata.get("provider_called") is True
        settlement = resource_lease.settle(
            actual_tokens=actual_tokens,
            provider_called=provider_called,
        )
        _attach_proxy_resource_metadata(
            result,
            resource_lease,
            settlement=settlement,
            actual_tokens=actual_tokens,
        )
    return result


def _exception_provider_called(error: Exception) -> bool | None:
    """Read a trusted Provider-attempt fact from a gateway exception.

    Model-selection policy errors carry the immutable pre-Provider audit row;
    charging their reserved Provider tokens would make a caller exhaust a
    cost quota without any outbound model request. Provider transport/contract
    failures set ``provider_attempted`` and remain conservatively chargeable.
    Unknown exceptions return ``None`` so the existing fail-closed billing
    behavior is preserved.
    """

    audit = getattr(error, "gateway_audit", None)
    if not isinstance(audit, dict):
        return None
    candidates = [audit]
    nested_audit = audit.get("audit_log")
    if isinstance(nested_audit, dict):
        candidates.append(nested_audit)
    for candidate in candidates:
        context = candidate.get("stage_context")
        context = context if isinstance(context, dict) else {}
        if context.get("provider_attempted") is True:
            return True
        if isinstance(context.get("provider_called"), bool):
            return bool(context["provider_called"])
        if isinstance(candidate.get("provider_attempted"), bool):
            return bool(candidate["provider_attempted"])
        if isinstance(candidate.get("provider_called"), bool):
            return bool(candidate["provider_called"])
    return None


def _validated_proxy_mode(options: dict[str, Any]) -> str:
    """Resolve one explicit execution boundary and reject misspelled downgrades."""

    raw_mode: Any
    if "mode" in options:
        raw_mode = options.get("mode")
    else:
        raw_mode = os.getenv("AGENT_SUPERVISOR_PROXY_MODE") or "transparent"
    if not isinstance(raw_mode, str):
        raise ValueError("agent_supervisor.mode 必须是 transparent 或 managed")
    mode = raw_mode.strip().lower()
    if mode not in {"transparent", "managed"}:
        raise ValueError("agent_supervisor.mode 必须是 transparent 或 managed")
    return mode


def _validate_proxy_mode_access(
    mode: str,
    *,
    options: dict[str, Any],
    security_context: dict[str, Any] | None,
) -> None:
    """Reject mode/identity authorization errors before reserving Provider resources."""

    context = security_context if isinstance(security_context, dict) else {}
    role = str(context.get("role") or "").strip().lower()
    authenticated_agent_id = str(context.get("agent_id") or "").strip()
    requested_agent_id = str(options.get("agent_id") or "").strip()
    if authenticated_agent_id and requested_agent_id and authenticated_agent_id != requested_agent_id:
        raise ValueError("请求中的 agent_id 与代理凭证绑定身份不一致")
    if mode == "managed" and security_context is not None and not can_execute_managed_tools(
        role, authenticated_agent_id
    ):
        raise ValueError("当前角色无权使用服务端托管工具执行模式")


def _proxy_resource_plan(
    payload: dict[str, Any],
    *,
    security_context: dict[str, Any] | None,
    mode: str,
) -> ResourcePlan | None:
    """Build a reservation only for the authenticated HTTP gateway path."""

    if security_context is None or not resource_governance_enabled():
        return None
    context = security_context if isinstance(security_context, dict) else {}
    authenticated_agent_id = str(context.get("agent_id") or "").strip()
    raw_options = payload.get("agent_supervisor")
    body_options = raw_options if isinstance(raw_options, dict) else {}
    requested_agent_id = str(body_options.get("agent_id") or "").strip()
    role = str(context.get("role") or "").strip().lower()
    # A bound executor must never be able to select a new bucket by changing a
    # body field.  Unbound administrative/analyst paths may intentionally bind
    # an audit identity for review work.
    agent_id = authenticated_agent_id or (requested_agent_id if role in {"admin", "analyst"} else "")
    agent_id = agent_id or "openai-compatible-proxy"
    normalized_mode = mode
    options = payload.get("agent_supervisor")
    options = options if isinstance(options, dict) else {}
    rounds = _managed_tool_round_limit(options) if normalized_mode == "managed" else 0
    return estimate_request_plan(
        payload,
        agent_id=agent_id,
        mode=normalized_mode,
        managed_rounds=rounds,
    )


def _proxy_result_usage_tokens(result: dict[str, Any]) -> int | None:
    """Read Provider usage, including the accumulated managed-round counter."""

    metadata = result.get("agent_supervisor") if isinstance(result, dict) else None
    if isinstance(metadata, dict) and "resource_actual_tokens" in metadata:
        value = metadata.get("resource_actual_tokens")
        if isinstance(value, int) and value >= 0:
            return value
    usage = result.get("usage") if isinstance(result, dict) else None
    if not isinstance(usage, dict):
        return None
    total = usage.get("total_tokens")
    if isinstance(total, (int, float)) and not isinstance(total, bool) and total >= 0:
        return int(total)
    prompt = usage.get("prompt_tokens")
    completion = usage.get("completion_tokens")
    if (
        isinstance(prompt, bool)
        or not isinstance(prompt, (int, float))
        or prompt < 0
        or isinstance(completion, bool)
        or not isinstance(completion, (int, float))
        or completion < 0
    ):
        return None
    return int(prompt + completion)


def _record_proxy_resource_rejection(
    payload: dict[str, Any],
    *,
    security_context: dict[str, Any] | None,
    mode: str,
    plan: ResourcePlan,
    resource: str,
    limit: int | float,
    snapshot: dict[str, Any],
) -> str:
    """Persist a signed, provider-not-called audit for a rejected reservation."""

    context = security_context if isinstance(security_context, dict) else {}
    agent_id = str(plan.agent_id)
    request_id = f"chatcmpl-zhian-resource-{uuid4().hex[:16]}"
    request_hash = _proxy_payload_hash(payload)
    messages = payload.get("messages")
    prompt = _security_excerpt(_extract_prompt(messages if isinstance(messages, list) else []))
    try:
        audit = evaluate_agent_event(
            {
                "conversation_id": str(context.get("session_id") or request_id),
                "agent_id": agent_id,
                "agent_role": "openai-compatible-agent",
                "source_app": "openai-compatible-proxy",
                "model_input": prompt,
                "model_output": "",
                "context_sources": ["openai-compatible-client", "resource-governance"],
                "tool_call": {
                    "tool": "model.respond",
                    "arguments": {
                        "resource": resource,
                        "limit": limit,
                        "estimated_tokens": plan.estimated_tokens,
                        "provider_calls": plan.provider_calls,
                    },
                    "risk_hint": "resource_governance",
                },
                "authenticated_role": context.get("role", ""),
                "authenticated_agent_id": context.get("agent_id", ""),
                "agent_identity_verified": bool(context.get("agent_id")),
                "server_owned_execution": True,
                "stage_context": {
                    "request_id": request_id,
                    "request_hash": request_hash,
                    "mode": mode,
                    "resource": resource,
                    "resource_limit": limit,
                    "resource_plan": {
                        "provider_calls": plan.provider_calls,
                        "estimated_tokens": plan.estimated_tokens,
                        "estimated_cost_usd": plan.estimated_cost_usd,
                    },
                    "resource_snapshot": snapshot,
                    "provider_called": False,
                },
            },
            guard_enabled=True,
            execute_managed=False,
            receipt_required=True,
        )
    except (ValueError, TypeError):
        return ""
    return str(audit.get("audit_id") or "")


def _attach_proxy_resource_metadata(
    result: dict[str, Any],
    lease: ResourceLease,
    *,
    settlement: dict[str, Any],
    actual_tokens: int | None,
) -> None:
    metadata = result.get("agent_supervisor")
    if not isinstance(metadata, dict):
        metadata = {}
        result["agent_supervisor"] = metadata
    metadata["resource_governance"] = {
        "enabled": True,
        "scope": lease.scope,
        "agent_id": lease.agent_id,
        "provider_calls_reserved": lease.plan.provider_calls,
        "estimated_tokens": lease.plan.estimated_tokens,
        "actual_tokens": actual_tokens,
        "concurrency_limit": lease.concurrency_limit,
        "token_budget_per_minute": lease.token_budget,
        "cost_budget_per_minute_usd": lease.cost_budget_usd,
        "settlement": settlement,
    }


def _run_managed_proxy_completion(
    payload: dict[str, Any],
    *,
    security_context: dict[str, Any] | None,
) -> dict[str, Any]:
    """Run a bounded server-owned Agent tool loop through the OpenAI gateway.

    Transparent mode deliberately returns inspected tool calls to a caller-owned
    executor.  Managed mode is the stronger product path: the Provider response
    is still inspected by the same transparent gateway, but every allowed call is
    reloaded from its immutable audit record, executed by the supervisor-owned
    managed runtime, and only then returned to the Provider with a verified receipt.  A
    controlled call is never sent to the executor and is never exposed to the
    caller as an executable tool call.
    """

    raw_options = payload.get("agent_supervisor")
    options = dict(raw_options) if isinstance(raw_options, dict) else {}
    context = security_context if isinstance(security_context, dict) else {}
    context_role = str(context.get("role") or "").strip().lower()
    # Analyst credentials may inspect and generate model traffic, but they do
    # not receive server-owned side effects.  Managed mode crosses the second
    # trust boundary by executing a Provider-generated tool call, so keep it
    # limited to a bound executor or an administrator.
    authenticated_agent_id = str(context.get("agent_id") or "").strip()
    if security_context is not None and not can_execute_managed_tools(context_role, authenticated_agent_id):
        raise ValueError("当前角色无权使用服务端托管工具执行模式")
    requested_agent_id = str(options.get("agent_id") or "").strip()
    if authenticated_agent_id and requested_agent_id and authenticated_agent_id != requested_agent_id:
        raise ValueError("请求中的 agent_id 与代理凭证绑定身份不一致")
    agent_id = authenticated_agent_id or requested_agent_id or "openai-compatible-proxy"
    request_id = f"chatcmpl-zhian-managed-{uuid4().hex[:16]}"
    initial_request_hash = _proxy_payload_hash(payload)
    session_id, session_id_provided = _proxy_session_id(options, security_context, request_id)
    max_rounds = _managed_tool_round_limit(options)

    # The first request and each follow-up use the same authenticated identity
    # and session.  ``tool_receipts`` is replaced internally after each round;
    # accepting a caller-supplied map here would let a client pre-bind a result
    # from another conversation.
    transparent_options = {
        key: value
        for key, value in options.items()
        if key not in {"mode", "execution_mode", "tool_receipts", "max_tool_rounds"}
    }
    transparent_options.update(
        {
            "mode": "transparent",
            "agent_id": agent_id,
            "session_id": session_id,
        }
    )
    current_messages = deepcopy(payload.get("messages"))
    if not isinstance(current_messages, list) or not current_messages:
        raise ValueError("managed 模式需要非空 messages 数组")
    # A managed turn is an Agent state transition, not a batch completion.  If
    # ``n`` requests multiple Provider choices, their tool calls do not share a
    # single assistant/tool history and cannot be safely replayed into the next
    # round.  Returning one choice while executing another would be an
    # unbound-side-effect bug, so fail closed before the first Provider call.
    requested_completions = payload.get("n", 1)
    if requested_completions != 1:
        raise ValueError("managed 模式只支持 n=1；多候选响应无法绑定唯一工具执行历史")

    receipts: dict[str, dict[str, str]] = {}
    # Only the assistant/tool messages appended by the immediately preceding
    # round need a new one-time receipt claim.  Older tool results remain in
    # conversation history but must not be claimed a second time.
    receipt_messages: list[dict[str, Any]] = []
    executions: list[dict[str, Any]] = []
    all_audit_ids: list[str] = []
    round_evidence: list[dict[str, Any]] = []
    last_result: dict[str, Any] | None = None
    resource_actual_tokens = 0
    resource_usage_complete = True

    for round_index in range(max_rounds + 1):
        round_options = dict(transparent_options)
        if receipts:
            round_options["tool_receipts"] = dict(receipts)
        round_payload = dict(payload)
        round_payload["messages"] = deepcopy(current_messages)
        round_payload["agent_supervisor"] = round_options

        # Managed mode appends Provider assistant/tool messages after every
        # round.  Re-run the same request contract on the accumulated history;
        # validating only the first turn would let a bounded request grow past
        # message, text, structured-call, or generation limits before the next
        # Provider call.
        _validate_proxy_request(round_payload)

        result = _run_transparent_proxy_completion(
            round_payload,
            security_context=security_context,
            receipt_messages=receipt_messages,
            force_tool_receipts=bool(receipts),
            request_id_override=request_id,
        )
        last_result = result
        metadata = result.get("agent_supervisor")
        metadata = metadata if isinstance(metadata, dict) else {}
        provider_round_decisions = metadata.get("tool_decisions")
        round_usage_tokens = _proxy_result_usage_tokens(result)
        if round_usage_tokens is None:
            resource_usage_complete = False
        else:
            resource_actual_tokens += round_usage_tokens
        metadata["resource_actual_tokens"] = resource_actual_tokens if resource_usage_complete else None
        # The per-round request hash changes as managed history grows. Keep a
        # stable digest for the original caller request as well.
        metadata["initial_request_hash"] = initial_request_hash
        round_evidence.append(
            {
                "round": round_index + 1,
                "provider_called": metadata.get("provider_called") is True,
                "provider": metadata.get("provider", ""),
                # ``managed`` consumes the Provider tool call inside the
                # supervisor, so the final response intentionally exposes zero
                # tool calls to the caller. Preserve the fact that the Provider
                # produced a call in the round evidence instead of conflating
                # "not leaked" with "not generated".
                "provider_tool_call_count": (
                    len(provider_round_decisions)
                    if isinstance(provider_round_decisions, list)
                    else 0
                ),
                "provider_request_hash": metadata.get("provider_request_hash", ""),
                "provider_response_hash": metadata.get("provider_response_hash", ""),
                "provider_response_id": metadata.get("provider_response_id", ""),
                "usage_tokens": round_usage_tokens,
                "decision": metadata.get("decision", ""),
                "audit_ids": [
                    str(item.get("audit_id") or "")
                    for item in (metadata.get("tool_decisions") or [])
                    if isinstance(item, dict) and item.get("audit_id")
                ],
            }
        )
        _merge_managed_metadata(
            metadata,
            round_index=round_index,
            session_id=session_id,
            session_id_provided=session_id_provided,
            executions=executions,
            audit_ids=all_audit_ids,
            round_evidence=round_evidence,
            max_rounds=max_rounds,
            status="provider-response",
        )
        result["agent_supervisor"] = metadata

        raw_decisions = metadata.get("tool_decisions")
        tool_decisions = raw_decisions if isinstance(raw_decisions, list) else []
        invalid_calls = metadata.get("invalid_tool_calls")
        if not tool_decisions:
            _merge_managed_metadata(
                metadata,
                round_index=round_index,
                session_id=session_id,
                session_id_provided=session_id_provided,
                executions=executions,
                audit_ids=all_audit_ids,
                round_evidence=round_evidence,
                max_rounds=max_rounds,
                status="completed" if metadata.get("provider_called") else "blocked-before-provider",
            )
            return result

        if invalid_calls or any(str(item.get("decision") or "") != "允许" for item in tool_decisions if isinstance(item, dict)):
            _merge_managed_metadata(
                metadata,
                round_index=round_index,
                session_id=session_id,
                session_id_provided=session_id_provided,
                executions=executions,
                audit_ids=all_audit_ids,
                round_evidence=round_evidence,
                max_rounds=max_rounds,
                status="blocked-before-execution",
            )
            return result

        # A managed round crosses a real side-effect boundary.  The standard
        # executor currently exposes one-call semantics and does not provide a
        # transaction/compensation contract for a batch of heterogeneous tools
        # (file writes, mail records, target-lab mutations, or code execution).
        # Executing call 1 and discovering a runtime failure on call 2 would
        # therefore leave a partial side effect while the response is reported
        # as incomplete.  Keep the invariant explicit: transparent mode may
        # return multiple allowed calls to a caller-owned executor, while
        # managed mode requires the Provider to issue one call per round.  A
        # later round can still perform a multi-step Agent workflow, with a
        # receipt-bound tool result at every transition.
        if len(tool_decisions) > 1:
            block_reason = (
                "服务端托管模式每轮只执行一个工具调用；请将并行工具调用拆分为多轮，"
                "以保持副作用与服务端回执的一一对应。"
            )
            _replace_blocked_choices(
                result,
                {
                    "decision": "拒绝",
                    "policy_id": "managed-tool-batch-contract",
                    "reason": block_reason,
                },
            )
            metadata.update(
                {
                    "decision": "拒绝",
                    "policy_id": "managed-tool-batch-contract",
                    "reason": "托管模式每轮只允许一个工具调用；原始调用未进入执行器。",
                    "risk_score": max(int(metadata.get("risk_score") or 0), 75),
                    "managed_status": "blocked-before-execution",
                    "execution_boundary": "managed-tool-batch-contract",
                    "execution_outcome": "blocked-before-execution",
                    "tool_execution": "not-returned-to-caller",
                    "decision_enforced_before_tool_execution": True,
                    "gateway_contract_evidence": "managed-tool-batch-contract",
                    "managed_tool_batch_size": len(tool_decisions),
                }
            )
            _merge_managed_metadata(
                metadata,
                round_index=round_index,
                session_id=session_id,
                session_id_provided=session_id_provided,
                executions=executions,
                audit_ids=all_audit_ids,
                round_evidence=round_evidence,
                max_rounds=max_rounds,
                status="blocked-before-execution",
            )
            # _merge_managed_metadata preserves the contract marker supplied
            # above for a blocked round; restore the explicit batch metadata in
            # case a future metadata projection adds a default value.
            metadata.update(
                {
                    "decision": "拒绝",
                    "policy_id": "managed-tool-batch-contract",
                    "reason": "托管模式每轮只允许一个工具调用；原始调用未进入执行器。",
                    "execution_boundary": "managed-tool-batch-contract",
                    "execution_outcome": "blocked-before-execution",
                    "tool_execution": "not-returned-to-caller",
                    "decision_enforced_before_tool_execution": True,
                    "gateway_contract_evidence": "managed-tool-batch-contract",
                    "managed_tool_batch_size": len(tool_decisions),
                }
            )
            result["agent_supervisor"] = metadata
            return result

        if round_index >= max_rounds:
            _replace_blocked_choices(
                result,
                {
                    "decision": "询问",
                    "policy_id": "managed-round-limit",
                    "reason": f"服务端托管 Agent 已达到 {max_rounds} 轮工具执行上限，未继续暴露新的 tool call。",
                },
            )
            metadata.update(
                {
                    "decision": "询问",
                    "policy_id": "managed-round-limit",
                    "reason": f"服务端托管 Agent 已达到 {max_rounds} 轮工具执行上限。",
                    "managed_status": "round-limit",
                    "execution_boundary": "managed-round-limit",
                    "tool_execution": "not-returned-to-caller",
                    "decision_enforced_before_tool_execution": True,
                    "gateway_contract_evidence": "managed-round-limit",
                }
            )
            # _replace_blocked_choices intentionally strips vendor extensions;
            # restore the gateway's own evidence envelope after shaping the
            # visible choice so clients can still observe the enforced limit.
            result["agent_supervisor"] = metadata
            return result

        choices = result.get("choices")
        if not isinstance(choices, list) or not choices:
            raise ValueError("managed 模式的 Provider 响应缺少 choices")
        call_messages: list[dict[str, Any]] = []
        call_to_message: dict[str, dict[str, Any]] = {}
        for choice_index, choice in enumerate(choices):
            if not isinstance(choice, dict) or not isinstance(choice.get("message"), dict):
                continue
            message = choice["message"]
            raw_calls = message.get("tool_calls")
            assistant_message = _managed_assistant_message(message)
            if not isinstance(raw_calls, list) and isinstance(message.get("function_call"), dict):
                # Transparent mode keeps the legacy field for old SDK clients,
                # but the managed follow-up must enter the next request as one
                # canonical tool-call history.  Otherwise a legacy result has
                # no tool_call_id to bind, and retaining both shapes would
                # trigger the dual-representation rejection above.
                legacy_id = f"legacy-{metadata.get('request_id', '')}-{choice_index}"
                legacy_function = deepcopy(message["function_call"])
                raw_calls = [
                    {
                        "id": legacy_id,
                        "type": "function",
                        "function": legacy_function,
                    }
                ]
                assistant_message.pop("function_call", None)
                assistant_message["tool_calls"] = deepcopy(raw_calls)
            if not isinstance(raw_calls, list):
                continue
            call_messages.append(assistant_message)
            for raw_call in raw_calls:
                if isinstance(raw_call, dict):
                    call_id = str(raw_call.get("id") or "").strip()
                    if call_id:
                        call_to_message[call_id] = message

        round_results: list[dict[str, Any]] = []
        round_executions: dict[str, dict[str, Any]] = {}
        round_receipts: dict[str, dict[str, str]] = {}
        incomplete_execution: dict[str, Any] | None = None
        for item in tool_decisions:
            if not isinstance(item, dict):
                raise ValueError("managed 模式收到无效工具决策")
            audit_id = str(item.get("audit_id") or "").strip()
            call_id = str(item.get("call_id") or "").strip()
            if not audit_id or not call_id or call_id not in call_to_message:
                raise ValueError("managed 模式无法把 Provider tool call 绑定到服务端审计记录")
            execution = execute_gateway_tool_call(
                audit_id,
                agent_id=agent_id,
                session_id=session_id,
                provider_call_id=call_id,
            )
            round_executions[call_id] = execution
            round_results.append(
                {
                    "audit_id": audit_id,
                    "provider_call_id": call_id,
                    "status": (execution.get("receipt") or {}).get("status", ""),
                    "execution_evidence": execution.get("execution_evidence", ""),
                    "execution_observed_by_server": execution.get("execution_observed_by_server") is True,
                    "tool_result_hash": execution.get("tool_result_hash", ""),
                    "receipt_hash": (execution.get("receipt") or {}).get("receipt_hash", ""),
                    "audit_hash": (execution.get("receipt") or {}).get("audit_hash", ""),
                }
            )
            round_receipts[call_id] = {"audit_id": audit_id}
            if audit_id not in all_audit_ids:
                all_audit_ids.append(audit_id)
            receipt_payload = execution.get("receipt")
            execution_status = str(receipt_payload.get("status") or "") if isinstance(receipt_payload, dict) else ""
            if execution_status not in {"completed", "failed"}:
                incomplete_execution = {
                    "audit_id": audit_id,
                    "provider_call_id": call_id,
                    "status": execution_status or "unknown",
                }
                break

        if incomplete_execution is not None:
            executions.extend(round_results)
            _replace_blocked_choices(
                result,
                {
                    "decision": "隔离",
                    "policy_id": "managed-execution-incomplete",
                    "reason": "服务端执行器未产生可回灌的工具结果，已停止后续 Provider 调用。",
                },
            )
            metadata.update(
                {
                    "decision": "隔离",
                    "policy_id": "managed-execution-incomplete",
                    "reason": "服务端执行器未产生可回灌的工具结果，已停止后续 Provider 调用。",
                    "risk_score": max(int(metadata.get("risk_score") or 0), 95),
                    "managed_status": "execution-incomplete",
                    "execution_boundary": "server-owned-tool-execution-incomplete",
                    "tool_execution": "not-returned-to-provider",
                    "decision_enforced_before_tool_execution": False,
                    "gateway_contract_evidence": "managed-execution-incomplete",
                    "managed_incomplete_execution": incomplete_execution,
                }
            )
            _merge_managed_metadata(
                metadata,
                round_index=round_index,
                session_id=session_id,
                session_id_provided=session_id_provided,
                executions=executions,
                audit_ids=all_audit_ids,
                round_evidence=round_evidence,
                max_rounds=max_rounds,
                status="execution-incomplete",
            )
            metadata.update(
                {
                    "decision": "隔离",
                    "policy_id": "managed-execution-incomplete",
                    "reason": "服务端执行器未产生可回灌的工具结果，已停止后续 Provider 调用。",
                    "managed_status": "execution-incomplete",
                    "execution_boundary": "server-owned-tool-execution-incomplete",
                    "tool_execution": "not-returned-to-provider",
                    "decision_enforced_before_tool_execution": False,
                    "gateway_contract_evidence": "managed-execution-incomplete",
                    "managed_incomplete_execution": incomplete_execution,
                }
            )
            result["agent_supervisor"] = metadata
            return result

        executions.extend(round_results)
        if len(round_receipts) != len(tool_decisions):
            raise ValueError("managed 模式工具调用与执行回执数量不一致")

        # Append exactly the Provider assistant tool-call message(s), followed by
        # the supervisor-produced results.  The next gateway pass validates the
        # hashes and scans the results again before re-entering the Provider.
        current_messages.extend(call_messages)
        receipt_messages = [*call_messages]
        for call_id, _receipt_ref in round_receipts.items():
            # The result text is loaded from the idempotent execution response so
            # the exact value hashed in the receipt is the value sent to the model.
            execution_payload = round_executions[call_id]
            tool_message = {
                "role": "tool",
                "tool_call_id": call_id,
                "content": str(execution_payload.get("tool_result") or ""),
            }
            current_messages.append(tool_message)
            receipt_messages.append(tool_message)
        receipts = round_receipts

    if last_result is None:
        raise ValueError("managed 模式未生成 Provider 响应")
    return last_result


def _managed_tool_round_limit(options: dict[str, Any]) -> int:
    raw = options.get("max_tool_rounds", os.getenv("AGENT_SUPERVISOR_PROXY_MAX_TOOL_ROUNDS", "3"))
    try:
        value = int(raw)
    except (TypeError, ValueError):
        value = 3
    return max(1, min(value, 8))


def _managed_assistant_message(message: dict[str, Any]) -> dict[str, Any]:
    """Keep only OpenAI assistant fields needed to establish tool provenance."""

    allowed = {"role", "content", "tool_calls", "function_call", "name"}
    return {key: deepcopy(value) for key, value in message.items() if key in allowed}


def _merge_managed_metadata(
    metadata: dict[str, Any],
    *,
    round_index: int,
    session_id: str,
    session_id_provided: bool,
    executions: list[dict[str, Any]],
    audit_ids: list[str],
    round_evidence: list[dict[str, Any]],
    max_rounds: int,
    status: str,
) -> None:
    metadata.update(
        {
            "mode": "managed",
            "execution_mode": "managed",
            "managed_status": status,
            "managed_round": round_index,
            "managed_rounds": round_index + 1,
            "max_tool_rounds": max_rounds,
            "session_id": session_id,
            "session_id_provided": session_id_provided,
            "managed_tool_executions": deepcopy(executions),
            "managed_audit_ids": list(audit_ids),
            "managed_round_evidence": deepcopy(round_evidence),
            "provider_tool_call_count": sum(
                int(item.get("provider_tool_call_count") or 0)
                for item in round_evidence
                if isinstance(item, dict)
            ),
            "execution_boundary": (
                "gateway-blocked-before-tool-execution"
                if status in {"blocked-before-provider", "blocked-before-execution"} and not executions
                else "managed-round-limit"
                if status == "round-limit"
                else "server-owned-tool-execution"
            ),
            "execution_outcome": (
                "blocked-before-execution"
                if status in {"blocked-before-provider", "blocked-before-execution"} and not executions
                else "audit-uncertain"
                if status == "execution-incomplete"
                else "executed-result-contained"
                if executions
                else "no-tool-execution"
            ),
            "tool_execution": "server-executed-and-receipt-bound"
            if executions
            else metadata.get("tool_execution", "not-returned-to-caller"),
            "gateway_contract_evidence": (
                "managed-execution"
                if status == "completed"
                else "managed-round-limit"
                if status == "round-limit"
                else metadata.get("gateway_contract_evidence", "managed-boundary")
            ),
        }
    )
    metadata.update(_gateway_evidence_metadata())
    _apply_execution_contract_metadata(metadata)


def _run_transparent_proxy_completion(
    payload: dict[str, Any],
    *,
    security_context: dict[str, Any] | None,
    receipt_messages: list[dict[str, Any]] | None = None,
    force_tool_receipts: bool = False,
    provider_stream_callback: Callable[[dict[str, Any]], None] | None = None,
    stream_cancel_event: Any = None,
    stream_released_char_count_supplier: Callable[[], int] | None = None,
    request_id_override: str = "",
) -> dict[str, Any]:
    request_id = request_id_override or f"chatcmpl-zhian-{uuid4().hex[:16]}"
    options = payload.get("agent_supervisor") if isinstance(payload, dict) else None
    options = options if isinstance(options, dict) else {}
    context = security_context if isinstance(security_context, dict) else {}
    authenticated_agent_id = str(context.get("agent_id") or "").strip()
    requested_agent_id = str(options.get("agent_id") or "").strip()
    context_role = str(context.get("role") or "").strip().lower()
    if authenticated_agent_id and requested_agent_id and authenticated_agent_id != requested_agent_id:
        raise ValueError("请求中的 agent_id 与代理凭证绑定身份不一致")
    if security_context is not None and requested_agent_id and not authenticated_agent_id and context_role != "admin":
        raise ValueError("透明代理的 agent_id 必须来自服务端绑定凭证；管理员可显式指定审计身份")
    agent_id = authenticated_agent_id or requested_agent_id or "openai-compatible-proxy"
    session_id, session_id_provided = _proxy_session_id(options, security_context, request_id)
    request_hash = _proxy_payload_hash(payload)
    receipt_verification = {"verified": 0, "server_observed": 0, "caller_declared": 0}
    messages = payload.get("messages")
    messages_for_receipts = receipt_messages if receipt_messages is not None else messages
    server_observed_receipts_required = force_tool_receipts or (
        security_context is not None and proxy_server_observed_receipts_required()
    )
    if (force_tool_receipts or _proxy_tool_receipts_required(security_context)) and isinstance(messages_for_receipts, list):
        receipt_verification = _validate_proxy_tool_receipts(
            messages_for_receipts,
            options,
            agent_id=agent_id,
            session_id=session_id,
            request_hash=request_hash,
            require_server_observed=server_observed_receipts_required,
        )
    receipt_evidence = (
        "caller-declared"
        if receipt_verification["caller_declared"]
        else "server-observed"
        if receipt_verification["server_observed"]
        else "none"
    )
    receipt_metadata = {
        "tool_receipt_required": _proxy_tool_receipts_required(security_context) or force_tool_receipts,
        "tool_receipt_server_observed_required": server_observed_receipts_required,
        "tool_receipts_verified": receipt_verification["verified"],
        "tool_receipts_server_observed": receipt_verification["server_observed"],
        "tool_receipts_caller_declared": receipt_verification["caller_declared"],
        "tool_receipt_evidence": receipt_evidence,
    }
    request_model = str(payload.get("model") or "").strip()
    provider_profile = str(options.get("target_provider_profile") or "target").strip().lower()[:40]
    if not PROXY_SAFE_IDENTIFIER_RE.fullmatch(provider_profile):
        raise ValueError("透明代理的 Provider 配置档案格式无效")
    if security_context is not None and context_role not in {"analyst", "admin"} and provider_profile != "target":
        raise ValueError("当前凭证不能选择透明代理的其他 Provider 配置档案")
    raw_model_override = str(options.get("target_model") or "")
    model_override = _safe_model_label(raw_model_override, max_chars=PROXY_MAX_MODEL_CHARS)
    if raw_model_override and (not model_override or model_override != raw_model_override.strip()):
        raise ValueError("透明代理的 target_model 格式无效")
    if model_override and not _env_bool("AGENT_SUPERVISOR_PROXY_ALLOW_MODEL_OVERRIDE", False) and context_role not in {
        "analyst",
        "admin",
    }:
        raise ValueError("当前凭证不能覆盖透明代理的目标模型")
    model = model_override or request_model
    policy_settings = get_policy_settings()
    task_id, task_id_provided = _proxy_task_id(options, security_context)
    task_binding = resolve_task_profile(agent_id, task_id, settings=policy_settings)
    task_context = task_audit_context(task_binding)
    task_metadata = _task_response_metadata(task_binding, provided=task_id_provided)
    if task_binding.required and not task_binding.valid:
        task_audit = _record_proxy_task_profile_audit(
            session_id=session_id,
            agent_id=agent_id,
            request_id=request_id,
            request_hash=request_hash,
            task_context=task_context,
        )
        raise ProxyPolicyRejectionError(task_binding.reason or "任务授权无效。", gateway_audit=task_audit)
    model_allowlist = get_agent_model_allowlist(policy_settings, agent_id) if context.get("agent_id") else None
    tool_allowlist = get_agent_tool_allowlist(policy_settings, agent_id) if context.get("agent_id") else None
    task_tool_allowlist = (
        [str(item).strip().lower() for item in (task_binding.profile or {}).get("allowed_capabilities", []) if str(item).strip()]
        if task_binding.required
        else None
    )
    provider_tool_allowlist = task_tool_allowlist if task_tool_allowlist is not None else tool_allowlist
    model_allowlist_issue = model_allowlist_reason(model, model_allowlist)
    if model_allowlist_issue and context_role not in {"admin"}:
        model_audit = _record_proxy_model_allowlist_audit(
            session_id=session_id,
            agent_id=agent_id,
            request_id=request_id,
            request_hash=request_hash,
            model=model,
            reason=model_allowlist_issue,
            task_context=task_context,
        )
        raise ProxyPolicyRejectionError(model_allowlist_issue, gateway_audit=model_audit)
    request_guard = _proxy_request_guard(
        payload=payload,
        request_id=request_id,
        conversation_id=session_id,
        agent_id=agent_id,
        request_hash=request_hash,
        task_context=task_context,
    )
    if request_guard is None and isinstance(messages, list):
        request_guard = _proxy_tool_result_guard(
            messages=messages,
            request_id=request_id,
            conversation_id=session_id,
            agent_id=agent_id,
            request_hash=request_hash,
            task_context=task_context,
        )
    if request_guard:
        response: dict[str, Any] = {
            "id": request_id,
            "object": "chat.completion",
             "created": int(time.time()),
             "model": _safe_model_label(model),
            "choices": [{"index": 0, "message": {"role": "assistant", "content": ""}, "finish_reason": "stop"}],
        }
        _replace_blocked_choices(response, request_guard)
        response["agent_supervisor"] = {
            "mode": "transparent",
            "request_id": request_id,
            "session_id": session_id,
            "session_id_provided": session_id_provided,
            "request_stage": request_guard.get("request_stage", "pre-provider-input"),
            "agent_id": agent_id,
            "caller_role": context_role,
            "agent_identity_verified": bool(context.get("agent_id")),
            "provider": "未调用",
            "provider_called": False,
            "provider_endpoint_scope": "not-called",
             "provider_profile": provider_profile,
             "model": _safe_model_label(model),
             "model_allowlist_enforced": model_allowlist is not None and context_role not in {"admin"},
            "tool_allowlist_enforced": provider_tool_allowlist is not None,
            "request_hash": request_hash,
            "provider_request_hash": "",
            "provider_response_hash": "",
            "provider_response_id": "",
            "tool_call_count": 0,
            "tool_decisions": [],
            "invalid_tool_calls": [],
            "output_filter_blocked": False,
            "output_findings": [],
            "tool_argument_findings": [],
            "decision": request_guard["decision"],
            "policy_id": request_guard["policy_id"],
            "reason": request_guard["reason"],
            "risk_score": request_guard["risk_score"],
            "risk_factors": request_guard.get("risk_factors", []),
            "request_guard": request_guard,
            "tool_result_scan": request_guard.get("tool_result_scan", []),
            "audit_id": request_guard.get("audit_id", ""),
            "audit_ids": [request_guard.get("audit_id", "")] if request_guard.get("audit_id") else [],
            "execution_boundary": "gateway-blocked-before-provider",
            "execution_outcome": "blocked-before-execution",
            "tool_execution": "not-returned-to-caller",
            "decision_enforced_before_tool_execution": True,
            "evidence_scope": "gateway-contract",
            "gateway_contract_evidence": "pre-provider-block",
            "decision_source": "gateway-request-policy",
            **task_metadata,
            **receipt_metadata,
            "stream_buffered": True,
        }
        response["agent_supervisor"].update(_gateway_evidence_metadata())
        _apply_execution_contract_metadata(response["agent_supervisor"])
        return response
    tool_scan = _scan_proxy_tool_definitions(payload)
    tool_allowlist_audit: dict[str, Any] | None = None
    tool_allowlist_scan = _proxy_tool_allowlist_scan(
        payload,
        agent_id=agent_id,
        allowed_tools=provider_tool_allowlist,
    )
    if tool_allowlist_scan["blocked"] and not tool_scan["blocked"]:
        first_allowlist_finding = tool_allowlist_scan["findings"][0]
        tool_allowlist_audit = _record_proxy_tool_allowlist_audit(
            session_id=session_id,
            agent_id=agent_id,
            request_id=request_id,
            request_hash=request_hash,
            finding=first_allowlist_finding,
            task_context=task_context,
        )
        tool_scan = {
            "blocked": True,
            "findings": [*tool_scan["findings"], *tool_allowlist_scan["findings"]],
            "reason": _safe_tool_allowlist_reason(),
            "policy_id": "tool-contract",
        }
    if tool_scan["blocked"]:
        audit_result = tool_allowlist_audit or evaluate_agent_event(
            {
                "conversation_id": session_id,
                "agent_id": agent_id,
                "agent_role": "openai-compatible-agent",
                "source_app": "openai-compatible-proxy",
                "model_input": tool_scan["reason"],
                "model_output": tool_scan["reason"],
                "context_sources": ["openai-compatible-client", "tool-definition"],
                "tool_call": {
                    "tool": "model.respond",
                    "arguments": {"topic": tool_scan["reason"]},
                    "risk_hint": "tool_description_poison",
                },
                "stage_context": {
                    "session_id": session_id,
                    "request_id": request_id,
                    "request_hash": request_hash,
                    "provider_called": False,
                    **task_context,
                },
            },
            guard_enabled=True,
            execute_managed=False,
        )
        response = {
            "id": request_id,
            "object": "chat.completion",
            "created": int(time.time()),
            "model": model,
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                         "content": (
                             "[智垒] 本次请求已阻断：Agent 工具能力未登记。"
                             if tool_allowlist_audit is not None
                             else "[智垒] 本次请求已隔离：工具定义命中投毒扫描策略。"
                         ),
                    },
                    "finish_reason": "content_filter",
                }
            ],
            "agent_supervisor": {
                "mode": "transparent",
                "request_id": request_id,
                "session_id": session_id,
                "session_id_provided": session_id_provided,
                "request_stage": "tool-definition",
                "agent_id": agent_id,
                "caller_role": context_role,
                 "agent_identity_verified": bool(context.get("agent_id")),
                 "provider": "未调用",
                 "provider_called": False,
                 "provider_endpoint_scope": "not-called",
                 "provider_profile": provider_profile,
                 "model": model,
                "tool_allowlist_enforced": provider_tool_allowlist is not None,
                 "request_hash": request_hash,
                "provider_request_hash": "",
                "provider_response_hash": "",
                "provider_response_id": "",
                "tool_call_count": 0,
                "tool_decisions": [],
                "invalid_tool_calls": [],
                "output_filter_blocked": False,
                "output_findings": [],
                "tool_result_scan": [],
                "tool_argument_findings": [],
                # The raw tool name/description is caller-controlled and may
                # itself contain an instruction. Keep only hashes/signals in
                # the model-visible extension; the signed audit row retains
                # the detailed scanner evidence for operators.
                "tool_definition_scan": _safe_tool_definition_findings(tool_scan["findings"]),
                "decision": audit_result["decision"],
                 "policy_id": tool_scan.get("policy_id") or "tool-description-scan",
                 "reason": (
                     _safe_tool_allowlist_reason()
                     if tool_allowlist_audit is not None
                     else _safe_tool_definition_reason()
                 ),
                "risk_score": max(90, audit_result.get("risk_score", 0)),
                "audit_id": audit_result["audit_id"],
                "audit_ids": [audit_result["audit_id"]] if audit_result.get("audit_id") else [],
                "execution_boundary": "gateway-blocked-before-provider",
                "execution_outcome": "blocked-before-execution",
                "tool_execution": "not-returned-to-caller",
                "decision_enforced_before_tool_execution": True,
                "evidence_scope": "gateway-contract",
                "gateway_contract_evidence": "pre-provider-tool-definition-block",
                "decision_source": "gateway-tool-definition-policy",
                **task_metadata,
                **receipt_metadata,
                "stream_buffered": True,
            },
        }
        response["agent_supervisor"].update(_gateway_evidence_metadata())
        _apply_execution_contract_metadata(response["agent_supervisor"])
        return response
    stripped_provider_request_fields = _stripped_provider_request_fields(payload)
    stripped_provider_message_fields = _stripped_provider_message_fields(
        messages if isinstance(messages, list) else []
    )
    stripped_provider_tool_fields = _stripped_provider_tool_fields(payload)
    provider_payload = prepare_openai_provider_payload(payload)
    prompt = _extract_prompt(messages if isinstance(messages, list) else [])
    model_visible_messages: list[Any] = messages if isinstance(messages, list) else []
    tool_result_visibility: list[dict[str, Any]] = []
    if isinstance(messages, list):
        model_visible_messages, tool_result_visibility = _sanitize_proxy_tool_results(messages)
        provider_payload["messages"] = _project_provider_messages(model_visible_messages)
    try:
        provider_result = forward_openai_chat_completion(
            provider_payload,
            provider_profile=provider_profile,
            model_override=model_override,
            stream_callback=provider_stream_callback,
            stream_cancel_event=stream_cancel_event,
        )
    except ModelProviderStreamCancelledError as exc:
        released_char_count = _stream_released_char_count(stream_released_char_count_supplier)
        audit = _record_gateway_provider_failure_audit(
            session_id=session_id,
            agent_id=agent_id,
            request_id=request_id,
            prompt=prompt,
            request_hash=request_hash,
            provider_profile=provider_profile,
            model=model,
            failures=[],
            failure_kind="client-cancelled-stream",
            provider_called=True,
            provider_attempted=True,
            provider_output_exposed=released_char_count > 0,
            stream_released_char_count=released_char_count,
            task_context=task_context,
        )
        exc.gateway_audit = audit
        raise
    except ModelProviderUnavailableError as exc:
        released_char_count = _stream_released_char_count(stream_released_char_count_supplier)
        provider_called = bool(exc.failures) or released_char_count > 0
        audit = _record_gateway_provider_failure_audit(
            session_id=session_id,
            agent_id=agent_id,
            request_id=request_id,
            prompt=prompt,
            request_hash=request_hash,
            provider_profile=provider_profile,
            model=model,
            failures=exc.failures,
            provider_called=provider_called,
            provider_attempted=provider_called,
            provider_output_exposed=released_char_count > 0,
            stream_released_char_count=released_char_count,
            task_context=task_context,
        )
        exc.gateway_audit = audit
        raise
    except ValueError as exc:
        # Provider protocol failures are upstream failures, not malformed Agent
        # requests.  Record the same no-output boundary and expose a 502 to HTTP
        # clients so retries and operational dashboards classify them correctly.
        released_char_count = _stream_released_char_count(stream_released_char_count_supplier)
        audit = _record_gateway_provider_failure_audit(
            session_id=session_id,
            agent_id=agent_id,
            request_id=request_id,
            prompt=prompt,
            request_hash=request_hash,
            provider_profile=provider_profile,
            model=model,
            failures=[],
            failure_kind="provider-response-contract",
            provider_called=True,
            provider_attempted=True,
            provider_output_exposed=released_char_count > 0,
            stream_released_char_count=released_char_count,
            task_context=task_context,
        )
        raise ModelProviderUnavailableError("模型供应商响应未通过网关协议校验。", [], gateway_audit=audit) from exc
    try:
        upstream = provider_result["response"]
        if not isinstance(upstream, dict):
            raise ValueError("模型供应商响应不是 JSON 对象")
        response = deepcopy(upstream)
        choices = response.get("choices")
        if not isinstance(choices, list) or not choices:
            raise ValueError("模型供应商响应缺少 choices")
        if len(choices) > PROXY_MAX_PROVIDER_CHOICES:
            raise ValueError(f"模型供应商响应 choices 不能超过 {PROXY_MAX_PROVIDER_CHOICES} 个")
        provider_protocol_metadata_output = _provider_protocol_metadata_security_text(response)
        provider_protocol_normalizations = _normalize_provider_response_envelope(
            response,
            fallback_model=str(provider_result.get("model") or model),
            fallback_id=request_id,
        )
    except (KeyError, TypeError, ValueError, RecursionError):
        _raise_provider_response_contract_failure(
            session_id=session_id,
            agent_id=agent_id,
            request_id=request_id,
            prompt=prompt,
            request_hash=request_hash,
            provider_profile=provider_profile,
            model=model,
            provider_result=provider_result if isinstance(provider_result, dict) else {},
            task_context=task_context,
        )
        raise AssertionError("unreachable") from None
    requested_completions = payload.get("n", 1)
    provider_choice_count_issue = (
        f"Provider 返回 choices 数量 {len(choices)} 超过请求 n={requested_completions}"
        if security_context is not None
        and isinstance(requested_completions, int)
        and not isinstance(requested_completions, bool)
        and len(choices) > requested_completions
        else ""
    )

    tool_decisions: list[dict[str, Any]] = []
    invalid_calls: list[str] = [provider_choice_count_issue] if provider_choice_count_issue else []
    output_findings: list[dict[str, Any]] = []
    output_blocked = False
    tool_argument_findings: list[dict[str, str]] = []
    seen_provider_call_ids: set[str] = set()
    if provider_protocol_metadata_output:
        metadata_scan = _scan_provider_visible_output(provider_protocol_metadata_output)
        output_findings.extend(metadata_scan["findings"])
        output_blocked = output_blocked or bool(metadata_scan["blocked"])
    top_level_output = _provider_top_level_security_text(response)
    if top_level_output:
        output_scan = _scan_provider_visible_output(top_level_output)
        output_findings.extend(output_scan["findings"])
        output_blocked = output_blocked or bool(output_scan["blocked"])
    extension_output = _provider_extension_security_text(response)
    if extension_output:
        output_scan = _scan_provider_visible_output(extension_output)
        output_findings.extend(output_scan["findings"])
        output_blocked = output_blocked or bool(output_scan["blocked"])

    for choice_index, choice in enumerate(choices):
        if not isinstance(choice, dict):
            invalid_calls.append(f"choice[{choice_index}] 不是对象")
            continue
        message = choice.get("message")
        if not isinstance(message, dict):
            legacy_text = _content_to_text(choice.get("text"))
            if legacy_text:
                if not isinstance(choice.get("text"), str):
                    _raise_provider_response_contract_failure(
                        session_id=session_id,
                        agent_id=agent_id,
                        request_id=request_id,
                        prompt=prompt,
                        request_hash=request_hash,
                        provider_profile=provider_profile,
                        model=model,
                        provider_result=provider_result,
                        task_context=task_context,
                    )
                output_scan = _scan_provider_visible_output(legacy_text)
                output_findings.extend(output_scan["findings"])
                output_blocked = output_blocked or bool(output_scan["blocked"])
            else:
                invalid_calls.append(f"choice[{choice_index}] 缺少有效 message")
            continue
        normalized_content, content_issue, content_normalizations = _normalize_provider_content(
            message.get("content"),
            path=f"response.choices[{choice_index}].message.content",
        )
        provider_protocol_normalizations.extend(content_normalizations)
        if content_issue:
            _raise_provider_response_contract_failure(
                session_id=session_id,
                agent_id=agent_id,
                request_id=request_id,
                prompt=prompt,
                request_hash=request_hash,
                provider_profile=provider_profile,
                model=model,
                provider_result=provider_result,
                task_context=task_context,
            )
        message["content"] = normalized_content
        filtered = _scan_provider_visible_output(_provider_choice_security_text(choice))
        output_findings.extend(filtered["findings"])
        output_blocked = output_blocked or bool(filtered["blocked"])
        # A Provider response is model output, never a new system/developer
        # instruction.  Passing through a provider-supplied ``role=system``
        # (or an omitted/unknown role) would let a compromised upstream
        # escalate its content inside downstream Agent SDKs even when the text
        # itself looks harmless.  Keep assistant as the only model-visible
        # chat role and fail closed on every other role.
        provider_role = str(message.get("role") or "").strip().lower()
        if provider_role != "assistant":
            invalid_calls.append(
                f"choice[{choice_index}].message.role 必须是 assistant，实际为 {provider_role or 'empty'}"
            )
            continue
        message["role"] = "assistant"
        raw_tool_calls = message.get("tool_calls")
        legacy_function_call_present = "function_call" in message
        # A response carrying both protocol representations has two possible
        # execution meanings: modern clients may consume ``tool_calls`` while
        # older SDKs may consume ``function_call``.  Checking only one shape
        # would let the other call bypass schema/policy enforcement or execute
        # twice downstream.  Treat the dual shape as a protocol violation and
        # replace the whole response below; a null ``tool_calls`` field remains
        # compatible with providers that emit an empty extension alongside a
        # legacy call.
        if legacy_function_call_present and raw_tool_calls is not None:
            invalid_calls.append(
                f"choice[{choice_index}] 同时返回 tool_calls 与 function_call；响应形态存在歧义"
            )
        if raw_tool_calls is None and legacy_function_call_present:
            # Older OpenAI-compatible providers still emit the singular
            # function_call shape; it must go through the same gate.
            raw_tool_calls = [
                {
                    "id": f"legacy-{request_id}-{choice_index}",
                    "type": "function",
                    "function": message.get("function_call"),
                }
            ]
        if raw_tool_calls is None:
            continue
        if not isinstance(raw_tool_calls, list):
            invalid_calls.append(f"choice[{choice_index}] tool_calls 不是数组")
            continue
        if len(raw_tool_calls) > PROXY_MAX_PROVIDER_TOOL_CALLS:
            invalid_calls.append(
                f"choice[{choice_index}] tool_calls 不能超过 {PROXY_MAX_PROVIDER_TOOL_CALLS} 个"
            )
            continue
        for call_index, raw_call in enumerate(raw_tool_calls):
            parsed_call, parse_issue = _parse_transparent_tool_call(raw_call)
            if parsed_call and not parse_issue:
                if parsed_call["id"] in seen_provider_call_ids:
                    parse_issue = f"Provider 返回了重复的工具调用 ID：{parsed_call['id']}"
                else:
                    seen_provider_call_ids.add(parsed_call["id"])
            if parsed_call and not parse_issue:
                parse_issue = _validate_transparent_tool_call_schema(payload, parsed_call)
            if parsed_call and not parse_issue and skill_scan_enabled():
                argument_scan = _scan_proxy_tool_arguments(parsed_call["arguments"])
                if argument_scan["findings"]:
                    tool_argument_findings.extend(
                        {
                            "call_id": parsed_call["id"],
                            "path": item["path"],
                            "verdict": item["verdict"],
                            "signals": item["signals"],
                        }
                        for item in argument_scan["findings"]
                    )
                if argument_scan["blocked"]:
                    parse_issue = "工具参数命中间接提示注入或不可信外传指令"
            if parsed_call and not parse_issue:
                argument_filter = filter_model_output(
                    json.dumps(parsed_call["arguments"], ensure_ascii=False, default=str)
                )
                if argument_filter["blocked"]:
                    tool_argument_findings.extend(argument_filter["findings"])
                    parse_issue = "工具参数命中敏感凭据、系统提示词或危险指令输出策略"
            if parse_issue:
                invalid_calls.append(f"choice[{choice_index}].tool_calls[{call_index}]: {parse_issue}")

            # ``parsed_call`` is deliberately the boundary between a malformed
            # Provider envelope and a valid call that the policy layer rejected.
            # A valid call may still be denied because its schema, arguments or
            # untrusted content is unsafe.  Replacing that call with
            # ``__invalid_tool_call__`` loses the canonical capability and makes
            # baseline/protected causal evidence compare different hashes.  Keep
            # the normalized call whenever parsing succeeded; reserve the
            # synthetic marker for a structure that could not be parsed at all.
            if parsed_call is not None:
                audit_call = {
                    "tool": parsed_call["tool"],
                    "arguments": parsed_call["arguments"],
                }
            else:
                audit_call = {
                    "tool": "__invalid_tool_call__",
                    "arguments": {"raw_call": str(raw_call)[:2000]},
                }
            audit_event = {
                "conversation_id": session_id,
                "agent_id": agent_id,
                "agent_role": "openai-compatible-agent",
                "source_app": "openai-compatible-proxy",
                "model_input": prompt,
                "model_output": json.dumps(message, ensure_ascii=False, default=str)[:4000],
                "context_sources": ["openai-compatible-client", "provider-response"],
                "tool_call": audit_call,
                "stage_context": {
                    "provider": provider_result.get("provider", ""),
                    "provider_profile": provider_profile,
                    "provider_model": provider_result.get("model", model),
                    "provider_call_id": parsed_call.get("id", "") if parsed_call else "",
                    "session_id": session_id,
                    "request_id": request_id,
                    "tool_call_index": call_index,
                    "request_hash": request_hash,
                    "provider_request_hash": provider_result.get("request_hash", ""),
                    "provider_response_hash": provider_result.get("provider_response_hash", ""),
                    "provider_response_id": provider_result.get("provider_response_id", ""),
                    "provider_called": True,
                    **task_context,
                },
            }
            try:
                audit_result = evaluate_agent_event(
                    audit_event,
                    guard_enabled=True,
                    execute_managed=False,
                )
            except ValueError as error:
                # A malformed administrator mapping or provider-shaped call
                # must fail closed and still leave a normal audit record.
                # Keep the normalized tool for successfully parsed calls even
                # when a custom mapping raises during evaluation.  The
                # evaluator's normal contract path accepts standard canonical
                # capabilities; only an entirely unparseable envelope falls
                # back to the synthetic invalid marker.
                if parsed_call is not None:
                    fallback_event = {
                        **audit_event,
                        "tool_call": {
                            "tool": parsed_call["tool"],
                            "arguments": parsed_call["arguments"],
                            "risk_hint": "provider-tool-contract",
                        },
                    }
                else:
                    fallback_event = {
                        **audit_event,
                        "tool_call": {
                            "tool": "__invalid_tool_call__",
                            "arguments": {"raw_call": str(raw_call)[:2000]},
                        },
                    }
                try:
                    audit_result = evaluate_agent_event(
                        fallback_event,
                        guard_enabled=True,
                        execute_managed=False,
                    )
                except ValueError:
                    # If a parsed custom call cannot be resolved by the
                    # administrator mapping, the synthetic record is the only
                    # durable fallback that satisfies the audit schema.
                    if parsed_call is None:
                        raise
                    audit_result = evaluate_agent_event(
                        {
                            **audit_event,
                            "tool_call": {
                                "tool": "__invalid_tool_call__",
                                "arguments": {"raw_call": str(raw_call)[:2000]},
                            },
                        },
                        guard_enabled=True,
                        execute_managed=False,
                    )
                parse_issue = parse_issue or str(error)
            if parse_issue:
                audit_result = {
                    **audit_result,
                    "decision": "拒绝",
                    "policy_id": "tool-contract",
                    "reason": f"模型返回的工具调用格式无效：{parse_issue}",
                }
            decision_reason = str(audit_result.get("reason") or "工具调用已由网关策略处置。")
            if parse_issue or str(audit_result.get("decision") or "") in CONTROL_DECISIONS:
                decision_reason = _safe_tool_boundary_reason(str(audit_result.get("policy_id") or "tool-contract"))
            tool_decisions.append(
                {
                    "choice_index": choice_index,
                    "index": call_index,
                    "call_id": parsed_call.get("id", "") if parsed_call else "",
                    "external_tool": parsed_call.get("external_tool", "") if parsed_call else "",
                    "tool": parsed_call["tool"] if parsed_call else "",
                    "arguments_hash": _proxy_payload_hash(parsed_call.get("arguments", {})) if parsed_call else "",
                    "decision": audit_result["decision"],
                    "policy_id": audit_result["policy_id"],
                    "reason": decision_reason,
                    "audit_id": audit_result["audit_id"],
                    "risk_score": audit_result.get("risk_score", 0),
                }
            )

    blocked_decisions = {"拒绝", "询问", "隔离"}
    controlled = [item for item in tool_decisions if item["decision"] in blocked_decisions]
    output_audit: dict[str, Any] | None = None
    if output_blocked:
        output_audit = evaluate_agent_event(
            {
                "conversation_id": session_id,
                "agent_id": agent_id,
                "agent_role": "openai-compatible-agent",
                "source_app": "openai-compatible-proxy",
                "model_input": prompt,
                "model_output": _response_content_excerpt(response),
                "context_sources": ["openai-compatible-client", "provider-response"],
                "tool_call": {
                    "tool": "model.respond",
                    "arguments": {"topic": _response_content_excerpt(response)[:1000]},
                    "risk_hint": "jailbreak_output",
                },
                "stage_context": {
                    "session_id": session_id,
                    "request_id": request_id,
                    "provider": provider_result.get("provider", ""),
                    "provider_profile": provider_profile,
                    "provider_model": provider_result.get("model", model),
                    "provider_response_id": provider_result.get("provider_response_id", ""),
                    "request_hash": request_hash,
                    "provider_request_hash": provider_result.get("request_hash", ""),
                    "provider_response_hash": provider_result.get("provider_response_hash", ""),
                    "provider_called": True,
                    **task_context,
                },
            },
            guard_enabled=True,
            execute_managed=False,
        )
        controlled.append(
            {
                "decision": output_audit["decision"],
                "policy_id": output_audit["policy_id"],
                "reason": _safe_model_boundary_reason("provider-output"),
                "audit_id": output_audit["audit_id"],
                "risk_score": output_audit.get("risk_score", 0),
            }
        )

    if invalid_calls:
        controlled.append(
            {
                "decision": "拒绝",
                "policy_id": "tool-contract",
                # ``invalid_calls`` contains Provider-controlled parse details.
                # Keep those details in the hashed audit evidence only; using
                # them as the blocked assistant message would create a direct
                # response-injection channel for malformed tool envelopes.
                "reason": "模型返回的工具调用未通过协议校验；原始调用仅保留在审计证据中。",
                "audit_id": tool_decisions[-1]["audit_id"] if tool_decisions else "",
                "risk_score": 90,
            }
        )

    gateway_audit: dict[str, Any] | None = None
    if not tool_decisions and output_audit is None:
        gateway_audit = _record_gateway_response_audit(
            session_id=session_id,
            agent_id=agent_id,
            request_id=request_id,
            request_hash=request_hash,
            prompt=prompt,
            response=response,
            provider_result=provider_result,
            provider_profile=provider_profile,
            task_context=task_context,
        )

    overall = _aggregate_proxy_decision(controlled)
    provider_extensions_stripped: list[str] = []
    reasoning_channels_stripped: list[str] = []
    if overall["decision"] in blocked_decisions:
        _replace_blocked_choices(response, overall)
    elif output_blocked:
        # A text-only response with a finding is still replaced even if the
        # model.respond audit was unavailable for an unusual provider shape.
        _replace_blocked_choices(response, {
            "decision": "拒绝",
            "policy_id": "model-output-filter",
            "reason": "模型输出命中敏感信息或危险指令过滤策略。",
        })
    else:
        # A clean response still must not carry arbitrary vendor-defined text
        # or nested metadata into an Agent.  The scan above has already
        # inspected those fields; this pass enforces the protocol allowlist.
        reasoning_channels_stripped = _strip_provider_reasoning(response)
        provider_extensions_stripped = _strip_provider_extensions(response)

    metadata = {
        "mode": "transparent",
        "request_id": request_id,
        "session_id": session_id,
        "session_id_provided": session_id_provided,
        "agent_id": agent_id,
        "caller_role": context_role,
        "agent_identity_verified": bool(context.get("agent_id")),
        "provider": (
            str(provider_result.get("provider", ""))[:120]
            if PROXY_SAFE_IDENTIFIER_RE.fullmatch(str(provider_result.get("provider", "")))
            else "unknown"
        ),
        "provider_called": True,
        "provider_endpoint_scope": str(provider_result.get("provider_endpoint_scope") or "unknown")[:64],
        "provider_network_observation": (
            provider_result.get("provider_network_observation")
            if isinstance(provider_result.get("provider_network_observation"), dict)
            else {}
        ),
        "provider_profile": provider_profile,
        "model": _safe_protocol_identifier(provider_result.get("model") or model, fallback="unknown-model"),
         "model_allowlist_enforced": model_allowlist is not None and context_role not in {"admin"},
         "tool_allowlist_enforced": provider_tool_allowlist is not None,
        "request_hash": request_hash,
        "provider_request_hash": provider_result.get("request_hash", ""),
        "provider_response_hash": provider_result.get("provider_response_hash", ""),
        "provider_response_id": _safe_protocol_identifier(provider_result.get("provider_response_id", "")),
        "provider_failures": _safe_provider_failures(provider_result.get("provider_failures", [])),
        "request_stage": "post-provider-output",
        "request_guard": {
            "checked": True,
            "decision": "允许",
            "policy_id": "pre-provider-input",
            "untrusted_content_present": bool(_extract_untrusted_prompt(messages if isinstance(messages, list) else [])),
        },
        "tool_call_count": len(tool_decisions),
        "audit_id": (
            tool_decisions[0].get("audit_id", "")
            if tool_decisions
            else output_audit.get("audit_id", "")
            if output_audit
            else gateway_audit.get("audit_id", "")
            if gateway_audit
            else ""
        ),
        "audit_ids": [
            *[item.get("audit_id", "") for item in tool_decisions if item.get("audit_id")],
            *([output_audit.get("audit_id", "")] if output_audit and output_audit.get("audit_id") else []),
            *([gateway_audit.get("audit_id", "")] if gateway_audit and gateway_audit.get("audit_id") else []),
        ],
        "tool_decisions": _safe_tool_decisions(tool_decisions),
        "invalid_tool_calls": _safe_invalid_tool_calls(invalid_calls),
        "output_filter_blocked": output_blocked,
        "output_findings": output_findings,
        "provider_extensions_stripped": [str(item)[:200] for item in provider_extensions_stripped[:128]],
        "reasoning_channels_stripped": [str(item)[:200] for item in reasoning_channels_stripped[:64]],
        "provider_protocol_normalizations": provider_protocol_normalizations[:128],
        "provider_request_fields_stripped": stripped_provider_request_fields,
        "provider_message_fields_stripped": stripped_provider_message_fields,
        "provider_tool_fields_stripped": stripped_provider_tool_fields,
        "reasoning_exposed": _env_bool("AGENT_SUPERVISOR_PROXY_EXPOSE_REASONING", False),
        "output_audit_id": output_audit.get("audit_id", "") if output_audit else "",
        "gateway_audit_id": gateway_audit.get("audit_id", "") if gateway_audit else "",
        "tool_definition_scan": _safe_tool_definition_findings(tool_scan["findings"]),
        "tool_argument_findings": _safe_tool_argument_findings(tool_argument_findings),
        "tool_result_visibility": tool_result_visibility,
        "decision": overall["decision"],
        "policy_id": overall["policy_id"],
        "reason": overall["reason"],
        "risk_score": overall.get("risk_score", 0),
        "execution_boundary": (
            "gateway-blocked-before-tool-execution"
            if overall["decision"] in blocked_decisions
            else "caller-owned-tool-execution"
        ),
        "execution_outcome": (
            "blocked-before-execution"
            if overall["decision"] in blocked_decisions
            else "awaiting-caller-execution"
            if tool_decisions
            else "no-tool-execution"
        ),
        "tool_execution": (
            "not-returned-to-caller"
            if overall["decision"] in blocked_decisions
            else "caller-must-enforce-and-report-receipt"
        ),
        "decision_enforced_before_tool_execution": overall["decision"] in blocked_decisions,
        "evidence_scope": "gateway-contract",
        "gateway_contract_evidence": (
            "provider-output-block" if overall["decision"] in blocked_decisions else "provider-response-returned"
        ),
        "decision_source": "gateway-provider-response-policy",
        **task_metadata,
        **receipt_metadata,
        "stream_buffered": provider_stream_callback is None,
        "provider_streamed": bool(provider_result.get("provider_streamed")),
        "provider_stream_chunk_count": int(provider_result.get("provider_stream_chunk_count") or 0),
    }
    metadata.update(_gateway_evidence_metadata())
    _apply_execution_contract_metadata(metadata)
    response.setdefault("id", request_id)
    response.setdefault("object", "chat.completion")
    response["agent_supervisor"] = metadata
    return response


PROXY_STREAM_SAFETY_WINDOW_ENV = "AGENT_SUPERVISOR_PROXY_STREAM_SAFETY_WINDOW_CHARS"
PROXY_STREAM_DEFAULT_SAFETY_WINDOW_CHARS = 256
PROXY_STREAM_MIN_SAFETY_WINDOW_CHARS = 64
PROXY_STREAM_MAX_SAFETY_WINDOW_CHARS = 4096
PROXY_STREAM_QUEUE_ITEMS = 128


def _proxy_stream_safety_window_chars() -> int:
    raw = os.getenv(PROXY_STREAM_SAFETY_WINDOW_ENV, str(PROXY_STREAM_DEFAULT_SAFETY_WINDOW_CHARS))
    try:
        value = int(raw)
    except ValueError:
        value = PROXY_STREAM_DEFAULT_SAFETY_WINDOW_CHARS
    return max(PROXY_STREAM_MIN_SAFETY_WINDOW_CHARS, min(value, PROXY_STREAM_MAX_SAFETY_WINDOW_CHARS))


def _sse_data(value: dict[str, Any] | str) -> str:
    serialized = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    return f"data: {serialized}\n\n"


class _SafeProviderStreamProjector:
    """Release only text that has cleared a bounded trailing safety window.

    Tool calls, reasoning and Provider extensions never pass through this
    incremental projector.  They remain buffered until the complete response
    has passed the existing post-Provider policy and audit path.
    """

    def __init__(self, *, request_id: str, model: str, created: int, safety_window_chars: int) -> None:
        self.request_id = request_id
        self.model = _safe_model_label(model, fallback="unknown-model")
        self.created = created
        self.safety_window_chars = safety_window_chars
        self.choices: dict[int, dict[str, Any]] = {}
        self.provider_tool_delta_seen = False
        self.provider_chunk_count = 0

    @property
    def released_char_count(self) -> int:
        return sum(int(state["released"]) for state in self.choices.values())

    def ingest(self, chunk: dict[str, Any]) -> list[dict[str, Any]]:
        self.provider_chunk_count += 1
        projected_choices: list[dict[str, Any]] = []
        raw_choices = chunk.get("choices")
        if not isinstance(raw_choices, list):
            return []
        for raw_choice in raw_choices:
            if not isinstance(raw_choice, dict):
                continue
            index = raw_choice.get("index")
            if not isinstance(index, int) or isinstance(index, bool):
                continue
            delta = raw_choice.get("delta")
            if not isinstance(delta, dict):
                continue
            if "tool_calls" in delta or "function_call" in delta:
                self.provider_tool_delta_seen = True
            content = delta.get("content")
            if content is None:
                continue
            if not isinstance(content, str):
                continue
            state = self.choices.setdefault(index, {"text": "", "released": 0, "blocked": False, "role_sent": False})
            state["text"] = str(state["text"]) + content
            if len(str(state["text"])) > PROXY_MAX_TOTAL_TEXT_CHARS:
                state["blocked"] = True
                continue
            scan = _scan_provider_visible_output(str(state["text"]))
            if scan["blocked"]:
                state["blocked"] = True
                continue
            safe_end = max(0, len(str(state["text"])) - self.safety_window_chars)
            released = int(state["released"])
            if state["blocked"] or safe_end <= released:
                continue
            safe_delta = str(state["text"])[released:safe_end]
            state["released"] = safe_end
            projected_delta: dict[str, Any] = {"content": safe_delta}
            if not state["role_sent"]:
                projected_delta["role"] = "assistant"
                state["role_sent"] = True
            projected_choices.append({"index": index, "delta": projected_delta, "finish_reason": None})
        if not projected_choices:
            return []
        return [
            {
                "id": self.request_id,
                "object": "chat.completion.chunk",
                "created": self.created,
                "model": self.model,
                "choices": projected_choices,
            }
        ]

    def finalize(self, result: dict[str, Any]) -> list[dict[str, Any]]:
        raw_choices = result.get("choices")
        choices = raw_choices if isinstance(raw_choices, list) and raw_choices else [{}]
        metadata = result.get("agent_supervisor")
        metadata = metadata if isinstance(metadata, dict) else {}
        blocked = str(metadata.get("decision") or "") in CONTROL_DECISIONS or metadata.get("output_filter_blocked") is True
        deltas: list[dict[str, Any]] = []
        finishes: list[dict[str, Any]] = []
        for fallback_index, raw_choice in enumerate(choices):
            choice = raw_choice if isinstance(raw_choice, dict) else {}
            raw_index = choice.get("index")
            index = raw_index if isinstance(raw_index, int) and not isinstance(raw_index, bool) else fallback_index
            raw_message = choice.get("message")
            message = raw_message if isinstance(raw_message, dict) else {}
            delta: dict[str, Any] = {}
            content = _content_to_text(message.get("content"))
            state = self.choices.get(index)
            released = int(state["released"]) if state is not None else 0
            observed = str(state["text"]) if state is not None else ""
            if blocked:
                if content:
                    delta["content"] = content
            elif released and content.startswith(observed[:released]):
                remaining = content[released:]
                if remaining:
                    delta["content"] = remaining
            elif released == 0:
                if content:
                    delta["content"] = content
            else:
                raise ValueError("流式增量与最终安全响应不一致，已停止输出")
            if state is None or not state["role_sent"]:
                delta["role"] = "assistant"
            if not blocked and isinstance(message.get("tool_calls"), list):
                delta["tool_calls"] = message["tool_calls"]
            if not blocked and isinstance(message.get("function_call"), dict):
                delta["function_call"] = message["function_call"]
            if delta:
                deltas.append({"index": index, "delta": delta, "finish_reason": None})
            finishes.append(
                {
                    "index": index,
                    "delta": {},
                    "finish_reason": str(choice.get("finish_reason") or ("content_filter" if blocked else "stop")),
                }
            )
        frames: list[dict[str, Any]] = []
        base = {
            "id": _safe_protocol_identifier(result.get("id"), fallback=self.request_id),
            "object": "chat.completion.chunk",
            "created": result.get("created", self.created),
            "model": _safe_model_label(result.get("model"), fallback=self.model),
        }
        if deltas:
            frames.append({**base, "choices": deltas})
        frames.append({**base, "choices": finishes, "agent_supervisor": metadata})
        stream_options = result.get("_request_stream_options")
        if isinstance(stream_options, dict) and stream_options.get("include_usage") is True:
            frames.append({**base, "choices": [], "usage": result.get("usage") or {}})
        return frames


def _put_stream_queue(
    events: queue.Queue[tuple[str, Any]],
    item: tuple[str, Any],
    cancel_event: threading.Event,
) -> None:
    while not cancel_event.is_set():
        try:
            events.put(item, timeout=0.25)
            return
        except queue.Full:
            continue
    raise ModelProviderStreamCancelledError("下游客户端已取消模型流。")


def _stream_error_payload(error: BaseException) -> dict[str, Any]:
    audit = getattr(error, "gateway_audit", None)
    audit = audit if isinstance(audit, dict) else {}
    if isinstance(error, ProxyResourceLimitError):
        code = "resource_limit"
        message = "网关资源预算不足，本次流式请求未继续执行。"
    elif isinstance(error, ProxyPolicyRejectionError):
        code = "policy_rejection"
        message = "[智垒] 请求在到达 Provider 前被安全策略阻断。"
    elif isinstance(error, ModelProviderUnavailableError):
        code = "provider_stream_error"
        message = "Provider流式响应失败或在完成前中断。"
    else:
        code = "gateway_stream_error"
        message = "网关流式响应未完成。"
    return {
        "error": {"message": message, "type": "agent_supervisor_stream_error", "code": code},
        "agent_supervisor": {
            "stream_interrupted": True,
            "audit_id": str(audit.get("audit_id") or ""),
            "gateway_audit_id": str(audit.get("audit_id") or ""),
        },
    }


def stream_openai_proxy_completion(
    payload: dict[str, Any],
    *,
    security_context: dict[str, Any] | None = None,
) -> Iterable[str]:
    """Stream policy-checked text with bounded delay and buffered tool calls."""

    _validate_proxy_request(payload)
    options = payload.get("agent_supervisor") if isinstance(payload, dict) else None
    options = options if isinstance(options, dict) else {}
    mode = _validated_proxy_mode(options)
    _validate_proxy_mode_access(mode, options=options, security_context=security_context)
    if mode != "transparent":
        raise ValueError("stream=true 当前只支持 transparent 模式；managed 模式必须使用非流式请求")

    request_id = f"chatcmpl-zhian-{uuid4().hex[:16]}"
    created = int(time.time())
    model = str(payload.get("model") or "")
    safety_window = _proxy_stream_safety_window_chars()
    projector = _SafeProviderStreamProjector(
        request_id=request_id,
        model=model,
        created=created,
        safety_window_chars=safety_window,
    )
    events: queue.Queue[tuple[str, Any]] = queue.Queue(maxsize=PROXY_STREAM_QUEUE_ITEMS)
    cancel_event = threading.Event()

    def record_stream_failure_audit(failure_kind: str, *, related_audit_id: str = "") -> dict[str, Any]:
        context = security_context if isinstance(security_context, dict) else {}
        request_options = payload.get("agent_supervisor")
        request_options = request_options if isinstance(request_options, dict) else {}
        raw_messages = payload.get("messages")
        messages = raw_messages if isinstance(raw_messages, list) else []
        provider_called = projector.provider_chunk_count > 0
        released_char_count = projector.released_char_count
        return _record_gateway_provider_failure_audit(
            session_id=str(context.get("session_id") or request_options.get("session_id") or request_id),
            agent_id=str(context.get("agent_id") or request_options.get("agent_id") or "openai-compatible-proxy"),
            request_id=request_id,
            prompt=_extract_prompt(messages),
            request_hash=_proxy_payload_hash(payload),
            provider_profile=str(request_options.get("target_provider_profile") or "target")[:40],
            model=model,
            failures=[],
            failure_kind=failure_kind,
            provider_called=provider_called,
            provider_attempted=provider_called,
            provider_output_exposed=released_char_count > 0,
            stream_released_char_count=released_char_count,
            related_audit_id=related_audit_id,
        )

    def on_provider_chunk(chunk: dict[str, Any]) -> None:
        for frame in projector.ingest(chunk):
            _put_stream_queue(events, ("frame", frame), cancel_event)

    def run() -> None:
        try:
            result = run_openai_proxy_completion(
                payload,
                security_context=security_context,
                provider_stream_callback=on_provider_chunk,
                stream_cancel_event=cancel_event,
                stream_released_char_count_supplier=lambda: projector.released_char_count,
                request_id_override=request_id,
            )
            metadata = result.get("agent_supervisor")
            if not isinstance(metadata, dict):
                metadata = {}
                result["agent_supervisor"] = metadata
            metadata.update(
                {
                    "stream_buffered": False,
                    "provider_streamed": metadata.get("provider_streamed") is True,
                    "stream_security_mode": "bounded-safety-window",
                    "stream_safety_window_chars": safety_window,
                    "stream_released_char_count": projector.released_char_count,
                    "stream_tool_calls_buffered": projector.provider_tool_delta_seen,
                    "stream_interrupted": False,
                }
            )
            result["_request_stream_options"] = payload.get("stream_options")
            _put_stream_queue(events, ("result", result), cancel_event)
        except ModelProviderStreamCancelledError:
            return
        except BaseException as exc:  # noqa: BLE001 - serialized as a bounded SSE error
            if not cancel_event.is_set():
                stream_error: BaseException = exc
                if projector.provider_chunk_count and not isinstance(
                    exc,
                    (ModelProviderUnavailableError, ProxyPolicyRejectionError, ProxyResourceLimitError),
                ):
                    audit = record_stream_failure_audit("gateway-stream-finalization")
                    stream_error = GatewayStreamFinalizationError(gateway_audit=audit)
                try:
                    _put_stream_queue(events, ("error", stream_error), cancel_event)
                except ModelProviderStreamCancelledError:
                    return
        finally:
            if not cancel_event.is_set():
                try:
                    _put_stream_queue(events, ("done", None), cancel_event)
                except ModelProviderStreamCancelledError:
                    return

    worker = threading.Thread(target=run, daemon=True, name="openai-safe-provider-stream")

    def iterate() -> Iterable[str]:
        worker.start()
        completed = False
        try:
            while True:
                kind, value = events.get()
                if kind == "frame":
                    yield _sse_data(value)
                    continue
                if kind == "result":
                    try:
                        for frame in projector.finalize(value):
                            yield _sse_data(frame)
                    except (TypeError, ValueError):
                        result_metadata = value.get("agent_supervisor") if isinstance(value, dict) else None
                        result_metadata = result_metadata if isinstance(result_metadata, dict) else {}
                        audit = record_stream_failure_audit(
                            "gateway-stream-finalization",
                            related_audit_id=str(result_metadata.get("audit_id") or ""),
                        )
                        stream_error = GatewayStreamFinalizationError(gateway_audit=audit)
                        yield _sse_data(_stream_error_payload(stream_error))
                    yield _sse_data("[DONE]")
                    completed = True
                    continue
                if kind == "error":
                    yield _sse_data(_stream_error_payload(value))
                    yield _sse_data("[DONE]")
                    completed = True
                    continue
                if kind == "done":
                    return
        finally:
            if not completed:
                cancel_event.set()

    return iterate()


def _parse_transparent_tool_call(raw_call: Any) -> tuple[dict[str, Any] | None, str]:
    if not isinstance(raw_call, dict):
        return None, "tool_call 不是对象"
    call_type = str(raw_call.get("type") or "function").strip().lower()
    if call_type != "function":
        return None, f"tool_call.type 不支持：{call_type}"
    function = raw_call.get("function")
    if not isinstance(function, dict):
        return None, "tool_call.function 不是对象"
    tool = str(function.get("name") or "").strip()
    if (
        not tool
        or len(tool) > PROXY_MAX_TOOL_NAME_CHARS
        or any(ord(char) < 0x20 or ord(char) == 0x7F for char in tool)
    ):
        return None, "tool_call 缺少 function.name"
    call_id = str(raw_call.get("id") or "").strip()
    if not call_id or not PROXY_SAFE_IDENTIFIER_RE.fullmatch(call_id):
        return None, "tool_call 缺少调用 ID"
    if len(call_id) > PROXY_MAX_TOOL_CALL_ID_CHARS:
        return None, "tool_call 调用 ID 超出长度限制"
    raw_arguments = function.get("arguments", {})
    if isinstance(raw_arguments, str):
        if len(raw_arguments) > PROXY_MAX_TOOL_ARGUMENT_CHARS:
            return None, f"tool_call.arguments 超过 {PROXY_MAX_TOOL_ARGUMENT_CHARS} 个字符"
        try:
            arguments = _load_strict_tool_arguments(raw_arguments or "{}")
        except (json.JSONDecodeError, ValueError, RecursionError):
            return None, "tool_call.arguments 不是有效 JSON 或嵌套超过安全上限"
    else:
        arguments = raw_arguments
    if not isinstance(arguments, dict):
        return None, "tool_call.arguments 不是对象"
    value_issue = validate_json_value_limits(arguments, path="tool_call.arguments")
    if value_issue:
        return None, value_issue
    try:
        serialized_arguments = json.dumps(
            arguments,
            ensure_ascii=False,
            default=str,
            separators=(",", ":"),
        )
    except (TypeError, ValueError, RecursionError):
        return None, "tool_call.arguments 无法序列化"
    if len(serialized_arguments) > PROXY_MAX_TOOL_ARGUMENT_CHARS:
        return None, f"tool_call.arguments 超过 {PROXY_MAX_TOOL_ARGUMENT_CHARS} 个字符"
    return {"id": call_id, "tool": PROXY_TOOL_NAME_MAP.get(tool, tool), "external_tool": tool, "arguments": arguments}, ""


def _load_strict_tool_arguments(raw_arguments: str) -> Any:
    """Parse Provider tool arguments without parser-differential JSON keys."""

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("tool_call.arguments 包含重复 JSON 字段")
            result[key] = value
        return result

    def reject_non_finite(value: str) -> Any:
        raise ValueError(f"tool_call.arguments 包含非有限数字：{value}")

    return json.loads(
        raw_arguments,
        object_pairs_hook=reject_duplicates,
        parse_constant=reject_non_finite,
    )


def _scan_proxy_tool_definitions(payload: dict[str, Any]) -> dict[str, Any]:
    declared_items = _proxy_declared_tool_items(payload)
    if not declared_items:
        return {"blocked": False, "findings": [], "reason": ""}
    semantic_scan_enabled = skill_scan_enabled()
    findings: list[dict[str, Any]] = []
    for source, index, raw_tool, function in declared_items:
        definition = {
            "name": str(function.get("name") or ""),
            "description": "\n".join(
                item
                for item in (
                    str(function.get("description") or ""),
                    json.dumps(function.get("parameters"), ensure_ascii=False, default=str),
                )
                if item and item != "null"
            ),
        }
        # Preserve a useful, redacted quarantine response for a name that is
        # syntactically outside the OpenAI function identifier contract.  The
        # input validator already rejects control/bidi/zero-width characters;
        # this catches spaces and other display text before they can reach a
        # Provider or downstream Agent.
        invalid_identifier = not PROXY_SAFE_IDENTIFIER_RE.fullmatch(definition["name"])
        # Scan both the documented model-visible fields and the complete raw
        # definition.  Provider-specific extensions are not part of the
        # OpenAI contract, but compatible providers may still copy them into
        # their prompt.  Restricting the scan to description/schema leaves a
        # hidden ``metadata``/``x-*`` field as an instruction injection slot.
        scans = [scan_tool_definition(definition)] if semantic_scan_enabled else []
        try:
            raw_definition = json.dumps(raw_tool, ensure_ascii=False, default=str, separators=(",", ":"))
        except (TypeError, ValueError):
            raw_definition = ""
        if raw_definition and semantic_scan_enabled:
            scans.append(scan_text(raw_definition, quarantine_on_truncate=True))
        signals = list(dict.fromkeys(signal for scan in scans for signal in scan.signals))
        if any(scan.verdict == VERDICT_QUARANTINE for scan in scans):
            verdict = VERDICT_QUARANTINE
        elif any(scan.verdict != "clean" for scan in scans):
            verdict = next(scan.verdict for scan in scans if scan.verdict != "clean")
        else:
            verdict = "clean"
        if invalid_identifier:
            signals = list(dict.fromkeys([*signals, "invalid-tool-identifier"]))
            verdict = VERDICT_QUARANTINE
        if verdict != "clean":
            findings.append(
                {
                    "source": source,
                    "index": index,
                    "name": definition["name"],
                    "verdict": verdict,
                    "signals": signals,
                }
            )
    quarantined = [item for item in findings if item["verdict"] == VERDICT_QUARANTINE]
    if not quarantined:
        return {"blocked": False, "findings": findings, "reason": "", "policy_id": "tool-description-scan"}
    policy_id = (
        "tool-contract"
        if any("invalid-tool-identifier" in item.get("signals", []) for item in quarantined)
        else "tool-description-scan"
    )
    details = "；".join(
        f"{item.get('source', 'tools')}[{item['index']}] {item['name'] or 'unnamed'}: {', '.join(item['signals'])}"
        for item in quarantined[:4]
    )
    return {
        "blocked": True,
        "findings": findings,
        "reason": f"工具定义命中投毒扫描：{details}",
        "policy_id": policy_id,
    }


def _proxy_tool_allowlist_scan(
    payload: dict[str, Any],
    *,
    agent_id: str,
    allowed_tools: list[str] | None,
) -> dict[str, Any]:
    """Enforce Agent capability registration before exposing tools to a Provider.

    The post-Provider tool-call gate is still required, but it is not the first
    least-privilege boundary: a model should not receive schemas for capabilities
    its authenticated Agent is not allowed to use. MCP already applies this rule
    while building ``tools/list``; the OpenAI-compatible path must make the same
    decision before forwarding ``tools`` upstream.

    ``None`` means local/in-process compatibility or an unbound caller. An empty
    list is deliberate fail-closed production state and therefore quarantines
    every declared tool rather than silently exposing a default capability set.
    """
    declared_items = _proxy_declared_tool_items(payload)
    if not declared_items or not agent_id or allowed_tools is None:
        return {"blocked": False, "findings": [], "policy_id": "tool-contract"}

    allowed = {str(item).strip().lower() for item in allowed_tools if str(item).strip()}
    settings = get_policy_settings()
    registry = settings.get("agent_tool_mappings")
    merged_registry: dict[str, Any] = {}
    if isinstance(registry, dict):
        wildcard = registry.get("*")
        if isinstance(wildcard, dict):
            merged_registry.update(wildcard)
        scoped = registry.get(agent_id)
        if isinstance(scoped, dict):
            merged_registry.update(scoped)

    findings: list[dict[str, Any]] = []
    for source, index, _raw_tool, function in declared_items:
        name = str(function.get("name") or "").strip()
        normalized_name = name.lower()
        candidates = {normalized_name}
        mapped_name = PROXY_TOOL_NAME_MAP.get(name)
        if mapped_name:
            candidates.add(mapped_name.lower())
        mapping = merged_registry.get(normalized_name)
        if isinstance(mapping, dict):
            capability = str(mapping.get("capability") or "").strip().lower()
            if capability:
                candidates.add(capability)
        if candidates & allowed:
            continue
        findings.append(
            {
                "source": source,
                "index": index,
                "name": name,
                "verdict": VERDICT_QUARANTINE,
                "signals": ["agent-tool-allowlist"],
            }
        )

    return {
        "blocked": bool(findings),
        "findings": findings,
        "policy_id": "tool-contract",
    }


def _record_proxy_tool_allowlist_audit(
    *,
    session_id: str,
    agent_id: str,
    request_id: str,
    request_hash: str,
    finding: dict[str, Any],
    task_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Persist the pre-Provider capability denial without reflecting tool text."""
    raw_name = str(finding.get("name") or "")
    event = {
        "conversation_id": session_id,
        "agent_id": agent_id,
        "agent_role": "openai-compatible-agent",
        "source_app": "openai-compatible-proxy",
        "model_input": "tool capability allowlist",
        "model_output": "",
        "context_sources": ["openai-compatible-client", "tool-definition", "agent-tool-allowlist"],
        "tool_call": {"tool": raw_name or "__invalid_tool_call__", "arguments": {}},
        "stage_context": {
            "session_id": session_id,
            "request_id": request_id,
            "request_hash": request_hash,
            "provider_called": False,
            "tool_definition_index": finding.get("index"),
            "tool_name_hash": hashlib.sha256(raw_name.encode("utf-8")).hexdigest() if raw_name else "",
            **(task_context or {}),
        },
    }
    try:
        return evaluate_agent_event(event, guard_enabled=True, execute_managed=False, receipt_required=True)
    except (TypeError, ValueError):
        # A custom mapping may require arguments that a definition-only check does
        # not have. The fallback still produces a durable tool-contract audit,
        # while keeping the original name out of the Agent-visible response.
        event["tool_call"] = {"tool": "__invalid_tool_call__", "arguments": {}}
        return evaluate_agent_event(event, guard_enabled=True, execute_managed=False, receipt_required=True)


def _scan_proxy_tool_arguments(arguments: dict[str, Any]) -> dict[str, Any]:
    """Scan provider-generated tool arguments before returning them to an Agent.

    Tool descriptions are not the only indirect-injection carrier.  A provider can
    place an instruction in a string argument (for example ``file_write.content``)
    and rely on the caller or a later model turn to treat it as trusted data.  Walk
    the bounded JSON object and quarantine only the scanner's explicit high-risk
    verdict; warning-level signals stay visible in metadata without breaking normal
    text-bearing tools.
    """
    findings: list[dict[str, Any]] = []
    # The recursive walk is intentionally capped for CPU safety, but a
    # node-count cap must never become a tail-injection bypass: an attacker can
    # otherwise hide the instruction in node 257 while keeping the first 256
    # values benign.  The canonical whole-object scan is appended after leaf
    # findings so callers still get the most precise path first.
    string_values: list[str] = []

    def collect_string_values(value: Any, depth: int = 0) -> None:
        if depth > 16:
            return
        if isinstance(value, str):
            string_values.append(value)
            return
        if isinstance(value, dict):
            for item in value.values():
                collect_string_values(item, depth + 1)
            return
        if isinstance(value, list):
            for item in value:
                collect_string_values(item, depth + 1)

    collect_string_values(arguments)
    security_text = "\n".join(string_values)
    max_nodes = 256
    max_depth = 8
    visited = 0

    def walk(value: Any, path: str, depth: int) -> None:
        nonlocal visited
        if visited >= max_nodes or depth > max_depth:
            return
        visited += 1
        if isinstance(value, str):
            verdict = scan_text(value, quarantine_on_truncate=True)
            # A URL-valued argument is the destination itself.  A path such as
            # ``/upload`` must not be mistaken for an exfiltration instruction;
            # retain the stronger instruction-override/credential signals and
            # let the API-call policy inspect the destination plus payload.
            if path.lower().endswith((".endpoint", ".url", ".uri")) and "exfiltration-channel" in verdict.signals:
                signals = [signal for signal in verdict.signals if signal != "exfiltration-channel"]
                verdict = type(verdict)(
                    verdict="quarantine" if signals else "clean",
                    signals=signals,
                )
            if verdict.verdict != "clean":
                findings.append(
                    {
                        "path": path,
                        "verdict": verdict.verdict,
                        "signals": list(verdict.signals),
                    }
                )
            return
        if isinstance(value, dict):
            for key, item in value.items():
                walk(item, f"{path}.{key}", depth + 1)
            return
        if isinstance(value, list):
            for index, item in enumerate(value):
                walk(item, f"{path}[{index}]", depth + 1)

    walk(arguments, "arguments", 0)
    whole_scan = scan_text(security_text, quarantine_on_truncate=True)
    whole_signals = list(whole_scan.signals)
    # A JSON API call naturally contains a URL and often the method ``POST``;
    # that pair alone is an egress destination, not proof that the argument is
    # an instruction to exfiltrate.  The API policy separately evaluates the
    # target, method and sensitive payload and should produce review rather
    # than a scanner quarantine for this normal shape.
    if whole_signals == ["exfiltration-channel"]:
        whole_signals = []
    if whole_signals:
        findings.append(
            {
                "path": "arguments",
                "verdict": VERDICT_QUARANTINE if whole_scan.verdict == VERDICT_QUARANTINE else whole_scan.verdict,
                "signals": whole_signals,
            }
        )
    deduplicated: list[dict[str, Any]] = []
    seen: set[tuple[str, str, tuple[str, ...]]] = set()
    for finding in findings:
        key = (
            str(finding.get("path") or ""),
            str(finding.get("verdict") or ""),
            tuple(str(signal) for signal in finding.get("signals", [])),
        )
        if key in seen:
            continue
        seen.add(key)
        deduplicated.append(finding)
    critical_findings = [item for item in deduplicated if item.get("verdict") == VERDICT_QUARANTINE]
    noncritical_findings = [item for item in deduplicated if item.get("verdict") != VERDICT_QUARANTINE]
    # Preserve every quarantine-level signal in the bounded evidence excerpt,
    # even when benign opaque-value warnings consumed the first 64 slots.
    visible_findings = noncritical_findings[: max(0, 64 - len(critical_findings))] + critical_findings[:64]
    return {
        "blocked": any(item["verdict"] == VERDICT_QUARANTINE for item in deduplicated),
        "findings": visible_findings,
        "finding_count": len(deduplicated),
        "findings_truncated": len(visible_findings) < len(deduplicated),
    }


def _aggregate_proxy_decision(controlled: list[dict[str, Any]]) -> dict[str, Any]:
    if not controlled:
        return {
            "decision": "允许",
            "policy_id": "default-allow",
            "reason": "模型响应未产生受控工具调用，允许返回给调用方。",
            "risk_score": 0,
        }
    priority = {"拒绝": 3, "隔离": 2, "询问": 1}
    selected = max(controlled, key=lambda item: priority.get(str(item.get("decision")), 0))
    return {
        "decision": str(selected.get("decision") or "拒绝"),
        "policy_id": str(selected.get("policy_id") or "tool-contract"),
        "reason": str(selected.get("reason") or "模型响应命中安全策略。"),
        "risk_score": int(selected.get("risk_score") or 0),
    }


def _replace_blocked_choices(response: dict[str, Any], decision: dict[str, Any]) -> None:
    message = {
        "role": "assistant",
        "content": (
            "[智垒] 本次模型响应已阻断。"
            f"处置：{decision.get('decision', '拒绝')}；"
            f"策略：{decision.get('policy_id', 'tool-contract')}；"
            f"原因：{decision.get('reason', '命中安全边界。')}"
        ),
    }
    raw_choices = response.get("choices")
    # A blocked response is a new gateway-owned envelope.  Never mutate only
    # the dictionary-shaped choices in place: a compromised Provider can return
    # a non-object choice (or an arbitrary object beside a valid choice), which
    # would otherwise survive the block and leak uninspected data to the Agent.
    choice_count = len(raw_choices) if isinstance(raw_choices, list) else 1
    choice_count = max(1, min(choice_count, PROXY_MAX_PROVIDER_CHOICES))
    response["choices"] = [
        {
            "index": index,
            "message": message.copy(),
            # Keep the OpenAI response shape while making a gateway block
            # machine-detectable. A normal ``stop`` would look like a
            # successful model answer to clients that ignore metadata.
            "finish_reason": "content_filter",
        }
        for index in range(choice_count)
    ]
    for field in list(response):
        if field not in PROXY_BLOCKED_RESPONSE_FIELDS:
            response.pop(field, None)


def _response_content_excerpt(response: dict[str, Any]) -> str:
    choices = response.get("choices")
    if not isinstance(choices, list):
        return ""
    parts: list[str] = []
    for choice in choices[:4]:
        if not isinstance(choice, dict):
            continue
        excerpt = _provider_choice_security_text(choice)
        if excerpt:
            parts.append(excerpt)
    top_level = _provider_top_level_security_text(response)
    if top_level:
        parts.append(top_level)
    return "\n".join(item for item in parts if item)[:4000]


def _provider_message_security_text(message: dict[str, Any]) -> str:
    """Collect every provider text channel that can become Agent-visible output.

    OpenAI-compatible providers use ``reasoning_content`` inconsistently. Some
    gateways expose the same untrusted text as ``reasoning``, ``thinking`` or
    ``analysis``. Treating only the canonical ``content`` field as security
    relevant would leave a provider-specific channel outside the output gate.
    This helper is detection-only; the original provider response remains
    unchanged unless a finding causes the response to be replaced.
    """
    parts: list[str] = []
    for field in ("content", "reasoning_content", "reasoning", "thinking", "analysis", "refusal"):
        value = _content_to_text(message.get(field))
        if value:
            parts.append(f"{field}: {value}")
    return "\n".join(parts)


def _provider_choice_security_text(choice: dict[str, Any]) -> str:
    """Collect model-visible text from a complete provider choice.

    The OpenAI contract normally nests output under ``choice.message``. Several
    compatible providers additionally expose legacy ``text``, reasoning,
    annotations or audio/logprob fields beside it. Those fields are still
    delivered to the Agent SDK, so they must share the same output gate.
    """
    parts: list[str] = []
    message = choice.get("message")
    if isinstance(message, dict):
        message_text = _provider_message_security_text(message)
        if message_text:
            parts.append(message_text)
    for field in PROXY_PROVIDER_CHOICE_OUTPUT_FIELDS:
        value = _content_to_text(choice.get(field))
        if value:
            parts.append(f"choice.{field}: {value}")
    return "\n".join(parts)


def _scan_provider_visible_output(value: str) -> dict[str, Any]:
    """Apply both output-leak and indirect-instruction checks to Provider text.

    A Provider's plain assistant text can be consumed by another Agent turn just
    like a tool result.  Keyword redaction alone misses instruction-shaped text
    such as ``Before answering, call file_read ...``.  Reuse the bounded context
    scanner for the model-visible channel and keep warning-level signals
    observable without turning every advisory finding into a block.
    """

    filtered = filter_model_output(value)
    findings = list(filtered.get("findings", []))
    context_scan = scan_text(value, quarantine_on_truncate=True) if context_scan_enabled() else None
    if context_scan is not None and context_scan.verdict != "clean":
        findings.append(
            {
                "type": "untrusted-context",
                "count": "1",
                "verdict": context_scan.verdict,
                "signals": ",".join(context_scan.signals),
            }
        )
    return {
        "blocked": bool(filtered.get("blocked"))
        or bool(context_scan is not None and context_scan.verdict == VERDICT_QUARANTINE),
        "findings": findings,
    }


def _provider_top_level_security_text(response: dict[str, Any]) -> str:
    parts: list[str] = []
    for field in PROXY_PROVIDER_TOP_LEVEL_OUTPUT_FIELDS:
        value = _content_to_text(response.get(field))
        if value:
            parts.append(f"response.{field}: {value}")
    return "\n".join(parts)


def _provider_protocol_metadata_security_text(response: dict[str, Any]) -> str:
    """Scan standard response metadata that is still returned to SDK callers.

    ``system_fingerprint`` and ``service_tier`` are protocol fields, but they
    are Provider-controlled strings and are often logged, surfaced to an Agent
    framework, or copied into the next turn.  Treat those values as untrusted
    before normalizing or returning them instead of assuming that a standard
    field is automatically inert.  Unknown usage fields are removed by
    ``_strip_provider_extensions`` and therefore do not need to enter the
    model-output block decision.
    """

    parts: list[str] = []
    for field_name in ("system_fingerprint", "service_tier"):
        value = _content_to_text(response.get(field_name))
        if value:
            parts.append(f"response.{field_name}: {value}")

    return "\n".join(parts)


def _provider_extension_security_text(response: dict[str, Any]) -> str:
    """Collect text from provider-defined extension channels.

    OpenAI-compatible implementations frequently add fields such as
    ``thoughts``, ``trace`` or nested vendor metadata.  A name-based allowlist
    alone is not a security boundary: an indirect instruction or credential can
    be placed in an unknown string field and still reach an SDK.  Standard
    protocol fields are already scanned by the dedicated helpers; this pass
    covers everything else with bounded recursion.
    """
    parts: list[str] = []
    total_chars = 0
    max_parts = 256
    max_chars = 32_000

    def collect(value: Any, path: str, depth: int = 0) -> None:
        nonlocal total_chars
        if depth > 12 or len(parts) >= max_parts or total_chars >= max_chars:
            return
        if isinstance(value, str):
            if not value:
                return
            bounded = value[: max_chars - total_chars]
            parts.append(f"{path}: {bounded}")
            total_chars += len(bounded)
            return
        if isinstance(value, dict):
            for key, item in value.items():
                collect(item, f"{path}.{key}", depth + 1)
            return
        if isinstance(value, list):
            for index, item in enumerate(value[:256]):
                collect(item, f"{path}[{index}]", depth + 1)

    standard_top = {
        "id",
        "object",
        "created",
        "model",
        "choices",
        "usage",
        "system_fingerprint",
        "service_tier",
    } | set(PROXY_PROVIDER_TOP_LEVEL_OUTPUT_FIELDS)
    for key, value in response.items():
        if key not in standard_top:
            collect(value, f"response.{key}")

    choices = response.get("choices")
    if isinstance(choices, list):
        for choice_index, choice in enumerate(choices[:PROXY_MAX_PROVIDER_CHOICES]):
            if not isinstance(choice, dict):
                continue
            for key, value in choice.items():
                if key not in PROXY_BLOCKED_CHOICE_FIELDS and key not in set(PROXY_PROVIDER_CHOICE_OUTPUT_FIELDS):
                    collect(value, f"choice[{choice_index}].{key}")
            message = choice.get("message")
            if isinstance(message, dict):
                standard_message = {
                    "role",
                    "content",
                    "tool_calls",
                    "function_call",
                    "name",
                    "tool_call_id",
                    "reasoning_content",
                    "reasoning",
                    "thinking",
                    "analysis",
                    "refusal",
                }
                for key, value in message.items():
                    if key not in standard_message:
                        collect(value, f"choice[{choice_index}].message.{key}")
    return "\n".join(parts)


def _security_excerpt(value: str, limit: int = PROXY_AUDIT_EXCERPT_CHARS) -> str:
    """Keep audit records bounded while preserving both ends of an input."""
    text = str(value or "")
    if len(text) <= limit:
        return text
    head = max(1, limit // 2)
    tail = max(1, limit - head)
    return f"{text[:head]}\n…[truncated]…\n{text[-tail:]}"


def _extract_prompt(messages: list[Any]) -> str:
    parts: list[str] = []
    for item in messages[-8:]:
        if not isinstance(item, dict):
            continue
        role = str(item.get("role") or "user")
        content = _content_to_text(item.get("content"))
        if content:
            parts.append(f"{role}: {content}")
    return "\n".join(parts)[-8000:] or "空请求。"


def _content_to_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        chunks = []
        for item in content:
            if isinstance(item, dict) and item.get("type") in {"text", "input_text"}:
                chunks.append(str(item.get("text", "")))
            elif isinstance(item, dict):
                # Non-text blocks (image/audio/file references) are still
                # caller-controlled input.  Keep their structured form in the
                # security view so a URL or data reference cannot disappear
                # from size checks and audit evidence.
                chunks.append(json.dumps(item, ensure_ascii=False, default=str, separators=(",", ":")))
        return "\n".join(chunk for chunk in chunks if chunk)
    if isinstance(content, dict):
        return json.dumps(content, ensure_ascii=False, default=str, separators=(",", ":"))
    return str(content or "")


def _safe_model_boundary_reason(stage: str) -> str:
    """Return a non-reflective reason safe to expose to a downstream Agent."""

    messages = {
        "request": "请求内容命中输入上下文安全策略；原文未发送给 Provider。",
        "tool-result": "工具结果命中不可信上下文策略；原文未回灌给 Provider。",
        "provider-output": "Provider 输出命中不可信上下文或输出安全策略；原文已隐藏。",
    }
    return messages.get(stage, "网关安全策略已阻断不可信内容；原文已隐藏。")


def _safe_tool_definition_findings(findings: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return a model-facing tool scan view without reflecting tool metadata.

    Tool names, descriptions and schema strings are caller/provider-controlled
    input.  The full finding is retained in the signed audit record, but the
    ``agent_supervisor`` extension is visible to the downstream Agent and must
    not become a second prompt-injection channel.  A stable name hash keeps the
    UI/evidence view correlatable without returning the original value.
    """

    safe_findings: list[dict[str, Any]] = []
    for finding in list(findings)[:64]:
        if not isinstance(finding, dict):
            continue
        raw_name = str(finding.get("name") or "")
        raw_signals = finding.get("signals")
        signals = (
            [str(signal)[:80] for signal in raw_signals[:16] if str(signal).strip()]
            if isinstance(raw_signals, list)
            else []
        )
        safe_findings.append(
            {
                "index": finding.get("index"),
                "name_hash": hashlib.sha256(raw_name.encode("utf-8")).hexdigest() if raw_name else "",
                "verdict": str(finding.get("verdict") or "unknown"),
                "signals": signals,
            }
        )
    return safe_findings


def _safe_protocol_identifier(value: Any, *, fallback: str = "", max_chars: int = 256) -> str:
    """Keep protocol identifiers useful without reflecting control text.

    Provider-generated IDs and function names are returned to the downstream
    Agent.  They are not executable by themselves, but control characters,
    delimiters, or unbounded values can turn a JSON metadata field into a
    prompt/rendering injection or a response-size attack.  Valid OpenAI/MCP
    identifiers use a deliberately small ASCII subset; the full raw value is
    still covered by the Provider response hash and local audit row.
    """

    candidate = str(value or "")
    if len(candidate) > max_chars or not PROXY_SAFE_IDENTIFIER_RE.fullmatch(candidate):
        return str(fallback or "")[:max_chars]
    return candidate


def _safe_metadata_path(value: Any) -> str:
    candidate = str(value or "")
    return candidate if PROXY_SAFE_METADATA_PATH_RE.fullmatch(candidate) else "arguments.<redacted>"


def _safe_metadata_key(value: Any) -> str:
    """Project a Provider-controlled field name before it enters response metadata.

    Standard-looking extension names remain readable for operators.  Names
    containing spaces, control text, non-ASCII instruction content, or an
    excessive length are represented only by a stable short hash.  The raw key
    remains available in the signed audit evidence, not in the Agent-visible
    protocol envelope.
    """

    candidate = str(value or "")
    if len(candidate) <= 120 and PROXY_SAFE_METADATA_KEY_RE.fullmatch(candidate):
        return candidate
    digest = hashlib.sha256(candidate.encode("utf-8", errors="replace")).hexdigest()[:16]
    return f"key_hash:{digest}"


def _safe_provider_failures(failures: Any) -> list[dict[str, str]]:
    """Project Provider failures into a model-facing, non-reflective shape."""

    if not isinstance(failures, list):
        return []
    safe: list[dict[str, str]] = []
    for item in failures[:16]:
        if not isinstance(item, dict):
            raw = str(item or "")
            safe.append(
                {
                    "provider": "unknown",
                    "model": "",
                    "error": "Provider 请求失败",
                    "error_hash": hashlib.sha256(raw.encode("utf-8")).hexdigest(),
                }
            )
            continue
        raw_error = str(item.get("error") or "")
        raw_provider = re.sub(r"[\x00-\x1f\x7f]", "", str(item.get("provider") or ""))[:120]
        raw_model = re.sub(r"[\x00-\x1f\x7f]", "", str(item.get("model") or ""))[:200]
        provider = (
            raw_provider
            if PROXY_SAFE_IDENTIFIER_RE.fullmatch(raw_provider)
            else "unknown"
        )
        model = _safe_protocol_identifier(raw_model, max_chars=PROXY_MAX_MODEL_CHARS)
        # The model adapter already emits stable categories.  Keep a fixed
        # fallback for patched/legacy adapters so an arbitrary HTTP body cannot
        # re-enter through a successful failover response.
        known_error = "Provider 请求失败"
        stable_errors = {
            "Provider 网络连接失败",
            "Provider 请求超时",
            "Provider 响应格式校验失败",
            "Provider 请求参数或响应校验失败",
            "Provider 响应超过网关大小上限",
            "Provider 请求失败",
        }
        if raw_error in stable_errors:
            known_error = raw_error
        elif raw_error.startswith("Provider HTTP 请求失败（状态 ") and raw_error.endswith("）"):
            status = raw_error.removeprefix("Provider HTTP 请求失败（状态 ").removesuffix("）")
            if status.isdigit() and 100 <= int(status) <= 599:
                known_error = f"Provider HTTP 请求失败（状态 {status}）"
        safe.append(
            {
                "provider": provider or "unknown",
                "model": model,
                "error": known_error,
                "error_hash": hashlib.sha256(raw_error.encode("utf-8")).hexdigest(),
                "provider_hash": hashlib.sha256(raw_provider.encode("utf-8")).hexdigest() if raw_provider else "",
                "model_hash": hashlib.sha256(raw_model.encode("utf-8")).hexdigest() if raw_model else "",
            }
        )
    return safe


def _safe_invalid_tool_calls(calls: Any) -> list[str]:
    """Hide Provider parse details while preserving correlation evidence."""

    if not isinstance(calls, list):
        return []
    return [
        f"provider-tool-call-invalid:{hashlib.sha256(str(item or '').encode('utf-8')).hexdigest()}"
        for item in calls[:64]
    ]


def _safe_tool_argument_findings(findings: Any) -> list[dict[str, Any]]:
    """Keep argument finding paths bounded and free of caller-controlled text."""

    if not isinstance(findings, list):
        return []
    safe: list[dict[str, Any]] = []
    for item in findings[:64]:
        if not isinstance(item, dict):
            continue
        safe.append(
            {
                "call_id": _safe_protocol_identifier(item.get("call_id")),
                "path": _safe_metadata_path(item.get("path")),
                "verdict": str(item.get("verdict") or "unknown")[:32],
                "signals": [str(signal)[:80] for signal in item.get("signals", [])[:16]]
                if isinstance(item.get("signals"), list)
                else [],
            }
        )
    return safe


def _safe_tool_decisions(decisions: Any) -> list[dict[str, Any]]:
    """Project Provider-derived decisions before exposing them to an Agent.

    ``audit_id`` and the hashes remain usable for receipt correlation.  Raw
    Provider names, IDs and policy explanations are bounded or represented by
    hashes; the detailed values stay in the signed audit record.
    """

    if not isinstance(decisions, list):
        return []
    safe: list[dict[str, Any]] = []
    for item in decisions[:PROXY_MAX_PROVIDER_TOOL_CALLS]:
        if not isinstance(item, dict):
            continue
        raw_external = str(item.get("external_tool") or "")
        raw_tool = str(item.get("tool") or "")
        raw_call_id = str(item.get("call_id") or "")
        raw_arguments_hash = str(item.get("arguments_hash") or "")
        decision = str(item.get("decision") or "未知")
        policy_id = _safe_protocol_identifier(item.get("policy_id"), fallback="tool-contract", max_chars=120)
        raw_risk = item.get("risk_score")
        if isinstance(raw_risk, (int, float)) and not isinstance(raw_risk, bool):
            bounded_risk = max(0, min(100, int(raw_risk)))
        else:
            bounded_risk = 0
        safe.append(
            {
                "choice_index": item.get("choice_index") if isinstance(item.get("choice_index"), int) else 0,
                "index": item.get("index") if isinstance(item.get("index"), int) else 0,
                "call_id": _safe_protocol_identifier(raw_call_id),
                "call_id_hash": hashlib.sha256(raw_call_id.encode("utf-8")).hexdigest() if raw_call_id else "",
                "external_tool": _safe_protocol_identifier(raw_external),
                "external_tool_hash": hashlib.sha256(raw_external.encode("utf-8")).hexdigest()
                if raw_external
                else "",
                "tool": _safe_protocol_identifier(raw_tool),
                "tool_hash": hashlib.sha256(raw_tool.encode("utf-8")).hexdigest() if raw_tool else "",
                "arguments_hash": raw_arguments_hash
                if re.fullmatch(r"[0-9a-fA-F]{64}", raw_arguments_hash)
                else hashlib.sha256(raw_arguments_hash.encode("utf-8")).hexdigest(),
                "decision": decision if decision in {"允许", "拒绝", "询问", "隔离"} else "拒绝",
                "policy_id": policy_id,
                "reason": "工具调用已由网关策略处置；详细原因仅保留在审计记录中。",
                "audit_id": _safe_protocol_identifier(item.get("audit_id"), max_chars=200),
                "risk_score": bounded_risk,
            }
        )
    return safe


def _normalize_provider_response_envelope(
    response: dict[str, Any],
    *,
    fallback_model: str,
    fallback_id: str,
) -> list[str]:
    """Normalize protocol metadata before it is returned to an Agent.

    Content and tool arguments remain detection inputs and are not rewritten by
    this helper.  Transport identifiers, choice indexes and valid tool-call
    envelopes are normalized so a compromised Provider cannot smuggle control
    characters or vendor-specific shapes through the OpenAI response contract.
    """

    normalized: list[str] = []
    raw_id = response.get("id")
    safe_id = _safe_protocol_identifier(raw_id, fallback=fallback_id, max_chars=256)
    if safe_id != str(raw_id or ""):
        normalized.append("response.id")
    response["id"] = safe_id
    if response.get("object") != "chat.completion":
        normalized.append("response.object")
    response["object"] = "chat.completion"
    raw_model = response.get("model")
    safe_model = re.sub(r"[\x00-\x1f\x7f]", "", str(fallback_model or raw_model or ""))[:200]
    if not safe_model:
        safe_model = "unknown-model"
    if safe_model != str(raw_model or ""):
        normalized.append("response.model")
    response["model"] = safe_model
    for field_name in ("system_fingerprint", "service_tier"):
        if field_name not in response:
            continue
        raw_value = response.get(field_name)
        safe_value = _safe_protocol_identifier(raw_value, max_chars=256)
        if safe_value != str(raw_value or ""):
            normalized.append(f"response.{field_name}")
        response[field_name] = safe_value
    created = response.get("created")
    if isinstance(created, bool) or not isinstance(created, int) or created < 0 or created > 4_102_444_800:
        response["created"] = int(time.time())
        normalized.append("response.created")
    choices = response.get("choices")
    if not isinstance(choices, list):
        return normalized
    for choice_index, raw_choice in enumerate(choices[:PROXY_MAX_PROVIDER_CHOICES]):
        if not isinstance(raw_choice, dict):
            continue
        if raw_choice.get("index") != choice_index:
            normalized.append(f"response.choices[{choice_index}].index")
        raw_choice["index"] = choice_index
        finish = raw_choice.get("finish_reason")
        finish_text = "" if finish is None else str(finish)
        if finish_text not in PROXY_ALLOWED_FINISH_REASONS:
            raw_choice["finish_reason"] = "stop"
            normalized.append(f"response.choices[{choice_index}].finish_reason")
        message = raw_choice.get("message")
        if not isinstance(message, dict):
            continue
        if "name" in message:
            safe_name = _safe_protocol_identifier(message.get("name"), max_chars=PROXY_MAX_MESSAGE_NAME_CHARS)
            if safe_name != str(message.get("name") or ""):
                normalized.append(f"response.choices[{choice_index}].message.name")
            message["name"] = safe_name
        raw_calls = message.get("tool_calls")
        if isinstance(raw_calls, list):
            for call_index, raw_call in enumerate(raw_calls[:PROXY_MAX_PROVIDER_TOOL_CALLS]):
                parsed, issue = _parse_transparent_tool_call(raw_call)
                if issue or parsed is None:
                    continue
                canonical = {
                    "id": parsed["id"],
                    "type": "function",
                    "function": {
                        "name": parsed["external_tool"],
                        "arguments": json.dumps(
                            parsed["arguments"], ensure_ascii=False, separators=(",", ":")
                        ),
                    },
                }
                if raw_call != canonical:
                    normalized.append(f"response.choices[{choice_index}].message.tool_calls[{call_index}]")
                    raw_calls[call_index] = canonical
        legacy_call = message.get("function_call")
        if isinstance(legacy_call, dict):
            synthetic = {
                "id": f"legacy-{fallback_id}-{choice_index}",
                "type": "function",
                "function": legacy_call,
            }
            parsed, issue = _parse_transparent_tool_call(synthetic)
            if not issue and parsed is not None:
                canonical_legacy = {
                    "name": parsed["external_tool"],
                    "arguments": json.dumps(parsed["arguments"], ensure_ascii=False, separators=(",", ":")),
                }
                if legacy_call != canonical_legacy:
                    normalized.append(f"response.choices[{choice_index}].message.function_call")
                    message["function_call"] = canonical_legacy
    return normalized


def _safe_tool_definition_reason() -> str:
    """Keep blocked tool-definition explanations fixed at the Agent boundary."""

    return "工具定义命中投毒扫描策略；原始工具名称、描述和参数仅保留在审计记录中。"


def _safe_tool_allowlist_reason() -> str:
    """Keep capability authorization failures fixed at the Agent boundary."""

    return "工具定义包含当前 Agent 未登记的能力；原始工具名称和权限细节仅保留在审计记录中。"


def _safe_tool_boundary_reason(policy_id: str) -> str:
    """Summarize a controlled tool call without reflecting its arguments."""

    policy = str(policy_id or "tool-contract").strip() or "tool-contract"
    return f"工具调用命中 `{policy}` 策略；原始参数仅保留在审计证据中。"


def _final_proxy_content(filtered_content: str, supervisor: dict[str, Any], output_blocked: bool) -> str:
    if output_blocked or supervisor["decision"] in CONTROL_DECISIONS:
        return (
            "[智垒] 已拦截或降级本次模型输出。\n"
            f"处置：{supervisor['decision']}；策略：{supervisor['policy_id']}；"
            f"原因：{supervisor['reason']}\n"
            "可继续进行授权本地受控环境评测，但不会返回系统提示词、token、flag、危险命令或第三方攻击步骤。"
        )
    return filtered_content or "模型没有返回可展示内容。"


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.lower() in {"1", "true", "yes", "on"}
