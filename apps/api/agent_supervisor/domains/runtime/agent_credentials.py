import json
import os
from hmac import compare_digest
from typing import Any

from fastapi import HTTPException

AGENT_TOKENS_ENV = "AGENT_SUPERVISOR_AGENT_TOKENS_JSON"
ALLOW_SHARED_EXECUTOR_TOKEN_ENV = "AGENT_SUPERVISOR_ALLOW_SHARED_EXECUTOR_TOKEN"
MAX_AGENT_TOKEN_BINDINGS = 1000
ROLE_ORDER = {"observer": 1, "executor": 1, "analyst": 2, "admin": 3}
ROLE_LOOKUP_ORDER = tuple(ROLE_ORDER)


def env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def supplied_token(authorization: str | None, header_token: str | None) -> str:
    bearer_token = ""
    if authorization and authorization.lower().startswith("bearer "):
        bearer_token = authorization[7:].strip()
    return bearer_token or (header_token or "").strip()


def role_token(role: str) -> str:
    return (os.getenv(f"AGENT_SUPERVISOR_API_TOKEN_{role.upper()}") or "").strip()


def get_agent_token_bindings() -> dict[str, str]:
    raw = (os.getenv(AGENT_TOKENS_ENV) or "").strip()
    if not raw:
        return {}

    try:
        parsed = json.loads(raw, object_pairs_hook=_unique_json_object)
    except (json.JSONDecodeError, ValueError) as exc:
        raise HTTPException(status_code=503, detail=f"{AGENT_TOKENS_ENV} 配置格式错误：{exc}") from exc
    if not isinstance(parsed, dict):
        raise HTTPException(status_code=503, detail=f"{AGENT_TOKENS_ENV} 必须是 agent_id 到 Token 的 JSON 对象")
    if len(parsed) > MAX_AGENT_TOKEN_BINDINGS:
        raise HTTPException(status_code=503, detail=f"{AGENT_TOKENS_ENV} 最多配置 {MAX_AGENT_TOKEN_BINDINGS} 个 Agent")

    bindings: dict[str, str] = {}
    token_owners: dict[str, str] = {}
    reserved_tokens = {
        token
        for token in [(os.getenv("AGENT_SUPERVISOR_API_TOKEN") or "").strip(), *(role_token(role) for role in ROLE_ORDER)]
        if token
    }
    for raw_agent_id, raw_token in parsed.items():
        if not isinstance(raw_agent_id, str) or not isinstance(raw_token, str):
            raise HTTPException(status_code=503, detail=f"{AGENT_TOKENS_ENV} 的 Agent ID 和 Token 必须都是字符串")
        agent_id = raw_agent_id.strip()
        token = raw_token.strip()
        if not agent_id or len(agent_id) > 160 or agent_id != raw_agent_id:
            raise HTTPException(status_code=503, detail=f"{AGENT_TOKENS_ENV} 包含无效 Agent ID")
        if not token:
            raise HTTPException(status_code=503, detail=f"{AGENT_TOKENS_ENV} 中 {agent_id} 的 Token 为空")
        if token in reserved_tokens:
            raise HTTPException(status_code=503, detail=f"{AGENT_TOKENS_ENV} 中 {agent_id} 的 Token 与共享或角色 Token 重复")
        previous_owner = token_owners.get(token)
        if previous_owner:
            raise HTTPException(status_code=503, detail=f"{AGENT_TOKENS_ENV} 中 {previous_owner} 与 {agent_id} 使用了相同 Token")
        bindings[agent_id] = token
        token_owners[token] = agent_id
    return bindings


def agent_id_for_token(token: str) -> str | None:
    if not token:
        return None
    for agent_id, expected_token in get_agent_token_bindings().items():
        if compare_digest(token, expected_token):
            return agent_id
    return None


def require_agent_identity(agent_id: str, current_role: str, authenticated_agent_id: str | None) -> None:
    if current_role == "admin":
        return
    if current_role != "executor":
        raise HTTPException(status_code=403, detail="当前凭证无权代表 Agent 执行生产操作")
    if authenticated_agent_id:
        if not compare_digest(agent_id, authenticated_agent_id):
            raise HTTPException(status_code=403, detail="请求中的 agent_id 与服务端凭证绑定身份不一致")
        return
    if env_bool(ALLOW_SHARED_EXECUTOR_TOKEN_ENV):
        return
    raise HTTPException(status_code=403, detail="生产 Agent 必须使用服务端绑定到 agent_id 的独立凭证")


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"存在重复 Agent ID：{key}")
        result[key] = value
    return result
