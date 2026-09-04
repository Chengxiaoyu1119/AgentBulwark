from apps.api.agent_supervisor.domains.runtime import agent_credentials


def mcp_access_capabilities(role: str, authenticated_agent_id: str | None) -> dict[str, bool]:
    """Return the effective MCP discovery and execution permissions.

    The HTTP enforcement boundary and operator console consume this same
    projection, so the UI neither advertises actions the router rejects nor
    hides an explicitly enabled local compatibility path.
    """

    executor_identity_ready = bool(authenticated_agent_id) or agent_credentials.shared_executor_compatibility_enabled()
    can_use_mcp = role in {"analyst", "admin"} or (role == "executor" and executor_identity_ready)
    can_execute_mcp_tools = role == "admin" or (role == "executor" and executor_identity_ready)
    return {
        "can_use_mcp": can_use_mcp,
        "can_execute_mcp_tools": can_execute_mcp_tools,
    }
