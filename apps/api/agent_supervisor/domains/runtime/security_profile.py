"""Runtime security profiles for local fixtures and deployed Agent gateways."""

from __future__ import annotations

import os
from ipaddress import ip_address

SECURITY_PROFILE_ENV = "AGENT_SUPERVISOR_SECURITY_PROFILE"


def security_profile() -> str:
    """Return the normalized deployment profile without guessing from headers."""

    value = (os.getenv(SECURITY_PROFILE_ENV) or "").strip().lower()
    if value in {"production", "prod"}:
        return "production"
    if value in {"local", "dev", "development", "test"}:
        return "local"
    # CLI readiness runs outside the server lifespan. Mirror the bind-address
    # default so its policy snapshot matches the process that would serve it.
    host = (os.getenv("AGENT_SUPERVISOR_API_HOST") or "127.0.0.1").strip().lower()
    if host == "localhost":
        return "local"
    try:
        return "local" if ip_address(host).is_loopback else "production"
    except ValueError:
        return "production" if host else "local"


def production_security_profile() -> bool:
    return security_profile() == "production"
