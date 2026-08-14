from __future__ import annotations

import os

import uvicorn

from apps.api.agent_supervisor.domains.runtime.server_security import configure_server_security


def main() -> None:
    host = os.getenv("AGENT_SUPERVISOR_API_HOST", "127.0.0.1")
    configure_server_security(host)
    port = int(os.getenv("AGENT_SUPERVISOR_API_PORT", "8012"))
    uvicorn.run("apps.api.agent_supervisor.main:app", host=host, port=port)


if __name__ == "__main__":
    main()
