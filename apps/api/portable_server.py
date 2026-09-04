from __future__ import annotations

import os
import threading
import webbrowser

import uvicorn

from apps.api.agent_supervisor.domains.runtime.server_security import (
    configure_server_security,
    load_environment_file,
)


def main() -> None:
    load_environment_file()
    host = os.getenv("AGENT_SUPERVISOR_API_HOST", "127.0.0.1")
    configure_server_security(host)
    # Import the ASGI application only after the environment has been loaded.
    # ``agent_supervisor.paths`` resolves runtime directories at import time;
    # importing ``main`` at module scope would therefore ignore a runtime path
    # supplied by the portable launcher's .env file.
    from apps.api.agent_supervisor.main import app

    port = int(os.getenv("AGENT_SUPERVISOR_API_PORT", "8012"))
    url = f"http://{host}:{port}"
    open_browser = os.getenv("AGENT_SUPERVISOR_OPEN_BROWSER", "true").lower() not in {"0", "false", "no"}
    if open_browser:
        threading.Timer(2.0, lambda: webbrowser.open(url)).start()
    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()
