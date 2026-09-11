"""Shared bootstrap for every supported backend test runner.

The application resolves its SQLite/runtime paths when ``agent_supervisor`` is
first imported.  Test discovery must therefore select an isolated runtime
before importing any application module.  A process-unique directory also
prevents a previous or concurrent test process from leaking execution claims,
receipts, policy overrides, or audit rows into the current run.
"""

from __future__ import annotations

import atexit
import json
import os
import shutil
import tempfile
from pathlib import Path

_TEST_RUNTIME_DIR = Path(
    tempfile.mkdtemp(prefix=f"agent-supervisor-test-runtime-{os.getpid()}-")
).resolve()
os.environ["AGENT_SUPERVISOR_RUNTIME_DIR"] = str(_TEST_RUNTIME_DIR)
os.environ.setdefault("AGENT_SUPERVISOR_LABS_ENABLED", "true")
# Unit tests exercise lower-level protocol compatibility directly. Keep that
# fixture mode explicit now that clean installations default to fail-closed
# Agent registration boundaries.
(_TEST_RUNTIME_DIR / "policy_settings.json").write_text(
    json.dumps(
        {
            "require_agent_capability_registration": False,
            "require_agent_model_registration": False,
            "require_agent_context_registration": False,
        }
    ),
    encoding="utf-8",
)
atexit.register(shutil.rmtree, _TEST_RUNTIME_DIR, ignore_errors=True)

def _initialize_runtime_database() -> None:
    # Import only after the test runtime environment is fixed because paths are
    # resolved at module import time.
    from apps.api.agent_supervisor.storage.database import init_db

    init_db()


# Most tests call the ASGI app without opening TestClient as a lifespan context.
# Initialise the new database here instead of accidentally relying on a schema
# left by an earlier local server or test run.
_initialize_runtime_database()
