from __future__ import annotations

import os
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent
API_ROOT = PACKAGE_DIR.parent
APPS_ROOT = API_ROOT.parent
REPO_ROOT = APPS_ROOT.parent

# Operational state has one canonical root. Tests may override it with
# ``AGENT_SUPERVISOR_RUNTIME_DIR``; production never falls back to a shared runtime
# or experiment directory.
RUNTIME_ROOT_DIR = API_ROOT / "runtime"
RUNTIME_DIR = Path(
    os.getenv("AGENT_SUPERVISOR_RUNTIME_DIR", str(RUNTIME_ROOT_DIR / "operational"))
).resolve()

WORKSPACE_DIR = RUNTIME_DIR / "workspace"
OUTBOX_DIR = RUNTIME_DIR / "outbox"
MEMORY_DIR = RUNTIME_DIR / "memory"
