from __future__ import annotations

import os
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent
API_ROOT = PACKAGE_DIR.parent
APPS_ROOT = API_ROOT.parent
REPO_ROOT = APPS_ROOT.parent

ROOT_DOCS_DIR = REPO_ROOT / "docs"
SANDBOX_DIR = API_ROOT / "sandbox"
SANDBOX_FIXTURES_DIR = SANDBOX_DIR / "fixtures"
SANDBOX_EXAMPLES_DIR = SANDBOX_DIR / "examples"
SANDBOX_RUNTIME_DIR = SANDBOX_DIR / "runtime"
SANDBOX_REPORTS_DIR = SANDBOX_DIR / "reports"

# Product traffic and experiments must never share their default persistence
# root. The previous single ``apps/api/runtime`` database accumulated test,
# fixture and operator rows in one 346MB file, making the console impossible to
# interpret as live evidence. Explicit overrides remain authoritative for
# tests, containers and dedicated lab processes.
RUNTIME_ROOT_DIR = API_ROOT / "runtime"
RUNTIME_DIR = Path(
    os.getenv("AGENT_SUPERVISOR_RUNTIME_DIR", str(RUNTIME_ROOT_DIR / "operational"))
).resolve()
LAB_RUNTIME_DIR = Path(
    os.getenv("AGENT_SUPERVISOR_LAB_RUNTIME_DIR", str(SANDBOX_RUNTIME_DIR / "lab-data"))
).resolve()

FIXTURE_WORKSPACE_DIR = SANDBOX_FIXTURES_DIR / "workspace"
WORKSPACE_DIR = SANDBOX_RUNTIME_DIR / "workspace"
OUTBOX_DIR = SANDBOX_RUNTIME_DIR / "outbox"
MEMORY_DIR = SANDBOX_RUNTIME_DIR / "memory"
