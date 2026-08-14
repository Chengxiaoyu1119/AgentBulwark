from __future__ import annotations

import os
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent
API_ROOT = PACKAGE_DIR.parent
APPS_ROOT = API_ROOT.parent
REPO_ROOT = APPS_ROOT.parent

ROOT_DOCS_DIR = REPO_ROOT / "docs"
RUNTIME_DIR = Path(os.getenv("AGENT_SUPERVISOR_RUNTIME_DIR", str(API_ROOT / "runtime"))).resolve()
SANDBOX_DIR = API_ROOT / "sandbox"
SANDBOX_FIXTURES_DIR = SANDBOX_DIR / "fixtures"
SANDBOX_EXAMPLES_DIR = SANDBOX_DIR / "examples"
SANDBOX_RUNTIME_DIR = SANDBOX_DIR / "runtime"
SANDBOX_REPORTS_DIR = SANDBOX_DIR / "reports"

FIXTURE_WORKSPACE_DIR = SANDBOX_FIXTURES_DIR / "workspace"
WORKSPACE_DIR = SANDBOX_RUNTIME_DIR / "workspace"
OUTBOX_DIR = SANDBOX_RUNTIME_DIR / "outbox"
MEMORY_DIR = SANDBOX_RUNTIME_DIR / "memory"
