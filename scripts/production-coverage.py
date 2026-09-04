from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PRODUCTION_OMIT = (
    "apps/api/agent_supervisor/adapters/integrations/*",
    "apps/api/agent_supervisor/commands/cli.py",
    "apps/api/agent_supervisor/domains/attacks/*",
    "apps/api/agent_supervisor/domains/evaluations/*",
    "apps/api/agent_supervisor/domains/reports/*",
    "apps/api/agent_supervisor/domains/runtime/gateway_comparison.py",
    "apps/api/agent_supervisor/domains/runtime/runtime_evaluation.py",
    "apps/api/agent_supervisor/routers/evaluations.py",
    "apps/api/agent_supervisor/routers/integrations.py",
    "apps/api/agent_supervisor/routers/scenarios.py",
    "apps/api/agent_supervisor/services/package_*.py",
    "apps/api/agent_supervisor/**/__init__.py",
)
MINIMUM_COVERAGE = 75


def run_coverage(*arguments: str, environment: dict[str, str]) -> int:
    completed = subprocess.run(
        [sys.executable, "-m", "coverage", *arguments],
        cwd=ROOT,
        env=environment,
        check=False,
    )
    return completed.returncode


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="agent-supervisor-production-coverage-") as temporary:
        environment = os.environ.copy()
        environment["COVERAGE_FILE"] = str(Path(temporary) / ".coverage")
        rcfile = Path(temporary) / "coverage.ini"
        rcfile.write_text("[run]\nbranch = true\n", encoding="utf-8")
        environment["COVERAGE_RCFILE"] = str(rcfile)
        test_status = run_coverage(
            "run",
            "--source=apps/api/agent_supervisor",
            "-m",
            "unittest",
            "discover",
            "-s",
            "apps/api/tests",
            "-t",
            ".",
            "-p",
            "test_*.py",
            environment=environment,
        )
        if test_status:
            return test_status
        omit = ",".join(PRODUCTION_OMIT)
        return run_coverage(
            "report",
            f"--omit={omit}",
            f"--fail-under={MINIMUM_COVERAGE}",
            "--show-missing",
            environment=environment,
        )


if __name__ == "__main__":
    raise SystemExit(main())
