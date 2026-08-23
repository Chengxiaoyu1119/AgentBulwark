from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from apps.api.agent_supervisor.commands.cli import _cli_secret


class CliTransportTests(unittest.TestCase):
    def test_cli_secret_reads_environment_without_returning_argv_value(self) -> None:
        with patch.dict("os.environ", {"TEST_GATEWAY_TOKEN": "secret-from-env"}, clear=False):
            self.assertEqual(_cli_secret("", "TEST_GATEWAY_TOKEN"), "secret-from-env")
        self.assertEqual(_cli_secret("direct-token", "TEST_GATEWAY_TOKEN"), "direct-token")

    def test_cli_secret_rejects_invalid_environment_name(self) -> None:
        with self.assertRaises(SystemExit):
            _cli_secret("", "TOKEN-NAME")

    def test_windows_style_json_argument_reaches_python_as_one_argv_value(self) -> None:
        """The Node launcher must not let a shell strip JSON quoting.

        The endpoint is deliberately unreachable: this test only exercises
        argument transport.  A valid JSON argument reaches the Python CLI and
        therefore produces a partial network probe, rather than the parser
        error seen when cmd.exe removes the inner quotes on Windows.
        """
        node = shutil.which("node")
        if not node:
            self.skipTest("Node.js is required for the CLI transport regression")

        repo_root = Path(__file__).resolve().parents[3]
        with tempfile.TemporaryDirectory(prefix="agent-supervisor-cli-") as output_dir:
            result = subprocess.run(
                [
                    node,
                    "scripts/agent-supervisor-cli.mjs",
                    "mcp-probe",
                    "--url",
                    "http://127.0.0.1:9/api/mcp",
                    "--arguments",
                    json.dumps({"path": "x"}, ensure_ascii=False, separators=(",", ":")),
                    "--timeout",
                    "0.1",
                    "--output",
                    output_dir,
                ],
                cwd=repo_root,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                env={**os.environ, "AGENT_SUPERVISOR_PYTHON": sys.executable},
                timeout=30,
                check=False,
            )

        combined = f"{result.stdout}\n{result.stderr}"
        self.assertNotIn("MCP 工具参数 JSON 无效", combined)
        self.assertEqual(result.returncode, 0, combined)
        self.assertIn('"evidence_verdict": "partial"', result.stdout)


if __name__ == "__main__":
    unittest.main()
