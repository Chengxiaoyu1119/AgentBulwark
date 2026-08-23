from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from apps.api.agent_supervisor.domains.runtime.tools import (
    SandboxPaths,
    execute_tool,
    init_sandbox,
)
from apps.api.agent_supervisor.paths import FIXTURE_WORKSPACE_DIR


class RegisteredProbeIntegrityTests(unittest.TestCase):
    def _paths(self, root: Path, fixtures: Path = FIXTURE_WORKSPACE_DIR) -> SandboxPaths:
        return SandboxPaths(
            workspace=root / "workspace",
            outbox=root / "outbox",
            memory=root / "memory",
            fixtures=fixtures,
        )

    def test_workspace_write_cannot_replace_registered_probe_source(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._paths(root)
            init_sandbox(paths)
            overwritten = paths.workspace / "scripts" / "tool_hijack_probe.py"
            overwritten.write_text(
                "from pathlib import Path\n"
                "(Path.cwd() / 'reports' / 'workspace-overwrite-marker').write_text('pwned')\n",
                encoding="utf-8",
            )

            result = execute_tool(
                {
                    "tool": "code.run",
                    "arguments": {
                        "command": 'python scripts/tool_hijack_probe.py --payload "integrity-test"'
                    },
                },
                "允许",
                sandbox=paths,
            )

            self.assertTrue(result["executed"])
            self.assertEqual(result["trusted_script"], "scripts/tool_hijack_probe.py")
            self.assertEqual(result["script_sha256"], "af0d15f2ad6460ce5f1a52367895811d65f1b8d14fd7e7469708df658ddb618b")
            evidence = json.loads(
                (paths.workspace / "reports" / "tool-hijack-probe.json").read_text(encoding="utf-8")
            )
            self.assertFalse((paths.workspace / "reports" / "workspace-overwrite-marker").exists())
            self.assertEqual(evidence["real_shell_executed"], False)

    def test_tampered_fixture_is_rejected_before_process_start(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            fixtures = root / "fixtures"
            shutil.copytree(FIXTURE_WORKSPACE_DIR, fixtures)
            script = fixtures / "scripts" / "tool_hijack_probe.py"
            script.write_text(script.read_text(encoding="utf-8") + "\n# tampered\n", encoding="utf-8")
            paths = self._paths(root, fixtures)

            result = execute_tool(
                {
                    "tool": "code.run",
                    "arguments": {"command": 'python scripts/tool_hijack_probe.py --payload "tampered"'},
                },
                "允许",
                sandbox=paths,
            )

            self.assertFalse(result["executed"])
            self.assertEqual(result["execution_target"], "none")
            self.assertIn("完整性校验失败", result["output"])


if __name__ == "__main__":
    unittest.main()
