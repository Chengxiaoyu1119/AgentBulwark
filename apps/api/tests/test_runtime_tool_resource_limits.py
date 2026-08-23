from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from apps.api.agent_supervisor.domains.runtime.tools import (
    MAX_FILE_READ_BYTES,
    MAX_MEMORY_FILE_BYTES,
    MAX_MEMORY_ITEMS,
    SandboxPaths,
    execute_tool,
    init_sandbox,
)


class RuntimeToolResourceLimitTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(prefix="runtime-tool-limits-")
        root = Path(self.temp_dir.name)
        self.paths = SandboxPaths(
            workspace=root / "workspace",
            outbox=root / "outbox",
            memory=root / "memory",
            fixtures=root / "fixtures",
            target_state=root / "target.json",
        )
        init_sandbox(self.paths)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_file_read_limits_bytes_before_decoding(self) -> None:
        target = self.paths.workspace / "public" / "large.txt"
        target.write_bytes(b"A" * (MAX_FILE_READ_BYTES + 1024))

        result = execute_tool(
            {"tool": "file.read", "arguments": {"path": "public/large.txt"}},
            "允许",
            sandbox=self.paths,
        )

        self.assertTrue(result["executed"])
        self.assertTrue(result["resource_limited"])
        self.assertEqual(result["read_limit_bytes"], MAX_FILE_READ_BYTES)
        self.assertLessEqual(len(result["output"].encode("utf-8")), 800)

    def test_memory_read_rejects_oversized_store_without_loading_json(self) -> None:
        memory_file = self.paths.memory / "memory.json"
        memory_file.write_bytes(b"[" + b" " * MAX_MEMORY_FILE_BYTES + b"]")

        result = execute_tool(
            {"tool": "memory.read", "arguments": {"query": "all"}},
            "允许",
            sandbox=self.paths,
        )

        self.assertFalse(result["executed"])
        self.assertTrue(result["resource_limited"])

    def test_wsl_fallback_is_opt_in_when_docker_is_missing(self) -> None:
        with (
            patch.dict(os.environ, {"AGENT_SUPERVISOR_COMMAND_ALLOW_WSL_FALLBACK": "false"}, clear=False),
            patch("apps.api.agent_supervisor.domains.runtime.tools.shutil.which", return_value=None),
            patch("apps.api.agent_supervisor.domains.runtime.tools._run_wsl_isolated_command") as run_wsl,
        ):
            result = execute_tool(
                {"tool": "code.run", "arguments": {"command": "python -c 'print(1)'"}},
                "允许",
                sandbox=self.paths,
            )

        self.assertFalse(result["executed"])
        self.assertIn("WSL 降级执行默认关闭", result["output"])
        run_wsl.assert_not_called()

    def test_memory_write_rejects_unbounded_item_growth(self) -> None:
        memory_file = self.paths.memory / "memory.json"
        memory_file.write_text(
            json.dumps([{"id": str(index), "content": "ok", "status": "active"} for index in range(MAX_MEMORY_ITEMS)]),
            encoding="utf-8",
        )

        result = execute_tool(
            {"tool": "memory.write", "arguments": {"content": "new item"}},
            "允许",
            sandbox=self.paths,
        )

        self.assertFalse(result["executed"])
        self.assertTrue(result["resource_limited"])


if __name__ == "__main__":
    unittest.main()
