from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from apps.api.agent_supervisor.domains.attacks.target_lab import target_lab_snapshot
from apps.api.agent_supervisor.domains.runtime.tools import SandboxPaths, default_sandbox_paths, execute_tool, init_sandbox
from apps.api.agent_supervisor.paths import FIXTURE_WORKSPACE_DIR


class AgentSandboxIsolationTests(unittest.TestCase):
    def test_identity_bound_default_sandboxes_do_not_share_mutable_roots(self) -> None:
        first = default_sandbox_paths("agent-a")
        second = default_sandbox_paths("agent-b")

        self.assertNotEqual(first.workspace, second.workspace)
        self.assertNotEqual(first.outbox, second.outbox)
        self.assertNotEqual(first.memory, second.memory)
        self.assertNotEqual(first.target_state, second.target_state)
        self.assertIn("agents", first.workspace.parts)
        self.assertNotIn("agent-a", str(first.workspace))
        self.assertFalse(first.seed_fixtures)

    def test_identity_bound_sandbox_does_not_copy_regression_secrets(self) -> None:
        with tempfile.TemporaryDirectory(prefix="agent-sandbox-empty-") as temporary:
            # Patch the runtime root through the returned immutable path so the
            # assertion exercises the same init path as a server-owned Agent.
            paths = SandboxPaths(
                workspace=Path(temporary) / "workspace",
                outbox=Path(temporary) / "outbox",
                memory=Path(temporary) / "memory",
                fixtures=FIXTURE_WORKSPACE_DIR,
                target_state=Path(temporary) / "target-state.json",
                seed_fixtures=False,
            )
            init_sandbox(paths)

            self.assertFalse((paths.workspace / "confidential" / "challenge-seeds.json").exists())
            self.assertFalse((paths.workspace / "confidential" / "competition-teams.csv").exists())
            self.assertEqual((paths.memory / "memory.json").read_text(encoding="utf-8"), "[]")

    def test_file_and_target_state_effects_do_not_cross_agents(self) -> None:
        with tempfile.TemporaryDirectory(prefix="agent-sandbox-isolation-") as temporary:
            root = Path(temporary)
            first = SandboxPaths(
                workspace=root / "agent-a" / "workspace",
                outbox=root / "agent-a" / "outbox",
                memory=root / "agent-a" / "memory",
                fixtures=FIXTURE_WORKSPACE_DIR,
                target_state=root / "agent-a" / "target-state.json",
            )
            second = SandboxPaths(
                workspace=root / "agent-b" / "workspace",
                outbox=root / "agent-b" / "outbox",
                memory=root / "agent-b" / "memory",
                fixtures=FIXTURE_WORKSPACE_DIR,
                target_state=root / "agent-b" / "target-state.json",
            )
            init_sandbox(first)
            init_sandbox(second)

            write_result = execute_tool(
                {
                    "tool": "file.write",
                    "arguments": {"path": "public/agent-a-note.txt", "content": "agent-a-only"},
                },
                "允许",
                sandbox=first,
            )
            self.assertTrue(write_result["executed"])

            read_result = execute_tool(
                {"tool": "file.read", "arguments": {"path": "public/agent-a-note.txt"}},
                "允许",
                sandbox=second,
            )
            self.assertTrue(read_result["executed"])
            self.assertIn("不存在", str(read_result["output"]))

            execute_tool(
                {
                    "tool": "api.call",
                    "arguments": {"endpoint": "/competition/review-notes/create", "body": "agent-a-note"},
                },
                "允许",
                sandbox=first,
            )
            self.assertEqual(target_lab_snapshot(first.target_state)["review_note_count"], 1)
            self.assertEqual(target_lab_snapshot(second.target_state)["review_note_count"], 0)


if __name__ == "__main__":
    unittest.main()
