from __future__ import annotations

import argparse
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from apps.api.agent_supervisor.commands.cli import cmd_readiness
from apps.api.agent_supervisor.domains.reports.readiness import _deployment_security_for_readiness


class ReadinessCliTests(unittest.TestCase):
    def test_write_accepts_concrete_output_file_without_treating_it_as_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            generated_json = root / "AI Agent安全网关就绪检查.json"
            generated_md = root / "AI Agent安全网关就绪检查.md"
            generated_json.write_text('{"overall_status":"has-p0-proof-gap"}', encoding="utf-8")
            generated_md.write_text("# AI Agent 安全网关就绪检查", encoding="utf-8")
            requested = root / "custom-readiness.json"
            args = argparse.Namespace(output=str(requested), format="json", write=True)

            with patch(
                "apps.api.agent_supervisor.commands.cli.write_competition_readiness_report",
                return_value={
                    "json_path": str(generated_json),
                    "markdown_path": str(generated_md),
                },
            ) as writer:
                cmd_readiness(args)

            writer.assert_called_once()
            self.assertEqual(Path(writer.call_args.kwargs["output_root"]), root)
            self.assertEqual(requested.read_text(encoding="utf-8"), generated_json.read_text(encoding="utf-8"))

    def test_deployment_security_prefers_process_environment_over_env_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / ".env").write_text(
                "AGENT_SUPERVISOR_AUTH_DISABLED=false\n"
                "AGENT_SUPERVISOR_API_TOKEN=file-token\n",
                encoding="utf-8",
            )
            (root / ".env.example").write_text("AGENT_SUPERVISOR_AUTH_DISABLED=false\n", encoding="utf-8")
            with (
                patch("apps.api.agent_supervisor.domains.reports.readiness.REPO_ROOT", root),
                patch.dict(
                    "os.environ",
                    {
                        "AGENT_SUPERVISOR_AUTH_DISABLED": "false",
                        "AGENT_SUPERVISOR_API_TOKEN": "runtime-token",
                        "AGENT_SUPERVISOR_AUDIT_HMAC_KEY": "runtime-hmac",
                        "AGENT_SUPERVISOR_API_HOST": "0.0.0.0",
                    },
                    clear=False,
                ),
            ):
                result = _deployment_security_for_readiness()

            self.assertTrue(result["auth_enabled"])
            self.assertTrue(result["api_token_configured"])
            self.assertTrue(result["hmac_configured"])
            self.assertEqual(result["host"], "0.0.0.0")
            self.assertIn("process environment", result["source"])

    def test_deployment_security_accepts_bound_agent_tokens_without_role_token(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / ".env").write_text(
                "AGENT_SUPERVISOR_AUTH_DISABLED=false\n"
                'AGENT_SUPERVISOR_AGENT_TOKENS_JSON={"agent-1":"bound-token"}\n'
                "AGENT_SUPERVISOR_AUDIT_HMAC_KEY=local-hmac\n",
                encoding="utf-8",
            )
            (root / ".env.example").write_text("AGENT_SUPERVISOR_AUTH_DISABLED=false\n", encoding="utf-8")
            with (
                patch("apps.api.agent_supervisor.domains.reports.readiness.REPO_ROOT", root),
                patch.dict("os.environ", {}, clear=True),
            ):
                result = _deployment_security_for_readiness()

            self.assertTrue(result["auth_enabled"])
            self.assertTrue(result["api_token_configured"])
            self.assertTrue(result["agent_tokens_configured"])
            self.assertTrue(result["hmac_configured"])


if __name__ == "__main__":
    unittest.main()
