import json
import os
import shutil
import socket
import subprocess
import tempfile
import unittest
from pathlib import Path


class LocalLauncherTest(unittest.TestCase):
    def test_python_server_exit_code_is_propagated_through_powershell_and_npm(self) -> None:
        if os.name != "nt":
            self.skipTest("The launcher is Windows-only")
        powershell = shutil.which("powershell") or shutil.which("pwsh")
        npm = shutil.which("npm")
        if powershell is None or npm is None:
            self.skipTest("PowerShell and npm are required for the Windows launcher regression")

        repo_root = Path(__file__).resolve().parents[3]
        source = (repo_root / "scripts" / "启动智安哨.ps1").read_text(encoding="utf-8").lstrip("\ufeff")
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        source = source.replace('AGENT_SUPERVISOR_API_PORT = "8012"', f'AGENT_SUPERVISOR_API_PORT = "{port}"')
        source = source.replace("http://127.0.0.1:8012", f"http://127.0.0.1:{port}")
        source = "\n".join(
            (
                "function Start-Job {",
                "  param([object[]]$ArgumentList, [scriptblock]$ScriptBlock)",
                "  return $null",
                "}",
                source,
            )
        )

        with tempfile.TemporaryDirectory(prefix="local-launcher-exit-") as temporary:
            temporary_root = Path(temporary)
            scripts_dir = temporary_root / "scripts"
            scripts_dir.mkdir()
            launcher_path = scripts_dir / "launcher.ps1"
            launcher_path.write_text(source, encoding="utf-8-sig")
            bin_dir = temporary_root / "bin"
            bin_dir.mkdir()
            (bin_dir / "npm.cmd").write_text("@exit /b 0\n", encoding="ascii")
            (bin_dir / "python.cmd").write_text("@exit /b 7\n", encoding="ascii")
            (temporary_root / "package.json").write_text(
                json.dumps(
                    {
                        "scripts": {
                            "start:local": f'"{powershell}" -NoProfile -ExecutionPolicy Bypass -File scripts/launcher.ps1',
                        }
                    }
                ),
                encoding="utf-8",
            )
            environment = os.environ.copy()
            environment["PATH"] = f"{bin_dir};{environment['PATH']}"
            environment["AGENT_SUPERVISOR_PYTHON"] = "python"
            npm_result = subprocess.run(
                [npm, "run", "start:local"],
                cwd=temporary_root,
                env=environment,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
                check=False,
            )

        self.assertEqual(npm_result.returncode, 7, f"stdout={npm_result.stdout}\nstderr={npm_result.stderr}")
