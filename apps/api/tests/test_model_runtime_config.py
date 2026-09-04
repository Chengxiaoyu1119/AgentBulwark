import concurrent.futures
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from apps.api.agent_supervisor.adapters.models import model_runtime_config
from apps.api.agent_supervisor.storage.json_store import exclusive_file_lock


class ModelRuntimeConfigTests(unittest.TestCase):
    def test_crashed_lock_initializer_is_recovered_by_next_process(self) -> None:
        repo_root = Path(__file__).resolve().parents[3]
        worker = """
import os
import sys
from pathlib import Path

from apps.api.agent_supervisor.storage.json_store import _lock_handle

resource = Path(sys.argv[1])
marker = resource.parent / f".{resource.name}.lock.init.lock"
fd = os.open(marker, os.O_CREAT | os.O_EXCL | os.O_RDWR)
os.write(fd, b"0")
os.lseek(fd, 0, os.SEEK_SET)
handle = os.fdopen(fd, "r+b", buffering=0)
_lock_handle(handle)
os._exit(73)
        """
        with tempfile.TemporaryDirectory(prefix="json-lock-initializer-crash-") as temp_dir:
            root = Path(temp_dir)
            resource = root / "state.json"
            environment = os.environ.copy()
            environment["PYTHONPATH"] = os.pathsep.join(
                [str(repo_root), environment.get("PYTHONPATH", "")]
            ).rstrip(os.pathsep)
            crashed = subprocess.run(
                [sys.executable, "-X", "utf8", "-c", worker, str(resource)],
                cwd=repo_root,
                env=environment,
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
            self.assertEqual(crashed.returncode, 73, crashed.stderr)
            marker = root / ".state.json.lock.init.lock"
            self.assertTrue(marker.exists())

            with exclusive_file_lock(resource, timeout_seconds=1):
                self.assertTrue((root / ".state.json.lock").exists())

            self.assertFalse(marker.exists())

    def test_read_projects_every_field_from_one_file_snapshot(self) -> None:
        snapshot = {
            "real_api_enabled": False,
            "profiles": {
                "global": {"provider_priority": ["zhipu"]},
                "optimizer": {"provider_priority": ["deepseek"]},
                "target": {
                    "provider_priority": ["openai-compatible"],
                    "model_overrides": {"openai-compatible": "snapshot-model"},
                },
            },
        }
        newer_version = {
            "real_api_enabled": True,
            "profiles": {
                "global": {"provider_priority": ["deepseek"]},
                "optimizer": {"provider_priority": ["zhipu"]},
                "target": {"provider_priority": ["deepseek"]},
            },
        }

        with (
            patch.object(
                model_runtime_config,
                "_load_raw_config",
                side_effect=[snapshot, newer_version, newer_version, newer_version, newer_version],
            ) as load,
            patch.dict(os.environ, {"MODEL_REAL_API_ENABLED": "true"}, clear=False),
        ):
            config = model_runtime_config.get_model_runtime_config()

        self.assertEqual(load.call_count, 1)
        self.assertFalse(config["real_api_enabled"])
        self.assertEqual(config["real_api_enabled_source"], "runtime")
        self.assertEqual(config["profiles"]["global"]["provider_priority"], ["zhipu"])
        self.assertEqual(config["profiles"]["optimizer"]["provider_priority"], ["deepseek"])
        self.assertEqual(config["profiles"]["target"]["provider_priority"], ["openai-compatible"])
        self.assertEqual(
            config["profiles"]["target"]["model_overrides"],
            {"openai-compatible": "snapshot-model"},
        )

    def test_corrupt_runtime_file_falls_back_to_environment(self) -> None:
        with tempfile.TemporaryDirectory(prefix="model-runtime-config-") as temp_dir:
            config_path = Path(temp_dir) / "model_runtime_config.json"
            config_path.write_bytes(b"\xff\xfe\x00invalid-json")

            with (
                patch.object(model_runtime_config, "MODEL_RUNTIME_CONFIG_PATH", config_path),
                patch.dict(os.environ, {"MODEL_REAL_API_ENABLED": "true"}, clear=False),
            ):
                config = model_runtime_config.get_model_runtime_config()

        self.assertTrue(config["real_api_enabled"])
        self.assertEqual(config["real_api_enabled_source"], "env")
        self.assertEqual(
            config["profiles"]["global"]["provider_priority"],
            ["openai-compatible", "deepseek", "zhipu"],
        )

    def test_unknown_profile_update_cannot_mutate_global_profile(self) -> None:
        with tempfile.TemporaryDirectory(prefix="model-runtime-config-") as temp_dir:
            config_path = Path(temp_dir) / "model_runtime_config.json"
            config_path.write_text(
                json.dumps(
                    {
                        "profiles": {
                            "global": {
                                "provider_priority": ["openai-compatible", "deepseek"],
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )

            with patch.object(model_runtime_config, "MODEL_RUNTIME_CONFIG_PATH", config_path):
                result = model_runtime_config.update_model_runtime_config(
                    {"profiles": {"targte": {"provider_priority": ["zhipu"]}}}
                )

        self.assertEqual(
            result["profiles"]["global"]["provider_priority"],
            ["openai-compatible", "deepseek"],
        )

    def test_update_merges_priorities_and_removes_blank_model_override(self) -> None:
        with tempfile.TemporaryDirectory(prefix="model-runtime-config-") as temp_dir:
            config_path = Path(temp_dir) / "model_runtime_config.json"
            config_path.write_text(
                json.dumps(
                    {
                        "real_api_enabled": False,
                        "profiles": {
                            "target": {
                                "provider_priority": ["deepseek", "zhipu"],
                                "model_overrides": {
                                    "deepseek": "old-deepseek-model",
                                    "zhipu": "old-zhipu-model",
                                },
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )

            with patch.object(model_runtime_config, "MODEL_RUNTIME_CONFIG_PATH", config_path):
                result = model_runtime_config.update_model_runtime_config(
                    {
                        "real_api_enabled": True,
                        "profiles": {
                            "target": {
                                "provider_priority": ["zhipu", "zhipu", "openai-compatible"],
                                "model_overrides": {
                                    "deepseek": "  ",
                                    "zhipu": "new\r\nzhipu-model",
                                },
                            }
                        },
                    }
                )
                persisted = json.loads(config_path.read_text(encoding="utf-8"))

        self.assertTrue(result["real_api_enabled"])
        self.assertEqual(
            result["profiles"]["target"]["provider_priority"],
            ["zhipu", "openai-compatible"],
        )
        self.assertEqual(result["profiles"]["target"]["model_overrides"], {"zhipu": "newzhipu-model"})
        self.assertEqual(persisted["profiles"]["target"]["model_overrides"], {"zhipu": "newzhipu-model"})
        self.assertEqual(list(config_path.parent.glob("*.tmp")), [])

    def test_concurrent_updates_serialize_the_read_modify_write_section(self) -> None:
        active_writers = 0
        max_active_writers = 0
        state_lock = threading.Lock()

        def fake_save(_: dict[str, object]) -> None:
            nonlocal active_writers, max_active_writers
            with state_lock:
                active_writers += 1
                max_active_writers = max(max_active_writers, active_writers)
            time.sleep(0.02)
            with state_lock:
                active_writers -= 1

        with tempfile.TemporaryDirectory(prefix="model-runtime-config-thread-lock-") as temp_dir:
            config_path = Path(temp_dir) / "model_runtime_config.json"
            with (
                patch.object(model_runtime_config, "MODEL_RUNTIME_CONFIG_PATH", config_path),
                patch.object(model_runtime_config, "_load_raw_config", return_value={}),
                patch.object(model_runtime_config, "_save_raw_config", side_effect=fake_save),
                concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor,
            ):
                futures = [
                    executor.submit(
                        model_runtime_config.update_model_runtime_config,
                        {"profiles": {"target": {"model_overrides": {"zhipu": f"model-{index}"}}}},
                    )
                    for index in range(4)
                ]
                [future.result() for future in futures]

        self.assertEqual(max_active_writers, 1)

    def test_updates_from_two_processes_preserve_both_model_overrides(self) -> None:
        repo_root = Path(__file__).resolve().parents[3]
        worker = """
import sys
import time
from pathlib import Path
from unittest.mock import patch

from apps.api.agent_supervisor.adapters.models import model_runtime_config

config_path, provider, model, ready_path, start_path = map(Path, sys.argv[1:])
original_save = model_runtime_config._save_raw_config

def delayed_save(config):
    time.sleep(0.3)
    original_save(config)

ready_path.write_text("ready", encoding="utf-8")
deadline = time.monotonic() + 15
while not start_path.exists():
    if time.monotonic() >= deadline:
        raise RuntimeError("test start barrier timed out")
    time.sleep(0.01)
with (
    patch.object(model_runtime_config, "MODEL_RUNTIME_CONFIG_PATH", config_path),
    patch.object(model_runtime_config, "_save_raw_config", side_effect=delayed_save),
):
    model_runtime_config.update_model_runtime_config(
        {"profiles": {"target": {"model_overrides": {provider.name: model.name}}}}
    )
"""
        with tempfile.TemporaryDirectory(prefix="model-runtime-config-process-lock-") as temp_dir:
            root = Path(temp_dir)
            config_path = root / "model_runtime_config.json"
            start_path = root / "start"
            environment = os.environ.copy()
            environment["PYTHONPATH"] = os.pathsep.join(
                [str(repo_root), environment.get("PYTHONPATH", "")]
            ).rstrip(os.pathsep)
            cases = [
                ("deepseek", "deepseek-process-model"),
                ("zhipu", "zhipu-process-model"),
            ]
            processes = [
                subprocess.Popen(
                    [
                        sys.executable,
                        "-c",
                        worker,
                        str(config_path),
                        provider,
                        model,
                        str(root / f"ready-{provider}"),
                        str(start_path),
                    ],
                    cwd=repo_root,
                    env=environment,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                for provider, model in cases
            ]
            outcomes: list[tuple[str, str]] = []
            try:
                deadline = time.monotonic() + 15
                while len(list(root.glob("ready-*"))) < len(processes) and time.monotonic() < deadline:
                    time.sleep(0.02)
                self.assertEqual(len(list(root.glob("ready-*"))), len(processes))
                start_path.write_text("start", encoding="utf-8")
                outcomes = [process.communicate(timeout=20) for process in processes]
            finally:
                for process in processes:
                    if process.poll() is None:
                        process.kill()
                        process.wait(timeout=5)

            for process, (stdout, stderr) in zip(processes, outcomes, strict=True):
                self.assertEqual(process.returncode, 0, f"stdout={stdout}\nstderr={stderr}")
            persisted = json.loads(config_path.read_text(encoding="utf-8"))

        self.assertEqual(
            persisted["profiles"]["target"]["model_overrides"],
            {provider: model for provider, model in cases},
        )

    def test_invalid_runtime_shape_uses_defaults_without_leaking_host_path(self) -> None:
        with tempfile.TemporaryDirectory(prefix="model-runtime-config-") as temp_dir:
            config_path = Path(temp_dir) / "model_runtime_config.json"
            config_path.write_text("[]", encoding="utf-8")

            with (
                patch.object(model_runtime_config, "MODEL_RUNTIME_CONFIG_PATH", config_path),
                patch.dict(os.environ, {"MODEL_REAL_API_ENABLED": "false"}, clear=False),
            ):
                config = model_runtime_config.get_model_runtime_config()

        self.assertFalse(config["real_api_enabled"])
        self.assertEqual(config["real_api_enabled_source"], "env")
        self.assertEqual(config["config_path"], "runtime/model_runtime_config.json")
        self.assertNotIn(temp_dir, config["config_path"])


if __name__ == "__main__":
    unittest.main()
