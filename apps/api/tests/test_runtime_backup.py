from __future__ import annotations

import concurrent.futures
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from contextlib import closing
from pathlib import Path
from unittest import mock
from zipfile import ZIP_DEFLATED, ZipFile

from apps.api.agent_supervisor.commands import runtime_backup as runtime_backup_command
from apps.api.agent_supervisor.domains.runtime import runtime_backup
from apps.api.agent_supervisor.domains.runtime.runtime_backup import (
    ACTIVE_RUNTIME_DIR,
    RuntimeBackupError,
    clear_runtime_active,
    create_runtime_backup,
    mark_runtime_active,
    restore_runtime_backup,
    verify_runtime_backup,
)
from apps.api.agent_supervisor.storage import data as policy_data
from apps.api.agent_supervisor.storage import database


class RuntimeBackupTests(unittest.TestCase):
    signing_key = "runtime-backup-test-key-000000000000000000000000000000"

    def _runtime(self, root: Path, *, marker: str = "original") -> Path:
        runtime = root / "runtime"
        runtime.mkdir(parents=True)
        database = runtime / "agent_supervisor.sqlite3"
        with closing(sqlite3.connect(database)) as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("CREATE TABLE evidence (id INTEGER PRIMARY KEY, marker TEXT NOT NULL)")
            connection.execute("INSERT INTO evidence (marker) VALUES (?)", (marker,))
            connection.commit()
        (runtime / "policy_settings.json").write_text(
            json.dumps({"marker": marker}, ensure_ascii=False), encoding="utf-8"
        )
        agent_file = runtime / "agents" / "hashed-agent" / "workspace" / "public" / "marker.txt"
        agent_file.parent.mkdir(parents=True)
        agent_file.write_text(marker, encoding="utf-8")
        return runtime

    def test_signed_backup_captures_database_json_and_agent_files(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime-backup-test-") as temporary:
            root = Path(temporary)
            runtime = self._runtime(root)
            archive = root / "backup.zip"

            created = create_runtime_backup(
                archive,
                source_root=runtime,
                signing_key=self.signing_key,
                signing_key_id="test-key-v1",
                require_signature=True,
            )
            verified = verify_runtime_backup(archive, signing_key=self.signing_key, require_signature=True)

            self.assertEqual(created["file_count"], 3)
            self.assertTrue(verified["valid"])
            self.assertTrue(verified["authenticated"])
            self.assertEqual(verified["database_integrity"], "ok")
            with ZipFile(archive) as package:
                names = set(package.namelist())
            self.assertIn("data/agent_supervisor.sqlite3", names)
            self.assertIn("data/policy_settings.json", names)
            self.assertIn("data/agents/hashed-agent/workspace/public/marker.txt", names)
            self.assertNotIn("data/agent_supervisor.sqlite3-wal", names)

    def test_backup_can_snapshot_an_active_runtime_without_waiting_for_service_lock(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime-backup-online-") as temporary:
            root = Path(temporary)
            runtime = self._runtime(root / "source")
            archive = root / "backup.zip"
            marker = mark_runtime_active(runtime)
            try:
                result = create_runtime_backup(archive, source_root=runtime)
            finally:
                clear_runtime_active(marker)

            self.assertTrue(archive.is_file())
            self.assertGreater(result["file_count"], 0)
            self.assertTrue(verify_runtime_backup(archive)["valid"])

    def test_malformed_manifest_types_are_reported_as_runtime_backup_errors(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime-backup-manifest-") as temporary:
            root = Path(temporary)
            runtime = self._runtime(root / "source")
            good = root / "good.zip"
            create_runtime_backup(good, source_root=runtime)
            with ZipFile(good) as source:
                manifest = json.loads(source.read("manifest.json"))
                entries = {info.filename: source.read(info) for info in source.infolist() if info.filename != "manifest.json"}

            mutations = (
                lambda value: value.__setitem__("file_count", "bad"),
                lambda value: value.pop("total_bytes"),
                lambda value: value.__setitem__("database_path", {"path": "agent_supervisor.sqlite3"}),
                lambda value: value["integrity"].__setitem__("authenticated", "true"),
                lambda value: value["integrity"].__setitem__("signature", {"value": "x"}),
                lambda value: value["files"][0].__setitem__("sha256", "z" * 64),
            )
            for index, mutate in enumerate(mutations):
                with self.subTest(index=index):
                    malformed = root / f"malformed-{index}.zip"
                    current = json.loads(json.dumps(manifest))
                    mutate(current)
                    with ZipFile(malformed, "w", compression=ZIP_DEFLATED) as target:
                        target.writestr("manifest.json", json.dumps(current).encode("utf-8"))
                        for name, payload in entries.items():
                            target.writestr(name, payload)
                    with self.assertRaises(RuntimeBackupError):
                        verify_runtime_backup(malformed)

    def test_wrong_key_and_modified_file_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime-backup-tamper-") as temporary:
            root = Path(temporary)
            runtime = self._runtime(root)
            archive = root / "backup.zip"
            create_runtime_backup(archive, source_root=runtime, signing_key=self.signing_key)

            with self.assertRaisesRegex(RuntimeBackupError, "HMAC"):
                verify_runtime_backup(archive, signing_key="wrong-key", require_signature=True)

            tampered = root / "tampered.zip"
            with ZipFile(archive) as source, ZipFile(tampered, "w", compression=ZIP_DEFLATED) as target:
                for info in source.infolist():
                    payload = source.read(info)
                    if info.filename.endswith("marker.txt"):
                        payload = b"tampered"
                    target.writestr(info.filename, payload)
            with self.assertRaisesRegex(RuntimeBackupError, "Hash"):
                verify_runtime_backup(tampered, signing_key=self.signing_key, require_signature=True)

    def test_path_traversal_archive_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime-backup-traversal-") as temporary:
            archive = Path(temporary) / "traversal.zip"
            with ZipFile(archive, "w") as package:
                package.writestr("manifest.json", "{}")
                package.writestr("data/../outside.txt", "bad")
            with self.assertRaisesRegex(RuntimeBackupError, "越界路径"):
                verify_runtime_backup(archive)

    def test_restore_replaces_runtime_and_keeps_rollback(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime-backup-restore-") as temporary:
            root = Path(temporary)
            source = self._runtime(root / "source", marker="snapshot")
            archive = root / "backup.zip"
            create_runtime_backup(archive, source_root=source, signing_key=self.signing_key)

            target = self._runtime(root / "target", marker="current")
            result = restore_runtime_backup(
                archive,
                target_root=target,
                signing_key=self.signing_key,
                offline_confirmed=True,
            )

            with closing(sqlite3.connect(target / "agent_supervisor.sqlite3")) as connection:
                marker = connection.execute("SELECT marker FROM evidence").fetchone()[0]
            self.assertEqual(marker, "snapshot")
            self.assertEqual(
                (target / "agents" / "hashed-agent" / "workspace" / "public" / "marker.txt").read_text(encoding="utf-8"),
                "snapshot",
            )
            rollback = Path(result["rollback"])
            self.assertTrue(rollback.is_dir())
            with closing(sqlite3.connect(rollback / "agent_supervisor.sqlite3")) as connection:
                previous = connection.execute("SELECT marker FROM evidence").fetchone()[0]
            self.assertEqual(previous, "current")

    def test_backup_policy_update_and_restore_keep_one_transaction_snapshot(self) -> None:
        """A backup cannot combine pre-update SQLite with post-update JSON."""
        with tempfile.TemporaryDirectory(prefix="runtime-backup-policy-race-") as temporary:
            root = Path(temporary)
            runtime = self._runtime(root / "source", marker="before")
            archive = root / "backup.zip"
            restored = root / "restored"
            settings_path = runtime / "policy_settings.json"
            outbox_path = runtime / "policy_audit_outbox.json"
            database_path = runtime / "agent_supervisor.sqlite3"
            database_snapshot_done = threading.Event()
            updater_started = threading.Event()
            original_snapshot_database = runtime_backup._snapshot_database

            def delayed_after_database_snapshot(source: Path, destination: Path) -> None:
                original_snapshot_database(source, destination)
                database_snapshot_done.set()
                self.assertTrue(updater_started.wait(timeout=5))
                # Give an uncoordinated writer enough time to publish JSON,
                # audit SQLite, and remove its outbox entry before file copy.
                time.sleep(0.3)

            def update_settings() -> None:
                self.assertTrue(database_snapshot_done.wait(timeout=5))
                updater_started.set()
                policy_data.update_policy_settings({"anomaly_review_threshold": 63})

            with (
                mock.patch.object(database, "RUNTIME_DIR", runtime),
                mock.patch.object(database, "DB_PATH", database_path),
                mock.patch.object(policy_data, "RUNTIME_DIR", runtime),
                mock.patch.object(policy_data, "POLICY_OVERRIDES_PATH", runtime / "policy_overrides.json"),
                mock.patch.object(policy_data, "POLICY_SETTINGS_PATH", settings_path),
                mock.patch.object(policy_data, "POLICY_AUDIT_OUTBOX_PATH", outbox_path),
                mock.patch.object(runtime_backup, "_snapshot_database", side_effect=delayed_after_database_snapshot),
            ):
                database.init_db()
                policy_data._invalidate_settings_cache()
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                    update = executor.submit(update_settings)
                    create_runtime_backup(archive, source_root=runtime, signing_key=self.signing_key)
                    update.result(timeout=10)

            restore_runtime_backup(
                archive,
                target_root=restored,
                signing_key=self.signing_key,
                offline_confirmed=True,
                keep_rollback=False,
            )
            restored_settings = json.loads((restored / "policy_settings.json").read_text(encoding="utf-8"))
            with closing(sqlite3.connect(restored / "agent_supervisor.sqlite3")) as connection:
                audit_count = connection.execute("SELECT COUNT(*) FROM policy_versions").fetchone()[0]

            self.assertEqual(restored_settings, {"marker": "before"})
            self.assertEqual(audit_count, 0)
            self.assertFalse((restored / "policy_audit_outbox.json").exists())
            self.assertEqual(
                json.loads(settings_path.read_text(encoding="utf-8"))["anomaly_review_threshold"],
                63,
            )

    def test_restore_rolls_back_original_runtime_when_replacement_fails(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime-backup-rollback-") as temporary:
            root = Path(temporary)
            source = self._runtime(root / "source", marker="snapshot")
            archive = root / "backup.zip"
            create_runtime_backup(archive, source_root=source, signing_key=self.signing_key)
            target = self._runtime(root / "target", marker="current")
            real_replace = os.replace

            def fail_on_restored_entry(source_path: str | os.PathLike[str], destination_path: str | os.PathLike[str]) -> None:
                source_value = Path(source_path)
                if any(part.startswith(".restore-stage-") for part in source_value.parts):
                    raise OSError("injected restore replacement failure")
                real_replace(source_path, destination_path)

            with mock.patch(
                "apps.api.agent_supervisor.domains.runtime.runtime_backup.os.replace",
                side_effect=fail_on_restored_entry,
            ):
                with self.assertRaisesRegex(OSError, "injected restore replacement failure"):
                    restore_runtime_backup(
                        archive,
                        target_root=target,
                        signing_key=self.signing_key,
                        offline_confirmed=True,
                    )

            with closing(sqlite3.connect(target / "agent_supervisor.sqlite3")) as connection:
                marker = connection.execute("SELECT marker FROM evidence").fetchone()[0]
            self.assertEqual(marker, "current")
            self.assertEqual(
                (target / "agents" / "hashed-agent" / "workspace" / "public" / "marker.txt").read_text(
                    encoding="utf-8"
                ),
                "current",
            )

    def test_restore_refuses_active_runtime_and_missing_confirmation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime-backup-active-") as temporary:
            root = Path(temporary)
            source = self._runtime(root / "source", marker="snapshot")
            target = self._runtime(root / "target", marker="current")
            archive = root / "backup.zip"
            create_runtime_backup(archive, source_root=source, signing_key=self.signing_key)

            with self.assertRaisesRegex(RuntimeBackupError, "显式确认"):
                restore_runtime_backup(archive, target_root=target, signing_key=self.signing_key)

            marker = mark_runtime_active(target)
            try:
                with self.assertRaisesRegex(RuntimeBackupError, str(os.getpid())):
                    restore_runtime_backup(
                        archive,
                        target_root=target,
                        signing_key=self.signing_key,
                        offline_confirmed=True,
                    )
            finally:
                # Release the Windows file handle before TemporaryDirectory
                # removes the runtime tree. unittest cleanups run only after
                # this context manager has already attempted its cleanup.
                clear_runtime_active(marker)

    @unittest.skipUnless(os.name == "nt", "Windows process-query regression")
    def test_windows_pid_probe_does_not_terminate_checked_process(self) -> None:
        source = (
            "import os; "
            "from apps.api.agent_supervisor.domains.runtime.runtime_backup import _pid_is_alive; "
            "assert _pid_is_alive(os.getpid()); "
            "print('survived')"
        )
        completed = subprocess.run(
            [sys.executable, "-X", "utf8", "-c", source],
            cwd=Path(__file__).resolve().parents[3],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.strip(), "survived")

    def test_cli_restore_uses_security_profile_signature_policy(self) -> None:
        cases = [
            (False, [], False),
            (True, [], True),
            (True, ["--allow-unsigned"], False),
        ]
        for production, extra_arguments, expected in cases:
            with self.subTest(production=production, extra_arguments=extra_arguments):
                with (
                    mock.patch.object(runtime_backup_command, "load_environment_file"),
                    mock.patch.object(
                        runtime_backup_command,
                        "production_security_profile",
                        return_value=production,
                    ),
                    mock.patch.object(
                        runtime_backup_command,
                        "restore_runtime_backup",
                        return_value={"restored": True},
                    ) as restore,
                    mock.patch.object(
                        sys,
                        "argv",
                        [
                            "runtime-backup",
                            "restore",
                            "--input",
                            "runtime-backup.zip",
                            "--confirm-offline-restore",
                            *extra_arguments,
                        ],
                    ),
                    mock.patch("builtins.print"),
                ):
                    runtime_backup_command.main()

                self.assertIs(restore.call_args.kwargs["require_signature"], expected)

    def test_backup_must_live_outside_runtime_directory(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime-backup-location-") as temporary:
            runtime = self._runtime(Path(temporary))
            with self.assertRaisesRegex(RuntimeBackupError, "运行目录之外"):
                create_runtime_backup(runtime / "backups" / "backup.zip", source_root=runtime)

    def test_invalid_operations_do_not_create_runtime_directories(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime-backup-no-side-effect-") as temporary:
            root = Path(temporary)
            missing_source = root / "missing-source"
            with self.assertRaisesRegex(RuntimeBackupError, "运行目录不存在"):
                create_runtime_backup(root / "backup.zip", source_root=missing_source)
            self.assertFalse(missing_source.exists())

            source = self._runtime(root / "source")
            archive = root / "valid.zip"
            create_runtime_backup(archive, source_root=source)
            missing_target = root / "missing-target"
            with self.assertRaisesRegex(RuntimeBackupError, "显式确认"):
                restore_runtime_backup(archive, target_root=missing_target, require_signature=False)
            self.assertFalse(missing_target.exists())

    def test_active_marker_cleanup_removes_empty_marker_directory(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime-backup-marker-") as temporary:
            runtime = Path(temporary)
            marker = mark_runtime_active(runtime)
            self.assertTrue(marker.exists())
            clear_runtime_active(marker)
            self.assertFalse((runtime / ACTIVE_RUNTIME_DIR).exists())


if __name__ == "__main__":
    unittest.main()
