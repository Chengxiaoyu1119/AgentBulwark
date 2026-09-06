from __future__ import annotations

import json
import math
import os
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import closing
from pathlib import Path
from typing import Any
from unittest.mock import patch

from apps.api.agent_supervisor.storage import database


class CompetitionEvidenceRunStorageTests(unittest.TestCase):
    def test_multiple_processes_can_initialize_and_upgrade_one_database(self) -> None:
        repo_root = Path(__file__).resolve().parents[3]
        worker = """
import sys
import time
from pathlib import Path

from apps.api.agent_supervisor.storage import database

ready_path, start_path = map(Path, sys.argv[1:])
ready_path.write_text("ready", encoding="utf-8")
deadline = time.monotonic() + 20
while not start_path.exists():
    if time.monotonic() >= deadline:
        raise RuntimeError("database init start barrier timed out")
    time.sleep(0.01)
database.init_db()
"""
        with tempfile.TemporaryDirectory(prefix="database-multiprocess-init-") as temp_dir:
            runtime_dir = Path(temp_dir)
            database_path = runtime_dir / "agent_supervisor.sqlite3"
            with closing(sqlite3.connect(database_path)) as connection:
                connection.execute(
                    """
                    CREATE TABLE policy_versions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        policy_id TEXT NOT NULL,
                        operator TEXT NOT NULL,
                        comment TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        before_payload TEXT NOT NULL,
                        after_payload TEXT NOT NULL
                    )
                    """
                )

            environment = os.environ.copy()
            environment["AGENT_SUPERVISOR_RUNTIME_DIR"] = str(runtime_dir)
            environment["PYTHONPATH"] = os.pathsep.join(
                [str(repo_root), environment.get("PYTHONPATH", "")]
            ).rstrip(os.pathsep)
            start_path = runtime_dir / "start"
            processes = [
                subprocess.Popen(
                    [
                        sys.executable,
                        "-X",
                        "utf8",
                        "-c",
                        worker,
                        str(runtime_dir / f"ready-{index}"),
                        str(start_path),
                    ],
                    cwd=repo_root,
                    env=environment,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                for index in range(16)
            ]
            outcomes: list[tuple[str, str]] = []
            try:
                deadline = time.monotonic() + 20
                while len(list(runtime_dir.glob("ready-*"))) < len(processes) and time.monotonic() < deadline:
                    time.sleep(0.02)
                self.assertEqual(len(list(runtime_dir.glob("ready-*"))), len(processes))
                start_path.write_text("start", encoding="utf-8")
                outcomes = [process.communicate(timeout=30) for process in processes]
            finally:
                for process in processes:
                    if process.poll() is None:
                        process.kill()
                        process.wait(timeout=5)

            for process, (stdout, stderr) in zip(processes, outcomes, strict=True):
                self.assertEqual(process.returncode, 0, f"stdout={stdout}\nstderr={stderr}")

            with closing(sqlite3.connect(database_path)) as connection:
                columns = {row[1] for row in connection.execute("PRAGMA table_info(policy_versions)")}
                integrity = connection.execute("PRAGMA integrity_check").fetchone()

        self.assertIn("operation_id", columns)
        self.assertEqual(integrity, ("ok",))

    def test_latest_audit_logs_loads_exact_receipts_outside_recent_event_window(self) -> None:
        """A displayed audit must not lose its receipt behind unrelated traffic."""
        with tempfile.TemporaryDirectory(prefix="database-exact-receipts-") as temp_dir:
            runtime_dir = Path(temp_dir)
            with (
                patch.object(database, "RUNTIME_DIR", runtime_dir),
                patch.object(database, "DB_PATH", runtime_dir / "receipts.sqlite3"),
            ):
                database.init_db()
                audit_payload = {
                    "id": "old-audit",
                    "execution_receipt_expected": True,
                }
                with database.get_connection() as conn:
                    conn.execute(
                        """
                        INSERT INTO audit_logs (id, run_id, tool, decision, risk_level, reason, payload)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            "old-audit",
                            "run-1",
                            "file.read",
                            "允许",
                            "low",
                            "fixture",
                            json.dumps(audit_payload),
                        ),
                    )
                    conn.execute(
                        """
                        INSERT INTO runtime_events (event_type, created_at, payload)
                        VALUES (?, ?, ?)
                        """,
                        (
                            "execution-receipt",
                            "2026-08-25T00:00:00+00:00",
                            json.dumps(
                                {
                                    "audit_id": "old-audit",
                                    "receipt_id": "old-receipt",
                                    "status": "completed",
                                    "execution_target": "local-runtime",
                                }
                            ),
                        ),
                    )
                    conn.executemany(
                        """
                        INSERT INTO runtime_events (event_type, created_at, payload)
                        VALUES (?, ?, ?)
                        """,
                        [
                            (
                                "execution-receipt",
                                f"2026-08-25T00:01:{index:02d}+00:00",
                                json.dumps(
                                    {
                                        "audit_id": f"new-audit-{index}",
                                        "receipt_id": f"new-receipt-{index}",
                                        "status": "completed",
                                        "execution_target": "local-runtime",
                                    }
                                ),
                            )
                            for index in range(501)
                        ],
                    )

                audit = database.latest_audit_logs(1)[0]

        self.assertEqual(audit["id"], "old-audit")
        self.assertEqual(audit["execution_status"], "completed")
        self.assertEqual(audit["execution_receipt"]["receipt_id"], "old-receipt")

    def test_gateway_audit_identity_filter_is_applied_before_limit(self) -> None:
        """A noisy Agent must not evict another Agent's scoped Trace window."""
        with tempfile.TemporaryDirectory(prefix="database-gateway-agent-window-") as temp_dir:
            runtime_dir = Path(temp_dir)
            with (
                patch.object(database, "RUNTIME_DIR", runtime_dir),
                patch.object(database, "DB_PATH", runtime_dir / "gateway-agent-window.sqlite3"),
            ):
                database.init_db()

                def payload(agent_id: str, request_id: str) -> str:
                    return json.dumps(
                        {
                            "id": f"audit-{request_id}",
                            "source_app": "openai-compatible-proxy",
                            "agent_id": agent_id,
                            "stage_context": {
                                "request_id": request_id,
                                "session_id": f"session-{agent_id}",
                            },
                        }
                    )

                rows = [
                    ("audit-agent-a", "run-a", "", "允许", "low", "fixture", payload("agent-a", "request-a")),
                    *[
                        (
                            f"audit-agent-b-{index}",
                            "run-b",
                            "",
                            "允许",
                            "low",
                            "fixture",
                            payload("agent-b", f"request-b-{index}"),
                        )
                        for index in range(3)
                    ],
                ]
                with database.get_connection() as conn:
                    conn.executemany(
                        """
                        INSERT INTO audit_logs (id, run_id, tool, decision, risk_level, reason, payload)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        rows,
                    )

                scoped = database.latest_gateway_audit_logs(2, agent_id="agent-a")

        self.assertEqual([item["agent_id"] for item in scoped], ["agent-a"])
        self.assertEqual(scoped[0]["stage_context"]["request_id"], "request-a")

    def test_storage_rejects_non_finite_json_without_partial_writes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="database-strict-json-") as temp_dir:
            runtime_dir = Path(temp_dir)
            with (
                patch.object(database, "RUNTIME_DIR", runtime_dir),
                patch.object(database, "DB_PATH", runtime_dir / "strict.sqlite3"),
            ):
                database.init_db()
                result: dict[str, Any] = {
                    "run_id": "non-finite-run",
                    "scenario": {"id": "STRICT-JSON"},
                    "guard_enabled": True,
                    "attack_success": False,
                    "metrics": {
                        "blocked_count": 0,
                        "asked_count": 0,
                        "isolated_count": 0,
                        "detection_latency_ms": 1,
                    },
                    "created_at": "2026-08-25T00:00:00+00:00",
                    "audit_logs": [
                        {
                            "id": "non-finite-audit",
                            "run_id": "non-finite-run",
                            "tool": "file.read",
                            "decision": "允许",
                            "risk_level": "low",
                            "reason": "fixture",
                            "invalid": math.nan,
                        }
                    ],
                    "alerts": [],
                }

                with self.assertRaises(ValueError):
                    database.write_run(result)
                with self.assertRaises(ValueError):
                    database.append_runtime_event("strict-json", {"invalid": math.inf})
                with self.assertRaises(ValueError):
                    database.record_policy_version(
                        policy_id="strict-json",
                        before={"value": 1},
                        after={"value": -math.inf},
                    )

                with database.get_connection() as conn:
                    counts = {
                        table: conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                        for table in ("experiment_runs", "audit_logs", "runtime_events", "policy_versions")
                    }

        self.assertEqual(counts, {"experiment_runs": 0, "audit_logs": 0, "runtime_events": 0, "policy_versions": 0})

    def test_runtime_metrics_snapshot_bounds_invalid_limits_without_crashing(self) -> None:
        with tempfile.TemporaryDirectory(prefix="database-metrics-limit-") as temp_dir:
            runtime_dir = Path(temp_dir)
            with (
                patch.object(database, "RUNTIME_DIR", runtime_dir),
                patch.object(database, "DB_PATH", runtime_dir / "metrics.sqlite3"),
            ):
                database.init_db()
                invalid_windows = [
                    database.runtime_metrics_snapshot("not-an-integer"),
                    database.runtime_metrics_snapshot(None),
                    database.runtime_metrics_snapshot(-7),
                    database.runtime_metrics_snapshot(float("inf")),
                ]

        self.assertEqual(invalid_windows[0]["window"]["run_limit"], 500)
        self.assertEqual(invalid_windows[1]["window"]["audit_limit"], 500)
        self.assertEqual(invalid_windows[2]["window"]["run_limit"], 1)
        self.assertEqual(invalid_windows[3]["window"]["audit_limit"], 500)

    def test_runtime_metrics_receipts_follow_only_the_bounded_audit_window(self) -> None:
        with tempfile.TemporaryDirectory(prefix="database-metrics-exact-receipts-") as temp_dir:
            runtime_dir = Path(temp_dir)
            with (
                patch.object(database, "RUNTIME_DIR", runtime_dir),
                patch.object(database, "DB_PATH", runtime_dir / "metrics.sqlite3"),
            ):
                database.init_db()
                with database.get_connection() as conn:
                    for index in range(3):
                        audit_id = f"audit-{index}"
                        conn.execute(
                            """
                            INSERT INTO audit_logs (id, run_id, tool, decision, risk_level, reason, payload)
                            VALUES (?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                audit_id,
                                "run-1",
                                "file.read",
                                "允许",
                                "low",
                                "fixture",
                                json.dumps({"id": audit_id, "execution_receipt_expected": True}),
                            ),
                        )
                        conn.execute(
                            """
                            INSERT INTO runtime_events (event_type, created_at, payload)
                            VALUES ('execution-receipt', ?, ?)
                            """,
                            (
                                f"2026-08-25T00:00:0{index}+00:00",
                                json.dumps(
                                    {
                                        "audit_id": audit_id,
                                        "receipt_id": f"receipt-{index}",
                                        "status": "completed",
                                        "execution_target": "local-runtime",
                                    }
                                ),
                            ),
                        )

                snapshot = database.runtime_metrics_snapshot(1)

        self.assertEqual(snapshot["window"]["audit_limit"], 1)
        self.assertEqual(snapshot["summary"]["audit_log_count"], 1)
        self.assertEqual(snapshot["summary"]["execution_receipt_count"], 1)

    def test_readers_skip_corrupt_json_and_bound_negative_limits(self) -> None:
        with tempfile.TemporaryDirectory(prefix="database-corrupt-payloads-") as temp_dir:
            runtime_dir = Path(temp_dir)
            with (
                patch.object(database, "RUNTIME_DIR", runtime_dir),
                patch.object(database, "DB_PATH", runtime_dir / "corrupt.sqlite3"),
            ):
                database.init_db()
                with database.get_connection() as conn:
                    conn.execute(
                        """
                        INSERT INTO experiment_runs (
                            id, scenario_id, guard_enabled, attack_success, blocked_count,
                            asked_count, isolated_count, detection_latency_ms, created_at, payload
                        ) VALUES (?, ?, 1, 0, 0, 0, 0, 0, ?, ?)
                        """,
                        ("bad-run", "SCENARIO-BAD", "2026-08-24T00:00:00+00:00", "{bad-json"),
                    )
                    conn.execute(
                        """
                        INSERT INTO experiment_runs (
                            id, scenario_id, guard_enabled, attack_success, blocked_count,
                            asked_count, isolated_count, detection_latency_ms, created_at, payload
                        ) VALUES (?, ?, 1, 0, 0, 0, 0, 0, ?, ?)
                        """,
                        (
                            "good-run",
                            "SCENARIO-GOOD",
                            "2026-08-24T00:01:00+00:00",
                            json.dumps({"run_id": "good-run", "scenario": {"id": "SCENARIO-GOOD"}}),
                        ),
                    )
                    conn.execute(
                        """
                        INSERT INTO audit_logs (id, run_id, tool, decision, risk_level, reason, payload)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        ("bad-audit", "good-run", "file.read", "允许", "low", "bad", "{bad-json"),
                    )
                    conn.execute(
                        """
                        INSERT INTO audit_logs (id, run_id, tool, decision, risk_level, reason, payload)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            "good-audit",
                            "good-run",
                            "file.read",
                            "允许",
                            "low",
                            "good",
                            json.dumps(
                                {
                                    "id": "good-audit",
                                    "conversation_id": "conversation-good",
                                    "execution_status": "pending",
                                }
                            ),
                        ),
                    )
                    conn.execute(
                        """
                        INSERT INTO policy_versions (
                            policy_id, operator, comment, created_at, before_payload, after_payload
                        ) VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        ("bad-policy", "operator", "bad", "2026-08-24T00:00:00+00:00", "{bad-json", "{}"),
                    )
                    conn.execute(
                        """
                        INSERT INTO policy_versions (
                            policy_id, operator, comment, created_at, before_payload, after_payload
                        ) VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            "good-policy",
                            "operator",
                            "good",
                            "2026-08-24T00:01:00+00:00",
                            "{}",
                            json.dumps({"enabled": True}),
                        ),
                    )

                self.assertEqual([item["run_id"] for item in database.latest_runs(-1)], ["good-run"])
                self.assertIsNone(database.load_run("bad-run"))
                self.assertEqual([item["id"] for item in database.latest_audit_logs(-1)], ["good-audit"])
                self.assertIsNone(database.load_audit_log("bad-audit"))
                self.assertEqual(
                    [item["id"] for item in database.load_audit_logs_by_conversation_ids({"conversation-good"})],
                    ["good-audit"],
                )
                self.assertEqual([item["policy_id"] for item in database.list_policy_versions(limit=-1)], ["good-policy"])

    def test_write_run_persists_intent_without_publishing_completed_run_event(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime-intent-storage-") as temp_dir:
            runtime_dir = Path(temp_dir)
            with (
                patch.object(database, "RUNTIME_DIR", runtime_dir),
                patch.object(database, "DB_PATH", runtime_dir / "intent.sqlite3"),
            ):
                database.init_db()
                result: dict[str, Any] = {
                    "run_id": "runtime-intent-run",
                    "scenario": {"id": "EXTERNAL-FILE-READ"},
                    "guard_enabled": True,
                    "attack_success": False,
                    "metrics": {
                        "blocked_count": 0,
                        "asked_count": 0,
                        "isolated_count": 0,
                        "detection_latency_ms": 3,
                    },
                    "created_at": "2026-08-23T00:00:00+00:00",
                    "audit_logs": [
                        {
                            "id": "runtime-intent-audit",
                            "run_id": "runtime-intent-run",
                            "tool": "file.read",
                            "decision": "允许",
                            "risk_level": "low",
                            "reason": "执行意图已建立。",
                            "execution_status": "pending",
                        }
                    ],
                    "alerts": [],
                }

                database.write_run(result, append_runtime_event=False)

                intent_runs = database.latest_runs(10)
                persisted_run = database.load_run("runtime-intent-run")
                persisted_audit = database.load_audit_log("runtime-intent-audit")
                run_events = database.list_runtime_events(event_type="run", limit=10)

                completed_result = {**result}
                completed_result["audit_logs"] = [
                    {
                        **result["audit_logs"][0],
                        "execution_status": "completed",
                        "execution_evidence": "server-observed",
                    }
                ]
                database.write_run(completed_result)
                completed_runs = database.latest_runs(10)

        self.assertEqual(intent_runs, [])
        self.assertIsNone(persisted_run)
        self.assertIsNotNone(persisted_audit)
        assert persisted_audit is not None
        self.assertEqual(persisted_audit["execution_status"], "pending")
        self.assertEqual(run_events, [])
        self.assertEqual([run["run_id"] for run in completed_runs], ["runtime-intent-run"])


if __name__ == "__main__":
    unittest.main()
