from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from apps.api.agent_supervisor.storage import database


class CompetitionEvidenceRunStorageTests(unittest.TestCase):
    def test_latest_scenario_run_pairs_are_not_lost_behind_recent_external_runs(self) -> None:
        with tempfile.TemporaryDirectory(prefix="competition-evidence-runs-") as temp_dir:
            runtime_dir = Path(temp_dir)
            with (
                patch.object(database, "RUNTIME_DIR", runtime_dir),
                patch.object(database, "DB_PATH", runtime_dir / "evidence.sqlite3"),
            ):
                database.init_db()
                self._insert_run("scenario-a-old-unguarded", "SCENARIO-A", False, "2026-08-12T01:00:00+00:00")
                self._insert_run("scenario-a-latest-unguarded", "SCENARIO-A", False, "2026-08-12T02:00:00+00:00")
                self._insert_run("scenario-a-latest-guarded", "SCENARIO-A", True, "2026-08-12T03:00:00+00:00")
                self._insert_run("scenario-b-latest-unguarded", "SCENARIO-B", False, "2026-08-12T04:00:00+00:00")
                self._insert_run("scenario-b-latest-guarded", "SCENARIO-B", True, "2026-08-12T05:00:00+00:00")
                self._insert_run("unrelated-guarded", "UNRELATED", True, "2026-08-12T06:00:00+00:00")
                for index in range(501):
                    self._insert_run(
                        f"external-{index}",
                        f"EXTERNAL-{index}",
                        bool(index % 2),
                        f"2026-08-13T00:{index // 60:02d}:{index % 60:02d}+00:00",
                    )

                recent_ids = {run["run_id"] for run in database.latest_runs(500)}
                evidence = database.latest_scenario_run_pairs(
                    ["SCENARIO-A", "SCENARIO-B", "SCENARIO-A", "MISSING"]
                )

        self.assertNotIn("scenario-a-latest-guarded", recent_ids)
        self.assertEqual(
            {
                (run["scenario"]["id"], run["guard_enabled"]): run["run_id"]
                for run in evidence
            },
            {
                ("SCENARIO-A", False): "scenario-a-latest-unguarded",
                ("SCENARIO-A", True): "scenario-a-latest-guarded",
                ("SCENARIO-B", False): "scenario-b-latest-unguarded",
                ("SCENARIO-B", True): "scenario-b-latest-guarded",
            },
        )

    @staticmethod
    def _insert_run(run_id: str, scenario_id: str, guard_enabled: bool, created_at: str) -> None:
        payload = {
            "run_id": run_id,
            "scenario": {"id": scenario_id},
            "guard_enabled": guard_enabled,
            "created_at": created_at,
        }
        with database.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO experiment_runs (
                    id, scenario_id, guard_enabled, attack_success, blocked_count,
                    asked_count, isolated_count, detection_latency_ms, created_at, payload
                ) VALUES (?, ?, ?, 0, 0, 0, 0, 0, ?, ?)
                """,
                (
                    run_id,
                    scenario_id,
                    int(guard_enabled),
                    created_at,
                    json.dumps(payload),
                ),
            )


if __name__ == "__main__":
    unittest.main()
