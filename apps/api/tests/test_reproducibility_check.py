from __future__ import annotations

import unittest
from pathlib import Path
from typing import Any

from apps.api.agent_supervisor.domains.evaluations.competition_benchmark import build_competition_benchmark
from apps.api.agent_supervisor.domains.evaluations.reproducibility_check import build_reproducibility_report


def _fake_external_demo(*, output_root: Path) -> dict[str, Any]:
    del output_root
    return {
        "schema_version": "agent-supervisor.external-agent-e2e.v1",
        "risk_hint_used": False,
        "security": {
            "token_authentication_used": True,
            "hmac_signature_expected": True,
        },
        "summary": {
            "task_count": 4,
            "controlled_count": 3,
            "executed_count": 1,
            "control_rate": 75,
            "executed_tools": ["file.read"],
            "audit_hash_count": 4,
            "audit_signature_count": 4,
        },
    }


class ReproducibilityCheckTest(unittest.TestCase):
    def test_repeated_deterministic_judges_are_stable(self) -> None:
        report = build_reproducibility_report(
            trials=3,
            operator="测试复现者",
            operator_role="测试",
            external_demo_runner=_fake_external_demo,
        )

        self.assertTrue(report["summary"]["passed"])
        self.assertEqual(report["summary"]["passed_count"], 3)
        self.assertEqual(report["summary"]["pass_rate"], 100)
        self.assertTrue(report["summary"]["stable_inputs"])
        self.assertTrue(report["summary"]["stable_outcomes"])
        self.assertFalse(report["method"]["external_validation"])
        self.assertEqual(len(report["evidence_sha256"]), 64)
        self.assertTrue(all(len(trial["checks"]) == 7 for trial in report["trials"]))

    def test_policy_hash_drift_fails_consistency(self) -> None:
        call_count = 0

        def drifting_benchmark(**kwargs: Any) -> dict[str, Any]:
            nonlocal call_count
            report = build_competition_benchmark(**kwargs)
            call_count += 1
            report["policy_snapshot"]["sha256"] = f"policy-{call_count}"
            return report

        report = build_reproducibility_report(
            trials=2,
            benchmark_builder=drifting_benchmark,
            external_demo_runner=_fake_external_demo,
        )

        self.assertFalse(report["summary"]["passed"])
        self.assertFalse(report["summary"]["stable_inputs"])
        self.assertEqual(report["summary"]["passed_count"], 2)


if __name__ == "__main__":
    unittest.main()
