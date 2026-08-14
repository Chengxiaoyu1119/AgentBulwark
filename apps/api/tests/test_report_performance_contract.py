from __future__ import annotations

import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from apps.api.agent_supervisor.main import app
from apps.api.agent_supervisor.services import report_service


class ReportPerformanceContractTest(unittest.TestCase):
    def test_report_endpoint_disables_client_caching(self) -> None:
        with (
            patch.dict("os.environ", {"AGENT_SUPERVISOR_AUTH_DISABLED": "true"}),
            patch(
                "apps.api.agent_supervisor.routers.evaluations.build_report",
                return_value={"summary": {"control_rate": 100}},
            ) as build_report,
            TestClient(app) as client,
        ):
            response = client.get("/api/report")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertEqual(response.json()["summary"]["control_rate"], 100)
        build_report.assert_called_once_with()

    def test_report_uses_bounded_runtime_sample_and_keeps_fixed_evidence(self) -> None:
        fake_runs = [
            {
                "created_at": "2026-08-12T00:00:00+00:00",
                "scenario": {"id": "EXTERNAL-TEST"},
                "guard_enabled": True,
                "attack_success": False,
                "metrics": {
                    "blocked_count": 0,
                    "asked_count": 0,
                    "isolated_count": 0,
                    "detection_latency_ms": 1,
                },
                "audit_logs": [],
                "alerts": [],
            }
            for _ in range(report_service.REPORT_RUN_LIMIT)
        ]
        with (
            patch.object(report_service, "latest_runs", return_value=fake_runs) as latest_runs,
            patch.object(report_service, "latest_scenario_run_pairs", return_value=[]) as evidence_pairs,
            patch.object(report_service, "evaluate_benign_cases", return_value=_benign_evaluation()),
            patch.object(report_service, "evaluate_benign_workflows", return_value=_workflow_evaluation()),
            patch.object(report_service, "build_surface_conclusions", return_value=_surface_conclusions()),
            patch.object(report_service, "build_output_filter_evidence", return_value=_output_filter()),
            patch.object(report_service, "build_attack_effectiveness", return_value=_attack_effectiveness()),
            patch.object(report_service, "load_policy_ablation_report", return_value=_policy_ablation()),
            patch.object(report_service, "build_project_roadmap", return_value=_roadmap()),
            patch.object(report_service, "build_anomaly_calibration", return_value=_calibration()),
            patch.object(report_service, "evaluate_adversarial_holdout", return_value=_holdout()),
            patch.object(report_service, "load_real_model_evaluation_report", return_value=None),
            patch.object(report_service, "load_competition_package_snapshot", return_value=None) as package_snapshot,
        ):
            report = report_service.build_report()

        latest_runs.assert_called_once_with(report_service.REPORT_RUN_LIMIT)
        evidence_pairs.assert_called_once()
        package_snapshot.assert_called_once_with([])
        self.assertEqual(len(report["runs"]), report_service.REPORT_RUN_LIMIT)
        self.assertEqual(report["summary"]["attack_reproduced_rate"], 100)
        self.assertEqual(report["summary"]["defense_effective_rate"], 100)
        self.assertIsNone(report["competition_package"])


def _benign_evaluation() -> dict:
    return {
        "summary": {
            "case_count": 0,
            "false_positive_count": 0,
            "false_positive_rate": 0,
            "expected_match_rate": 100,
        },
        "cases": [],
    }


def _workflow_evaluation() -> dict:
    return {
        "summary": {
            "workflow_count": 0,
            "step_count": 0,
            "workflow_pass_rate": 100,
            "false_positive_rate": 0,
            "expected_match_rate": 100,
            "audit_chain_valid_count": 0,
        },
        "workflows": [],
    }


def _surface_conclusions() -> dict:
    return {"summary": {"conclusion_count": 0}, "conclusions": []}


def _output_filter() -> dict:
    return {"summary": {"case_count": 0, "block_rate": 0}, "cases": []}


def _attack_effectiveness() -> dict:
    return {
        "summary": {
            "attack_reproduced_rate": 100,
            "defense_effective_rate": 100,
            "evidence_complete_rate": 100,
        },
        "cases": [],
        "requirement_alignment": [],
    }


def _policy_ablation() -> dict:
    return {"summary": {"control_drop": 0, "risk_exposed_count": 0}, "experiments": []}


def _roadmap() -> dict:
    return {
        "summary": {"overall_score": 100, "p0_backlog_count": 0},
        "direction": {"verdict": "方向匹配"},
        "dimensions": [
            {
                "name": "OpenClaw/外部 Agent 接入",
                "score": 100,
                "status": "已完成",
                "evidence": "已验证",
                "next_actions": [],
            }
        ],
        "feature_backlog": [],
        "next_sprint": [],
        "risk_register": [],
    }


def _calibration() -> dict:
    return {
        "summary": {
            "recommended_threshold": 55,
            "attack_recall_rate": 100,
            "benign_false_alarm_rate": 0,
            "policy_controlled_missed_count": 0,
        },
        "threshold_curve": [],
    }


def _holdout() -> dict:
    return {
        "summary": {
            "sample_count": 0,
            "attack_recall_rate": 100,
            "benign_false_positive_rate": 0,
            "expected_match_rate": 100,
        },
        "records": [],
    }


if __name__ == "__main__":
    unittest.main()
