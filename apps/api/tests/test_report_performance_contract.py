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
            patch.object(
                report_service,
                "load_benign_workflow_report",
                return_value=_workflow_evaluation(),
            ) as workflow_report,
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
        workflow_report.assert_called_once_with()
        package_snapshot.assert_called_once_with([])
        self.assertEqual(len(report["runs"]), report_service.REPORT_RUN_LIMIT)
        self.assertEqual(report["summary"]["attack_reproduced_rate"], 100)
        self.assertEqual(report["summary"]["defense_effective_rate"], 100)
        self.assertIsNone(report["competition_package"])

    def test_report_and_markdown_reads_do_not_execute_benign_workflow_tools(self) -> None:
        with (
            patch.dict("os.environ", {"AGENT_SUPERVISOR_AUTH_DISABLED": "true"}),
            patch(
                "apps.api.agent_supervisor.routers.evaluations.load_benign_workflow_report",
                return_value=_workflow_evaluation(),
            ) as load_workflow,
            patch(
                "apps.api.agent_supervisor.domains.evaluations.benign_workflows.evaluate_benign_workflows",
                side_effect=AssertionError("GET must not execute workflow tools"),
            ),
            TestClient(app) as client,
        ):
            response = client.get("/api/evaluations/benign_workflows.md")

        self.assertEqual(response.status_code, 200)
        load_workflow.assert_called_once_with()

    def test_policy_ablation_get_is_cached_and_does_not_toggle_live_policies(self) -> None:
        with (
            patch.dict("os.environ", {"AGENT_SUPERVISOR_AUTH_DISABLED": "true"}),
            patch(
                "apps.api.agent_supervisor.routers.evaluations.load_policy_ablation_report",
                return_value=_policy_ablation(),
            ) as load_ablation,
            patch(
                "apps.api.agent_supervisor.domains.evaluations.ablation.set_policy_enabled",
                side_effect=AssertionError("GET must not toggle live policies"),
            ),
            TestClient(app) as client,
        ):
            response = client.get("/api/evaluations/policy_ablation")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), _policy_ablation())
        load_ablation.assert_called_once_with()

    def test_policy_ablation_cannot_run_inside_a_production_gateway(self) -> None:
        with (
            patch.dict(
                "os.environ",
                {
                    "AGENT_SUPERVISOR_AUTH_DISABLED": "false",
                    "AGENT_SUPERVISOR_SECURITY_PROFILE": "production",
                    "AGENT_SUPERVISOR_AUDIT_HMAC_KEY": "test-audit-hmac-key",
                    "AGENT_SUPERVISOR_API_TOKEN_ANALYST": "analyst-token",
                },
            ),
            patch(
                "apps.api.agent_supervisor.domains.evaluations.ablation.run_scenario",
            ) as run_scenario,
            TestClient(app) as client,
        ):
            response = client.post(
                "/api/evaluations/policy_ablation/write",
                headers={"Authorization": "Bearer analyst-token"},
            )

        self.assertEqual(response.status_code, 409)
        run_scenario.assert_not_called()

    def test_deliverables_get_does_not_create_a_missing_snapshot(self) -> None:
        with (
            patch.dict("os.environ", {"AGENT_SUPERVISOR_AUTH_DISABLED": "true"}),
            patch(
                "apps.api.agent_supervisor.routers.core.load_competition_package_snapshot",
                return_value=None,
            ),
            patch(
                "apps.api.agent_supervisor.routers.core.write_competition_package_snapshot",
            ) as write_snapshot,
            TestClient(app) as client,
        ):
            response = client.get("/api/deliverables")

        self.assertEqual(response.status_code, 404)
        write_snapshot.assert_not_called()

    def test_real_model_get_reads_persisted_evidence_without_calling_provider(self) -> None:
        cached = {"schema_version": "agent-supervisor.real-model-evaluation.v3", "summary": {}, "results": []}
        with (
            patch.dict("os.environ", {"AGENT_SUPERVISOR_AUTH_DISABLED": "true"}),
            patch(
                "apps.api.agent_supervisor.routers.evaluations.load_real_model_evaluation_report",
                return_value=cached,
            ) as load_report,
            patch(
                "apps.api.agent_supervisor.domains.runtime.runtime_evaluation.build_real_model_evaluation",
                side_effect=AssertionError("GET must not call a model Provider"),
            ),
            TestClient(app) as client,
        ):
            response = client.get("/api/evaluations/real_model")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), cached)
        load_report.assert_called_once_with()

    def test_competition_benchmark_get_reads_cache_without_running_benchmark(self) -> None:
        cached = {
            "schema_version": "agent-supervisor.competition-benchmark.v1",
            "dataset": {"case_count": 0, "attack_count": 0, "benign_count": 0, "sha256": "fixture", "cases": []},
            "policy_snapshot": {"sha256": "fixture"},
            "baselines": [],
            "performance": {
                "call_count": 0,
                "sequential_throughput_per_second": 0,
                "sequential_latency_ms": {"p50": 0, "p95": 0, "p99": 0},
                "concurrency": 0,
                "concurrent_throughput_per_second": 0,
                "concurrent_latency_ms": {"p50": 0, "p95": 0, "p99": 0},
                "cpu_seconds": 0,
                "peak_traced_memory_mb": 0,
            },
        }
        with (
            patch.dict("os.environ", {"AGENT_SUPERVISOR_AUTH_DISABLED": "true"}),
            patch(
                "apps.api.agent_supervisor.routers.evaluations.load_competition_benchmark_report",
                return_value=cached,
            ) as load_report,
            patch(
                "apps.api.agent_supervisor.domains.evaluations.competition_benchmark.build_competition_benchmark",
                side_effect=AssertionError("GET must not run the CPU benchmark"),
            ),
            TestClient(app) as client,
        ):
            response = client.get("/api/evaluations/competition_benchmark")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), cached)
        load_report.assert_called_once_with()

    def test_openclaw_validation_get_does_not_write_package_or_run_subprocess(self) -> None:
        cached = {
            "generated_at": "2026-08-18T00:00:00+00:00",
            "overall_status": "static-validated",
            "file_checks": {},
            "static_checks": {},
        }
        with (
            patch.dict("os.environ", {"AGENT_SUPERVISOR_AUTH_DISABLED": "true"}),
            patch(
                "apps.api.agent_supervisor.routers.integrations.load_openclaw_plugin_validation_report",
                return_value=cached,
            ) as load_report,
            patch(
                "apps.api.agent_supervisor.adapters.integrations.openclaw_plugin_package.validate_openclaw_plugin_package",
                side_effect=AssertionError("GET must not create a package or run Node/OpenClaw"),
            ),
            TestClient(app) as client,
        ):
            response = client.get("/api/integrations/openclaw/plugin_package/validation")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), cached)
        load_report.assert_called_once_with()

    def test_readiness_roadmap_and_report_gets_do_not_execute_workflow_tools(self) -> None:
        workflow = _workflow_evaluation()
        with (
            patch.dict("os.environ", {"AGENT_SUPERVISOR_AUTH_DISABLED": "true"}),
            patch(
                "apps.api.agent_supervisor.domains.reports.readiness.load_benign_workflow_report",
                return_value=workflow,
            ) as readiness_load,
            patch(
                "apps.api.agent_supervisor.domains.reports.roadmap.load_benign_workflow_report",
                return_value=workflow,
            ) as roadmap_load,
            patch(
                "apps.api.agent_supervisor.domains.evaluations.benign_workflows.evaluate_benign_workflows",
                side_effect=AssertionError("GET must not execute sandbox workflow tools"),
            ),
            TestClient(app) as client,
        ):
            readiness_response = client.get("/api/readiness")
            roadmap_response = client.get("/api/project_roadmap")
            report_response = client.get("/api/report")

        self.assertEqual(readiness_response.status_code, 200)
        self.assertEqual(roadmap_response.status_code, 200)
        self.assertEqual(report_response.status_code, 200)
        self.assertGreaterEqual(readiness_load.call_count, 1)
        self.assertGreaterEqual(roadmap_load.call_count, 3)


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
            "expected_allow_step_count": 0,
            "expected_control_step_count": 0,
            "false_positive_count": 0,
            "false_positive_rate": 0,
            "expected_match_rate": 100,
            "audit_chain_valid_count": 0,
            "tool_distribution": {},
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
                "name": "LLM API / MCP / Agent 接入",
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
