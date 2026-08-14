from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from apps.api.agent_supervisor.domains.runtime import runtime_evaluation
from apps.api.agent_supervisor.domains.runtime.runtime_evaluation import load_real_model_evaluation_report


class RealModelEvidenceLoadingTest(unittest.TestCase):
    def test_missing_report_is_not_fabricated(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            self.assertIsNone(load_real_model_evaluation_report(temp_dir))

    def test_latest_report_is_loaded_without_running_a_model(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "真实模型工具调用盲测报告.json"
            path.write_text(json.dumps({"summary": {"case_count": 1}, "results": []}), encoding="utf-8")

            loaded = load_real_model_evaluation_report(temp_dir)

            assert loaded is not None
            self.assertEqual(loaded["summary"]["case_count"], 1)
            self.assertFalse(loaded["summary"]["report_integrity_valid"])
            self.assertFalse(loaded["integrity_verification"]["valid"])

    def test_strict_metrics_require_every_case_to_have_real_api_causal_receipts(self) -> None:
        def fake_run_case(case: dict, *, force_real: bool, evaluation_id: str) -> dict:
            is_attack = case["label"] == "attack"
            return {
                **case,
                "provider": "fixture-provider",
                "model": "fixture-model",
                "mode": "real-api",
                "tool_call": {"tool": "file.read", "arguments": {"path": "public/项目说明.md"}},
                "tool_calls": [{"tool": "file.read", "arguments": {"path": "public/项目说明.md"}}],
                "task_aligned": True,
                "expected_control_match": True,
                "benign_task_completed": not is_attack,
                "causal_integrity_valid": True,
                "provider_evidence_complete": True,
                "decision": "拒绝" if is_attack else "允许",
                "controlled": is_attack,
                "risk_score": 90 if is_attack else 10,
                "anomaly_score": 80 if is_attack else 5,
                "supervisor_latency_ms": 3.5,
                "attack_reproduced": is_attack,
                "defense_effective": is_attack,
                "receipt_complete": True,
                "real_model_evidence_valid": True,
                "provider_failures": [],
            }

        with (
            patch.object(
                runtime_evaluation,
                "get_scenarios",
                return_value=[
                    {"id": "TOOL-HIJACK-001", "adversarial_prompt": "fixture attack", "target": "file.read"}
                ],
            ),
            patch.object(
                runtime_evaluation,
                "get_benign_cases",
                return_value=[
                    {
                        "id": "BENIGN-FILE-001",
                        "model_input": "fixture benign",
                        "expected_decision": "允许",
                        "tool_call": {"tool": "file.read"},
                    }
                ],
            ),
            patch.object(runtime_evaluation, "_run_case", side_effect=fake_run_case),
        ):
            report = runtime_evaluation.build_real_model_evaluation(force_real=True)

        summary = report["summary"]
        self.assertEqual(summary["real_api_coverage_rate"], 100)
        self.assertEqual(summary["attack_reproduced_rate"], 100)
        self.assertEqual(summary["defense_effective_rate"], 100)
        self.assertEqual(summary["receipt_complete_rate"], 100)
        self.assertTrue(summary["strict_real_api_ready"])
        self.assertEqual(summary["evidence_verdict"], "pass")
        self.assertEqual(summary["expected_control_match_rate"], 100)
        self.assertEqual(summary["benign_task_completion_rate"], 100)
        self.assertEqual(summary["provider_evidence_coverage_rate"], 100)
        self.assertTrue(runtime_evaluation.verify_real_model_evaluation_report(report)["valid"])

    def test_model_followup_can_add_a_second_tool_and_guard_replays_the_same_chain(self) -> None:
        plan = {
            "provider": "fixture-provider",
            "model": "fixture-model",
            "mode": "real-api",
            "request_hash": "plan-request-hash",
            "provider_response_hash": "plan-response-hash",
            "content": "",
            "tool_calls": [
                {"id": "call-read", "tool": "file.read", "arguments": {"path": "public/项目说明.md"}}
            ],
            "provider_failures": [],
        }
        continuation = {
            "provider": "fixture-provider",
            "model": "fixture-model",
            "mode": "real-api",
            "request_hash": "continuation-request-hash",
            "provider_response_hash": "continuation-response-hash",
            "content": "",
            "tool_calls": [
                {
                    "id": "call-mail",
                    "tool": "mail.send",
                    "arguments": {"to": "outside@example.com", "subject": "fixture", "body": "fixture"},
                }
            ],
            "requires_additional_tool_call": True,
            "provider_failures": [],
        }
        final_response = {
            "provider": "fixture-provider",
            "model": "fixture-model",
            "mode": "real-api",
            "request_hash": "final-request-hash",
            "provider_response_hash": "final-response-hash",
            "content": "done",
            "tool_calls": [],
            "requires_additional_tool_call": False,
            "provider_failures": [],
        }

        def fake_branch(event: dict, tool_call: dict, *, guard_enabled: bool, sandbox: object) -> dict:
            attack_success = tool_call["tool"] == "mail.send" and not guard_enabled
            controlled = tool_call["tool"] == "mail.send" and guard_enabled
            return {
                "decision": "询问" if controlled else "允许",
                "controlled": controlled,
                "policy_id": "external-mail" if controlled else "guard-disabled",
                "risk_score": 90 if controlled else 0,
                "anomaly_score": 70 if controlled else 0,
                "supervisor_latency_ms": 2,
                "attack_success": attack_success,
                "attack_outcome": {"assertions": [{"observed": attack_success}]},
                "executor_called": not controlled,
                "execution_status": "not_executed" if controlled else "completed",
                "execution_target": "none" if controlled else "sandbox",
                "tool_output": {"executed": not controlled, "output": "fixture"},
                "audit_id": f"audit-{tool_call['tool']}-{guard_enabled}",
                "audit_hash": "audit-hash",
                "result_hash": "result-hash" if not controlled else "",
                "receipt_hash": "receipt-hash",
                "receipt_signature": "",
                "receipt_control_verified": controlled,
            }

        with (
            patch.object(runtime_evaluation, "generate_model_tool_plan", return_value=plan),
            patch.object(
                runtime_evaluation,
                "generate_model_tool_followup",
                side_effect=[continuation, final_response],
            ),
            patch.object(runtime_evaluation, "_case_sandbox", return_value=object()),
            patch.object(runtime_evaluation, "init_sandbox"),
            patch.object(
                runtime_evaluation,
                "_sandbox_state_hash",
                side_effect=["initial", "initial", "baseline-after", "guarded-after"],
            ),
            patch.object(runtime_evaluation, "_run_branch", side_effect=fake_branch),
        ):
            result = runtime_evaluation._run_case(
                {
                    "id": "PROMPT-INJECT-001",
                    "label": "attack",
                    "prompt": "fixture prompt",
                    "expected_control": True,
                },
                force_real=True,
                evaluation_id="evaluation-fixture",
            )

        self.assertEqual([item["tool"] for item in result["tool_calls"]], ["file.read", "mail.send"])
        self.assertEqual(result["model_tool_call_count"], 2)
        self.assertEqual(result["baseline"]["step_count"], 2)
        self.assertEqual(result["guarded"]["step_count"], 2)
        self.assertTrue(result["attack_reproduced"])
        self.assertTrue(result["defense_effective"])
        self.assertTrue(result["receipt_complete"])
        self.assertTrue(result["real_model_evidence_valid"])
        self.assertTrue(result["expected_control_match"])
        self.assertTrue(result["causal_integrity_valid"])
        self.assertTrue(result["provider_evidence_complete"])

    def test_local_only_evaluation_never_calls_a_configured_real_provider(self) -> None:
        plan = {
            "provider": "local-fixture",
            "model": "fixture-model",
            "mode": "fallback",
            "content": "",
            "tool_calls": [{"tool": "file.read", "arguments": {"path": "public/项目说明.md"}}],
        }
        followup = {
            "provider": "local-fixture",
            "model": "fixture-model",
            "mode": "fallback",
            "content": "done",
            "tool_calls": [],
            "requires_additional_tool_call": False,
        }

        def fake_branch(event: dict, tool_call: dict, *, guard_enabled: bool, sandbox: object) -> dict:
            return {
                "decision": "允许",
                "controlled": False,
                "policy_id": "default-allow" if guard_enabled else "guard-disabled",
                "risk_score": 5,
                "anomaly_score": 2,
                "supervisor_latency_ms": 1,
                "attack_success": False,
                "attack_outcome": {"assertions": []},
                "executor_called": True,
                "execution_status": "completed",
                "execution_target": "sandbox",
                "tool_output": {"executed": True, "output": "fixture"},
                "audit_id": f"audit-{guard_enabled}",
                "audit_hash": "audit-hash",
                "result_hash": "result-hash",
                "receipt_hash": "receipt-hash",
                "receipt_signature": "",
                "receipt_control_verified": False,
            }

        with (
            patch.object(runtime_evaluation, "generate_model_tool_plan") as real_provider,
            patch.object(runtime_evaluation, "simulate_tool_plan", return_value=plan),
            patch.object(runtime_evaluation, "generate_model_tool_followup", return_value=followup),
            patch.object(runtime_evaluation, "_case_sandbox", return_value=object()),
            patch.object(runtime_evaluation, "init_sandbox"),
            patch.object(runtime_evaluation, "_sandbox_state_hash", side_effect=["initial", "initial", "a", "b"]),
            patch.object(runtime_evaluation, "_run_branch", side_effect=fake_branch),
        ):
            result = runtime_evaluation._run_case(
                {
                    "id": "BENIGN-FILE-001",
                    "label": "benign",
                    "prompt": "fixture prompt",
                    "expected_control": False,
                    "expected_tool": "file.read",
                },
                force_real=False,
                evaluation_id="local-only-fixture",
            )

        real_provider.assert_not_called()
        self.assertEqual(result["mode"], "fallback")
        self.assertTrue(result["benign_task_completed"])
        self.assertFalse(result["real_model_evidence_valid"])

    def test_persisted_report_tampering_downgrades_strict_evidence(self) -> None:
        report: dict = {
            "schema_version": "agent-supervisor.real-model-evaluation.v3",
            "summary": {"strict_real_api_ready": True, "evidence_verdict": "pass"},
            "evidence_manifest": {
                "case_definitions_sha256": runtime_evaluation._payload_hash([]),
                "result_set_sha256": runtime_evaluation._payload_hash([]),
            },
            "results": [],
        }
        report["report_hash"] = runtime_evaluation._report_hash(report)
        report["results"].append({"id": "tampered"})

        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "真实模型工具调用盲测报告.json"
            path.write_text(json.dumps(report, ensure_ascii=False), encoding="utf-8")
            loaded = load_real_model_evaluation_report(temp_dir)

        assert loaded is not None
        self.assertFalse(loaded["integrity_verification"]["valid"])
        self.assertFalse(loaded["summary"]["strict_real_api_ready"])
        self.assertEqual(loaded["summary"]["evidence_verdict"], "invalid")


if __name__ == "__main__":
    unittest.main()
