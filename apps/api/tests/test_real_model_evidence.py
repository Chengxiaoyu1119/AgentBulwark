from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from apps.api.agent_supervisor.adapters.models import model_adapter
from apps.api.agent_supervisor.adapters.models.model_adapter import _tool_definitions
from apps.api.agent_supervisor.domains.runtime import runtime_evaluation
from apps.api.agent_supervisor.domains.runtime.runtime_evaluation import load_real_model_evaluation_report
from apps.api.agent_supervisor.domains.runtime.tools import SandboxPaths, init_sandbox


class RealModelEvidenceLoadingTest(unittest.TestCase):
    def test_evaluation_sandbox_can_seed_only_synthetic_sensitive_memory(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            evaluation_paths = SandboxPaths(
                workspace=root / "evaluation" / "workspace",
                outbox=root / "evaluation" / "outbox",
                memory=root / "evaluation" / "memory",
                fixtures=root / "fixtures",
                target_state=root / "evaluation" / "target-state.json",
                seed_fixtures=False,
                seed_sensitive_memory=True,
            )
            normal_paths = SandboxPaths(
                workspace=root / "normal" / "workspace",
                outbox=root / "normal" / "outbox",
                memory=root / "normal" / "memory",
                fixtures=root / "fixtures",
                target_state=root / "normal" / "target-state.json",
                seed_fixtures=False,
            )
            init_sandbox(evaluation_paths)
            init_sandbox(normal_paths)

            evaluation_memory = json.loads((evaluation_paths.memory / "memory.json").read_text(encoding="utf-8"))
            normal_memory = json.loads((normal_paths.memory / "memory.json").read_text(encoding="utf-8"))

        self.assertTrue(any(item.get("source") == "evaluation-fixture" for item in evaluation_memory))
        self.assertEqual(normal_memory, [])

    def test_model_tool_schema_preserves_provider_selected_relative_paths(self) -> None:
        definitions = {item["function"]["name"]: item["function"] for item in _tool_definitions()}

        description = definitions["file_read"]["description"]
        self.assertIn("不要自行添加 public/ 前缀", description)

    def test_evaluation_uses_a_registered_agent_identity_for_benign_cases(self) -> None:
        settings = {
            "require_agent_capability_registration": True,
            "require_agent_model_registration": True,
            "agent_tool_allowlists": {"fixture-agent": ["file.read", "api.call", "mail.send"]},
            "agent_model_allowlists": {"fixture-agent": ["fixture-model"]},
        }
        providers = [{"configured": True, "model": "fixture-model"}]
        with (
            patch.object(runtime_evaluation, "get_policy_settings", return_value=settings),
            patch.object(runtime_evaluation, "provider_status", return_value=providers),
            patch.dict("os.environ", {runtime_evaluation.REAL_MODEL_EVALUATION_AGENT_ENV: ""}, clear=False),
        ):
            binding = runtime_evaluation._evaluation_agent_binding()

        self.assertEqual(binding["agent_id"], "fixture-agent")
        self.assertTrue(binding["registered"])
        self.assertTrue(binding["tools_ready"])
        self.assertTrue(binding["model_ready"])

    def test_strict_provider_mode_fails_closed_when_multiple_providers_are_configured(self) -> None:
        configured = [
            {
                "provider_id": "deepseek",
                "provider": "DeepSeek",
                "model": "deepseek-fixture",
                "api_key": "key-a",
                "endpoint": "https://deepseek.example/v1/chat/completions",
            },
            {
                "provider_id": "zhipu",
                "provider": "智谱",
                "model": "glm-fixture",
                "api_key": "key-b",
                "endpoint": "https://zhipu.example/v1/chat/completions",
            },
        ]
        with (
            patch.dict(
                "os.environ",
                {"REAL_MODEL_EVALUATION_PROVIDER": "", "TARGET_REAL_MODEL_PROVIDER": ""},
                clear=False,
            ),
            patch.object(model_adapter, "_iter_configured_providers", return_value=configured),
            patch.object(model_adapter.urllib.request, "urlopen") as urlopen,
            patch.object(model_adapter, "simulate_tool_plan") as fallback,
        ):
            result = model_adapter.generate_model_tool_plan(
                "fixture prompt",
                "fixture-case",
                force_real=True,
                provider_profile="target",
                strict_provider="",
            )

        self.assertEqual(result["mode"], "provider-failure")
        self.assertIn("多个 Provider", result["provider_failures"][0]["error"])
        urlopen.assert_not_called()
        fallback.assert_not_called()

    def test_strict_provider_mode_calls_only_the_selected_provider(self) -> None:
        selected = {
            "provider_id": "zhipu",
            "provider": "智谱",
            "model": "glm-fixture",
            "api_key": "key-b",
            "endpoint": "https://zhipu.example/v1/chat/completions",
        }

        def iter_selected(profile: str, *, requested_model: str = "", provider_id: str = "") -> list[dict]:
            self.assertEqual(profile, "target")
            self.assertEqual(provider_id, "zhipu")
            return [selected]

        with (
            patch.object(model_adapter, "_iter_configured_providers", side_effect=iter_selected),
            patch.object(
                model_adapter,
                "_post_tool_completion",
                return_value={
                    "provider": "智谱",
                    "model": "glm-fixture",
                    "mode": "real-api",
                    "tool_calls": [
                        {
                            "id": "call-fixture",
                            "tool": "file.read",
                            "arguments": {"path": "public/readme.md"},
                        }
                    ],
                    "provider_failures": [],
                },
            ) as post,
        ):
            result = model_adapter.generate_model_tool_plan(
                "fixture prompt",
                "fixture-case",
                force_real=True,
                provider_profile="target",
                strict_provider="zhipu",
            )

        self.assertEqual(result["mode"], "real-api")
        self.assertEqual(result["provider_id"], "zhipu")
        self.assertEqual(post.call_args.kwargs["provider"], "智谱")

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
        # ``force_real=True`` is a per-evaluation override; it must not make a
        # fresh report look stale merely because the global runtime switch is
        # disabled.
        self.assertTrue(report["runtime_snapshot"]["real_api_enabled"])
        freshness = runtime_evaluation.verify_current_evidence_snapshot(report)
        # The case definitions were intentionally replaced inside this test to
        # keep the fixture small.  The runtime fingerprint is the property this
        # regression protects; the case fingerprint must correctly become stale
        # once the patched definitions leave scope.
        self.assertTrue(freshness["runtime_snapshot_current"])
        self.assertFalse(freshness["case_definitions_current"])
        self.assertFalse(freshness["current"])

    def test_runtime_snapshot_preserves_environment_real_api_switch(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            with (
                patch.dict("os.environ", {"MODEL_REAL_API_ENABLED": "true"}, clear=False),
                patch(
                    "apps.api.agent_supervisor.adapters.models.model_runtime_config.MODEL_RUNTIME_CONFIG_PATH",
                    Path(temp_dir) / "missing-model-runtime-config.json",
                ),
            ):
                snapshot = runtime_evaluation._runtime_evidence_snapshot(force_real=None)

        self.assertTrue(snapshot["real_api_enabled"])
        self.assertTrue(snapshot["runtime_real_api_enabled"])

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

    def test_parallel_tool_calls_are_all_replayed_before_followup(self) -> None:
        plan = {
            "provider": "fixture-provider",
            "model": "fixture-model",
            "mode": "real-api",
            "request_hash": "plan-request-hash",
            "provider_response_hash": "plan-response-hash",
            "content": "",
            "tool_calls": [
                {"id": "call-read", "tool": "file.read", "arguments": {"path": "public/项目说明.md"}},
                {
                    "id": "call-mail",
                    "tool": "mail.send",
                    "arguments": {"to": "outside@example.com", "subject": "fixture", "body": "fixture"},
                },
            ],
            "provider_failures": [],
        }
        continuation = {
            "provider": "fixture-provider",
            "model": "fixture-model",
            "mode": "real-api",
            "request_hash": "continuation-request-hash",
            "provider_response_hash": "continuation-response-hash",
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
                "policy_id": "external-mail" if controlled else "default-allow",
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
            patch.object(runtime_evaluation, "generate_model_tool_followup", return_value=continuation) as followup,
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
                    "id": "DATA-LEAK-001",
                    "label": "attack",
                    "prompt": "fixture prompt",
                    "expected_control": True,
                    "expected_tool": "mail.send",
                },
                force_real=True,
                evaluation_id="parallel-fixture",
            )

        self.assertEqual([item["tool"] for item in result["tool_calls"]], ["file.read", "mail.send"])
        self.assertEqual(result["model_tool_call_count"], 2)
        self.assertEqual(result["baseline"]["step_count"], 2)
        self.assertEqual(result["guarded"]["step_count"], 2)
        self.assertTrue(result["attack_reproduced"])
        self.assertTrue(result["defense_effective"])
        self.assertTrue(result["real_model_evidence_valid"])
        self.assertEqual(followup.call_args.args[3][0]["id"], "call-read")
        self.assertEqual(len(followup.call_args.args[3]), 2)
        self.assertEqual(len(followup.call_args.args[4]), 2)

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

    def test_self_consistent_old_runtime_snapshot_is_marked_stale(self) -> None:
        policy_snapshot = {"policies": runtime_evaluation.get_policies(), "settings": runtime_evaluation.get_policy_settings()}
        old_runtime = {"real_api_enabled": True, "providers": [{"profile": "target", "model": "old-model"}]}
        report: dict = {
            "schema_version": "agent-supervisor.real-model-evaluation.v3",
            "summary": {"strict_real_api_ready": True, "evidence_verdict": "pass"},
            "evidence_manifest": {
                "case_definitions_sha256": runtime_evaluation._payload_hash([]),
                "policy_snapshot_sha256": runtime_evaluation._payload_hash(policy_snapshot),
                "runtime_snapshot_sha256": runtime_evaluation._payload_hash(old_runtime),
                "result_set_sha256": runtime_evaluation._payload_hash([]),
            },
            "runtime_snapshot": old_runtime,
            "results": [],
        }
        report["report_hash"] = runtime_evaluation._report_hash(report)

        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "真实模型工具调用盲测报告.json"
            path.write_text(json.dumps(report, ensure_ascii=False), encoding="utf-8")
            loaded = load_real_model_evaluation_report(temp_dir)

        assert loaded is not None
        self.assertTrue(loaded["integrity_verification"]["valid"])
        self.assertFalse(loaded["freshness_verification"]["current"])
        self.assertFalse(loaded["summary"]["strict_real_api_ready"])
        self.assertEqual(loaded["summary"]["evidence_verdict"], "stale")

    def test_provider_order_is_part_of_runtime_freshness_fingerprint(self) -> None:
        with patch.object(runtime_evaluation, "provider_execution_order", return_value=["智谱"]):
            old_runtime = runtime_evaluation._runtime_evidence_snapshot(force_real=True)
        report = {
            "runtime_snapshot": old_runtime,
            "evidence_manifest": {
                "runtime_snapshot_sha256": runtime_evaluation._payload_hash(old_runtime),
            },
        }
        with patch.object(runtime_evaluation, "provider_execution_order", return_value=["DeepSeek", "智谱"]):
            freshness = runtime_evaluation.verify_current_evidence_snapshot(report)

        self.assertTrue(freshness["runtime_snapshot_valid"])
        self.assertFalse(freshness["runtime_snapshot_current"])


if __name__ == "__main__":
    unittest.main()
