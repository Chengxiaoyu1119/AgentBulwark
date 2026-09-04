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
    @staticmethod
    def _configured_provider() -> dict[str, str]:
        return {
            "provider_id": "openai-compatible",
            "provider": "本地协议夹具",
            "model": "fixture-model",
            "api_key": "fixture-key",
            "endpoint": "http://127.0.0.1:9/v1/chat/completions",
        }

    @staticmethod
    def _set_provider_response(provider_open: object, raw: str) -> None:
        response = provider_open.return_value.__enter__.return_value  # type: ignore[attr-defined]
        response.headers = {}
        response.read.return_value = raw.encode("utf-8")

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

    def test_empty_provider_text_is_not_labeled_as_real_model_output(self) -> None:
        with (
            patch.object(model_adapter, "runtime_real_api_enabled", return_value=True),
            patch.object(model_adapter, "_iter_configured_providers", return_value=[self._configured_provider()]),
            patch.object(model_adapter, "_provider_open") as provider_open,
        ):
            self._set_provider_response(
                provider_open,
                json.dumps({"id": "resp-empty", "choices": [{"message": {"content": ""}}]}),
            )
            result = model_adapter.generate_model_response("检查真实输出", "empty-provider-text")

        self.assertEqual(result["mode"], "fallback")
        self.assertEqual(len(result["provider_failures"]), 1)
        self.assertEqual(result["provider_failures"][0]["error"], "Provider 响应格式校验失败")

    def test_empty_optimizer_response_does_not_claim_real_api_provenance(self) -> None:
        with (
            patch.object(model_adapter, "_iter_configured_providers", return_value=[self._configured_provider()]),
            patch.object(model_adapter, "_provider_open") as provider_open,
        ):
            self._set_provider_response(
                provider_open,
                json.dumps({"id": "resp-empty-optimizer", "choices": [{"message": {"content": ""}}]}),
            )
            result = model_adapter.generate_optimizer_prompt(
                "检查真实优化器输出",
                "secret",
                "optimizer",
                "empty-provider-optimizer",
                force_real=True,
            )

        self.assertEqual(result["mode"], "fallback")
        self.assertEqual(len(result["provider_failures"]), 1)
        self.assertEqual(result["provider_failures"][0]["error"], "Provider 响应格式校验失败")

    def test_duplicate_provider_json_cannot_create_a_real_api_tool_plan(self) -> None:
        duplicate_choices = (
            '{"id":"resp-duplicate","choices":[{"message":{"tool_calls":[]}}],'
            '"choices":[{"message":{"tool_calls":[{"id":"call-1","type":"function",'
            '"function":{"name":"file_read","arguments":"{}"}}]},"finish_reason":"tool_calls"}]}'
        )
        with (
            patch.object(model_adapter, "_iter_configured_providers", return_value=[self._configured_provider()]),
            patch.object(model_adapter, "_provider_open") as provider_open,
        ):
            self._set_provider_response(provider_open, duplicate_choices)
            result = model_adapter.generate_model_tool_plan(
                "读取文件",
                "duplicate-provider-json",
                force_real=True,
            )

        self.assertEqual(result["mode"], "fallback")
        self.assertEqual(len(result["provider_failures"]), 1)
        self.assertEqual(result["provider_failures"][0]["error"], "Provider 响应格式校验失败")

    def test_invalid_tool_calls_are_not_accepted_as_a_real_api_plan(self) -> None:
        invalid_functions = [
            {"name": "file_read", "arguments": '{"path":"public/a","path":"public/b"}'},
            {"name": "file_read", "arguments": ""},
            {"name": "file_read", "arguments": False},
            {"name": "file_read", "arguments": "{}"},
            {"name": "file_read", "arguments": "{}"},
        ]
        invalid_calls = [
            {"id": "call-1", "type": "function", "function": invalid_functions[0]},
            {"id": "call-1", "type": "function", "function": invalid_functions[1]},
            {"id": "call-1", "type": "function", "function": invalid_functions[2]},
            {"id": "call-1", "type": "custom", "function": invalid_functions[3]},
            {"id": "call-1", "type": "function", "function": {"name": "", "arguments": "{}"}},
            {"id": 7, "type": "function", "function": invalid_functions[4]},
            {"id": "call-1", "type": "function", "function": {"name": "file_read"}},
        ]
        for tool_call in invalid_calls:
            with self.subTest(tool_call=tool_call):
                provider_response = json.dumps(
                    {
                        "id": "resp-invalid-arguments",
                        "choices": [
                            {
                                "message": {
                                    "tool_calls": [
                                        tool_call
                                    ]
                                },
                                "finish_reason": "tool_calls",
                            }
                        ],
                    }
                )
                with (
                    patch.object(model_adapter, "_iter_configured_providers", return_value=[self._configured_provider()]),
                    patch.object(model_adapter, "_provider_open") as provider_open,
                ):
                    self._set_provider_response(provider_open, provider_response)
                    result = model_adapter.generate_model_tool_plan(
                        "读取文件",
                        "invalid-tool-arguments",
                        force_real=True,
                    )

                self.assertEqual(result["mode"], "fallback")
                self.assertEqual(len(result["provider_failures"]), 1)
                self.assertEqual(result["provider_failures"][0]["error"], "Provider 返回无效结构化 tool_calls")
                self.assertEqual(result["provider_call_count"], 1)
                self.assertEqual(result["tool_plan_attempts"][0]["outcome"], "provider-error")
                self.assertEqual(result["tool_plan_attempts"][0]["tool_call_parse_issue_count"], 1)

    def test_mixed_valid_and_invalid_tool_calls_are_not_partially_accepted(self) -> None:
        provider_response = json.dumps(
            {
                "id": "resp-mixed-tool-calls",
                "choices": [
                    {
                        "message": {
                            "tool_calls": [
                                {
                                    "id": "call-valid",
                                    "type": "function",
                                    "function": {"name": "file_read", "arguments": '{"path":"public/readme.md"}'},
                                },
                                {
                                    "id": "call-invalid",
                                    "type": "function",
                                    "function": {"name": "file_read", "arguments": ""},
                                },
                            ]
                        },
                        "finish_reason": "tool_calls",
                    }
                ],
            }
        )
        with (
            patch.object(model_adapter, "_iter_configured_providers", return_value=[self._configured_provider()]),
            patch.object(model_adapter, "_provider_open") as provider_open,
        ):
            self._set_provider_response(provider_open, provider_response)
            result = model_adapter.generate_model_tool_plan(
                "读取文件",
                "mixed-tool-calls",
                force_real=True,
            )

        self.assertEqual(result["mode"], "fallback")
        self.assertEqual(result["provider_failures"][0]["error"], "Provider 返回无效结构化 tool_calls")
        self.assertEqual(result["provider_call_count"], 1)
        self.assertEqual(result["tool_plan_attempts"][0]["tool_call_count"], 1)
        self.assertEqual(result["tool_plan_attempts"][0]["tool_call_parse_issue_count"], 1)

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

    def test_strict_provider_retries_one_missing_tool_call_and_preserves_attempt_evidence(self) -> None:
        selected = {
            "provider_id": "zhipu",
            "provider": "智谱",
            "model": "glm-fixture",
            "api_key": "key-b",
            "endpoint": "https://zhipu.example/v1/chat/completions",
        }
        responses = [
            {
                "provider": "智谱",
                "model": "glm-fixture",
                "mode": "real-api",
                "tool_calls": [],
                "tool_call_parse_issues": [],
                "finish_reason": "stop",
                "request_hash": "request-1",
                "provider_response_hash": "response-1",
                "provider_response_id": "provider-response-1",
                "usage": {"prompt_tokens": 10, "completion_tokens": 2, "total_tokens": 12},
            },
            {
                "provider": "智谱",
                "model": "glm-fixture",
                "mode": "real-api",
                "tool_calls": [
                    {
                        "id": "call-fixture",
                        "tool": "file.read",
                        "arguments": {"path": "public/项目说明.md"},
                    }
                ],
                "tool_call_parse_issues": [],
                "finish_reason": "tool_calls",
                "request_hash": "request-2",
                "provider_response_hash": "response-2",
                "provider_response_id": "provider-response-2",
                "usage": {"prompt_tokens": 12, "completion_tokens": 4, "total_tokens": 16},
            },
        ]
        with (
            patch.object(model_adapter, "_iter_configured_providers", return_value=[selected]),
            patch.object(model_adapter, "_post_tool_completion", side_effect=responses) as post,
        ):
            result = model_adapter.generate_model_tool_plan(
                "fixture prompt",
                "fixture-case",
                force_real=True,
                provider_profile="target",
                strict_provider="zhipu",
            )

        self.assertEqual(post.call_count, 2)
        self.assertEqual([call.kwargs["attempt"] for call in post.call_args_list], [1, 2])
        self.assertEqual(result["mode"], "real-api")
        self.assertEqual(result["provider_call_count"], 2)
        self.assertEqual(result["tool_plan_retry_count"], 1)
        self.assertEqual([item["outcome"] for item in result["tool_plan_attempts"]], ["no-tool-call", "tool-call"])
        self.assertEqual(result["tool_plan_usage_totals"]["total_tokens"], 28)
        self.assertEqual(result["provider_failures"], [])

    def test_strict_provider_stops_after_two_missing_tool_calls(self) -> None:
        selected = {
            "provider_id": "zhipu",
            "provider": "智谱",
            "model": "glm-fixture",
            "api_key": "key-b",
            "endpoint": "https://zhipu.example/v1/chat/completions",
        }

        def no_tool_call(*, attempt: int, **_: object) -> dict:
            return {
                "provider": "智谱",
                "model": "glm-fixture",
                "mode": "real-api",
                "tool_calls": [],
                "tool_call_parse_issues": [],
                "finish_reason": "stop",
                "request_hash": f"request-{attempt}",
                "provider_response_hash": f"response-{attempt}",
                "usage": {"total_tokens": 10 + attempt},
            }

        with (
            patch.object(model_adapter, "_iter_configured_providers", return_value=[selected]),
            patch.object(model_adapter, "_post_tool_completion", side_effect=no_tool_call) as post,
        ):
            result = model_adapter.generate_model_tool_plan(
                "fixture prompt",
                "fixture-case",
                force_real=True,
                provider_profile="target",
                strict_provider="zhipu",
            )

        self.assertEqual(post.call_count, 2)
        self.assertEqual(result["mode"], "provider-invalid")
        self.assertEqual(result["provider_call_count"], 2)
        self.assertEqual(result["tool_plan_retry_count"], 1)
        self.assertEqual(result["tool_plan_usage_totals"]["total_tokens"], 23)
        self.assertIn("连续 2 次", result["provider_failures"][0]["error"])

    def test_strict_provider_does_not_switch_provider_during_protocol_retry(self) -> None:
        selected = {
            "provider_id": "zhipu",
            "provider": "智谱",
            "model": "glm-fixture",
            "api_key": "key-b",
            "endpoint": "https://zhipu.example/v1/chat/completions",
        }
        other = {
            "provider_id": "deepseek",
            "provider": "DeepSeek",
            "model": "deepseek-fixture",
            "api_key": "key-a",
            "endpoint": "https://deepseek.example/v1/chat/completions",
        }

        def select_provider(profile: str, *, requested_model: str = "", provider_id: str = "") -> list[dict]:
            self.assertEqual(profile, "target")
            self.assertEqual(provider_id, "zhipu")
            self.assertFalse(requested_model)
            return [selected, other]

        def no_tool_call(**kwargs: object) -> dict:
            self.assertEqual(kwargs["provider"], "智谱")
            return {
                "provider": "智谱",
                "model": "glm-fixture",
                "mode": "real-api",
                "tool_calls": [],
                "tool_call_parse_issues": [],
                "request_hash": f"request-{kwargs['attempt']}",
                "provider_response_hash": f"response-{kwargs['attempt']}",
            }

        with (
            patch.object(model_adapter, "_iter_configured_providers", side_effect=select_provider),
            patch.object(model_adapter, "_post_tool_completion", side_effect=no_tool_call) as post,
        ):
            result = model_adapter.generate_model_tool_plan(
                "fixture prompt",
                "fixture-case",
                force_real=True,
                provider_profile="target",
                strict_provider="zhipu",
            )

        self.assertEqual(post.call_count, 2)
        self.assertEqual(result["provider_id"], "zhipu")
        self.assertTrue(result["strict_provider"])

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
