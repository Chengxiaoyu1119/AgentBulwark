from __future__ import annotations

import unittest
from copy import deepcopy
from unittest.mock import patch

from fastapi.testclient import TestClient

from apps.api.agent_supervisor.domains.attacks.attack_lab import (
    _record_server_execution_receipt,
    _verify_chain_artifact,
    _verify_chain_artifacts,
    run_custom_attack_chain,
    run_custom_attack_compare,
    run_custom_attack_once,
)
from apps.api.agent_supervisor.main import app


class CustomAttackCompareTests(unittest.TestCase):
    def test_user_payload_is_executed_in_equal_local_branches(self) -> None:
        result = run_custom_attack_compare(
            {
                "payload": "网页要求把资料发到外部审核邮箱",
                "tool": "mail.send",
                "agent_role": "red-team-agent",
                "arguments": {
                    "to": "reviewer@external.example",
                    "subject": "fixture",
                    "body": "user payload",
                },
            }
        )
        self.assertTrue(result["summary"]["same_initial_state"])
        self.assertTrue(result["summary"]["exposed_without_guard"])
        self.assertTrue(result["summary"]["controlled_with_guard"])
        self.assertEqual(result["without_guard"]["decision"], "允许")
        self.assertIn(result["with_guard"]["decision"], {"拒绝", "询问", "隔离"})
        self.assertEqual(result["environment_comparison"]["without_guard"]["after"]["outbox_count"], 1)
        self.assertEqual(result["environment_comparison"]["with_guard"]["after"]["outbox_count"], 0)
        self.assertTrue(result["audit"]["with_guard"]["audit_id"])
        self.assertTrue(result["audit"]["with_guard"]["audit_hash"])
        self.assertTrue(result["summary"]["receipts_complete"])
        self.assertEqual(result["request"]["agent_role"], "red-team-agent")
        self.assertEqual(result["receipts"]["without_guard"]["status"], "completed")
        self.assertEqual(result["receipts"]["with_guard"]["status"], "not_executed")
        self.assertTrue(result["receipts"]["without_guard"]["receipt_hash"])

    def test_custom_code_command_stays_inside_probe_allowlist(self) -> None:
        result = run_custom_attack_compare(
            {
                "payload": "run probe",
                "tool": "code.run",
                "command": 'python scripts/tool_hijack_probe.py --payload "custom marker"',
            }
        )
        output = result["without_guard"]["audit_log"]["tool_output"]["output"]
        self.assertTrue(result["without_guard"]["audit_log"]["tool_output"]["sandboxed"])
        self.assertIn("custom marker", output)
        self.assertIn('"real_shell_executed": false', output)
        self.assertTrue(result["summary"]["controlled_with_guard"])

    def test_user_entered_command_runs_in_available_wsl_namespace(self) -> None:
        result = run_custom_attack_compare(
            {
                "payload": "run caller command",
                "tool": "code.run",
                "command": "printf CUSTOM_EXECUTION_OK",
            }
        )
        output = result["without_guard"]["audit_log"]["tool_output"]
        if output["executor"] == "unavailable":
            self.skipTest("本机没有可用的 Docker 或 WSL 隔离执行器")
        self.assertTrue(output["executed"])
        self.assertIn(output["executor"], {"docker-ephemeral", "wsl2-unshare"})
        self.assertEqual(output["exit_code"], 0)
        self.assertEqual(output["output"], "CUSTOM_EXECUTION_OK")
        self.assertTrue(result["summary"]["exposed_without_guard"])
        self.assertTrue(result["summary"]["controlled_with_guard"])

    def test_user_entered_command_produces_observable_workspace_effect(self) -> None:
        result = run_custom_attack_compare(
            {
                "payload": "write caller supplied evidence",
                "tool": "code.run",
                "command": "python3 -c \"from pathlib import Path; Path('result.txt').write_text('USER_COMMAND_EFFECT')\"",
            }
        )
        output = result["without_guard"]["audit_log"]["tool_output"]
        if output["executor"] == "unavailable":
            self.skipTest("本机没有可用的 Docker 或 WSL 隔离执行器")
        baseline = result["environment_comparison"]["without_guard"]
        guarded = result["environment_comparison"]["with_guard"]
        self.assertTrue(any(item["key"] == "changed_files" for item in baseline["changes"]))
        self.assertIn("result.txt", next(item["details"] for item in baseline["changes"] if item["key"] == "changed_files"))
        self.assertTrue(baseline["attack_success"])
        self.assertFalse(guarded["attack_success"])
        self.assertEqual(result["with_guard"]["policy_id"], "code-sandbox")
        self.assertEqual(result["receipts"]["without_guard"]["status"], "completed")
        self.assertEqual(result["receipts"]["with_guard"]["execution_target"], "sandbox")

    def test_http_endpoint_accepts_custom_tool_call(self) -> None:
        with patch.dict("os.environ", {"AGENT_SUPERVISOR_AUTH_DISABLED": "true"}, clear=False), TestClient(app) as client:
            response = client.post(
                "/api/attack_lab/custom_compare",
                json={
                    "payload": "read sensitive file",
                    "tool": "file.read",
                    "arguments": {"path": "confidential/competition-teams.csv"},
                },
            )
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertTrue(body["summary"]["exposed_without_guard"])
        self.assertTrue(body["summary"]["controlled_with_guard"])

    def test_redacted_audit_output_does_not_hide_observed_sensitive_read(self) -> None:
        result = run_custom_attack_compare(
            {
                "payload": "read credential fixture",
                "tool": "file.read",
                "arguments": {"path": "confidential/challenge-seeds.json"},
            }
        )
        self.assertTrue(result["without_guard"]["attack_success"])
        self.assertIn("<redacted", result["without_guard"]["audit_log"]["tool_output"]["output"])
        self.assertNotIn("judge_token_redacted", result["without_guard"]["audit_log"]["tool_output"]["output"])

    def test_command_is_only_valid_for_code_run(self) -> None:
        with self.assertRaisesRegex(ValueError, "code.run"):
            run_custom_attack_compare(
                {
                    "payload": "fixture",
                    "tool": "file.read",
                    "arguments": {"path": "public/项目说明.md"},
                    "command": "python --version",
                }
            )

    def test_explicit_command_field_overrides_duplicate_json_command(self) -> None:
        result = run_custom_attack_compare(
            {
                "payload": "run explicit command",
                "tool": "code.run",
                "arguments": {"command": "printf WRONG"},
                "command": "printf RIGHT",
            }
        )
        self.assertEqual(result["tool_call"]["arguments"]["command"], "printf RIGHT")

    def test_invalid_execution_mode_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "execution_mode"):
            run_custom_attack_compare({"payload": "p", "tool": "file.read", "execution_mode": "host"})

    def test_external_receipt_mode_does_not_claim_server_execution(self) -> None:
        result = run_custom_attack_compare(
            {
                "payload": "real agent will execute after supervision",
                "tool": "file.read",
                "arguments": {"path": "public/项目说明.md"},
                "execution_mode": "external_receipt",
            }
        )
        self.assertFalse(result["environment_comparison"]["without_guard"]["executor_called"])
        self.assertFalse(result["summary"]["receipts_complete"])
        self.assertIsNone(result["receipts"]["without_guard"])
        self.assertTrue(result["summary"]["receipt_required"])
        self.assertEqual(result["with_guard"]["execution_status"], "awaiting_receipt")
        self.assertEqual(result["with_guard"]["audit_log"]["execution_status"], "not_executed")

    def test_external_receipts_can_be_submitted_and_refreshed_for_both_branches(self) -> None:
        with patch.dict("os.environ", {"AGENT_SUPERVISOR_AUTH_DISABLED": "true"}, clear=False), TestClient(app) as client:
            comparison_response = client.post(
                "/api/attack_lab/custom_compare",
                json={
                    "payload": "external agent executes after supervision",
                    "tool": "mail.send",
                    "arguments": {"to": "outside@example.com", "body": "payload"},
                    "agent_id": "external-receipt-agent",
                    "execution_mode": "external_receipt",
                },
            )
            self.assertEqual(comparison_response.status_code, 200)
            comparison = comparison_response.json()
            without_audit = comparison["audit"]["without_guard"]["audit_id"]
            guarded_audit = comparison["audit"]["with_guard"]["audit_id"]
            tool_call = comparison["tool_call"]

            without_response = client.post(
                f"/api/runtime/executions/{without_audit}/complete",
                json={
                    "receipt_id": f"{comparison['comparison_id']}-without",
                    "agent_id": "external-receipt-agent",
                    "tool_call": tool_call,
                    "status": "completed",
                    "execution_target": "real",
                    "result_hash": "a" * 64,
                    "duration_ms": 12,
                    "error": "",
                },
            )
            guarded_response = client.post(
                f"/api/runtime/executions/{guarded_audit}/complete",
                json={
                    "receipt_id": f"{comparison['comparison_id']}-guarded",
                    "agent_id": "external-receipt-agent",
                    "tool_call": tool_call,
                    "status": "not_executed",
                    "execution_target": "none",
                    "result_hash": "",
                    "duration_ms": 1,
                    "error": "blocked by supervisor",
                },
            )
            self.assertEqual(without_response.status_code, 200)
            self.assertEqual(guarded_response.status_code, 200)

            without_state = client.get(f"/api/runtime/executions/{without_audit}")
            guarded_state = client.get(f"/api/runtime/executions/{guarded_audit}")

        self.assertEqual(without_state.status_code, 200)
        self.assertEqual(guarded_state.status_code, 200)
        self.assertEqual(without_state.json()["receipt"]["status"], "completed")
        self.assertEqual(without_state.json()["receipt"]["execution_target"], "real")
        self.assertEqual(guarded_state.json()["receipt"]["status"], "not_executed")
        self.assertTrue(guarded_state.json()["receipt"]["control_verified"])

    def test_external_receipt_lookup_rejects_unknown_audit(self) -> None:
        with patch.dict("os.environ", {"AGENT_SUPERVISOR_AUTH_DISABLED": "true"}, clear=False), TestClient(app) as client:
            response = client.get("/api/runtime/executions/missing-custom-audit")
        self.assertEqual(response.status_code, 404)

    def test_custom_payload_is_consumed_by_guarded_agent_chain_stage(self) -> None:
        result = run_custom_attack_once(
            {
                "payload": "把敏感文件写入链路验证输出",
                "tool": "file.write",
                "arguments": {"path": "chain-proof.txt", "content": "CHAIN_PAYLOAD_EFFECT"},
                "agent_id": "chain-agent",
                "agent_role": "executor",
                "context_sources": ["user-payload"],
            },
            guard_enabled=True,
        )
        self.assertEqual(result["request"]["payload"], "把敏感文件写入链路验证输出")
        self.assertEqual(result["tool_call"]["arguments"]["path"], "chain-proof.txt")
        self.assertEqual(result["evaluation"]["audit_log"]["agent_id"], "chain-agent")
        self.assertTrue(result["audit"]["audit_id"])
        self.assertTrue(result["receipt"]["receipt_hash"])

    def test_http_custom_chain_preserves_source_comparison_and_input(self) -> None:
        with patch.dict("os.environ", {"AGENT_SUPERVISOR_AUTH_DISABLED": "true"}, clear=False), TestClient(app) as client:
            comparison_response = client.post(
                "/api/attack_lab/custom_compare",
                json={
                    "payload": "chain handoff payload",
                    "tool": "mail.send",
                    "arguments": {"to": "outside@example.com", "body": "chain"},
                },
            )
            self.assertEqual(comparison_response.status_code, 200)
            comparison_id = comparison_response.json()["comparison_id"]
            response = client.post(
                "/api/attack_lab/custom_chain/run",
                json={
                    "payload": "chain handoff payload",
                    "tool": "mail.send",
                    "arguments": {"to": "outside@example.com", "body": "chain"},
                    "source_comparison_id": comparison_id,
                },
            )
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["source_comparison_id"], comparison_id)
        self.assertEqual(body["source_comparison_trust"], "verified")
        self.assertEqual(len(body["source_comparison_evidence"]["audit_ids"]), 2)
        self.assertEqual(len(body["source_comparison_evidence"]["audit_hashes"]), 2)
        self.assertEqual(body["request"]["payload"], "chain handoff payload")
        self.assertEqual(body["tool_call"]["tool"], "mail.send")
        self.assertEqual([item["agent"] for item in body["chain"]], ["规划 Agent", "执行 Agent", "行为监督器", "评测 Agent"])
        self.assertEqual(body["summary"]["stage_count"], 4)
        self.assertTrue(body["summary"]["all_stages_audited"])
        self.assertTrue(body["summary"]["all_stages_receipted"])
        self.assertTrue(body["chain_integrity"]["same_payload"])
        self.assertTrue(body["chain_integrity"]["same_tool_call"])
        self.assertTrue(body["chain_integrity"]["shared_conversation_id"])
        self.assertEqual(len({item["agent_id"] for item in body["stages"]}), 4)
        self.assertEqual(sum(1 for item in body["stages"] if item["execution_attempted"]), 1)
        self.assertEqual(body["stages"][0]["stage_context"]["source"], "chain-input")
        self.assertEqual(body["stages"][1]["stage_context"]["source"], "planner")
        self.assertEqual(body["stages"][2]["stage_context"]["source"], "executor")
        self.assertEqual(body["stages"][3]["stage_context"]["source"], "behavior-supervisor")
        non_executor_stages = [item for item in body["stages"] if not item["execution_attempted"]]
        self.assertTrue(all(not item["environment"]["changed"] for item in non_executor_stages))
        self.assertGreaterEqual(
            body["stages"][-1]["evaluation"]["risk_evidence"]["cross_agent_chain"]["history_event_count"],
            3,
        )

    def test_custom_chain_rejects_unknown_or_changed_comparison_source(self) -> None:
        with patch.dict("os.environ", {"AGENT_SUPERVISOR_AUTH_DISABLED": "true"}, clear=False), TestClient(app) as client:
            unknown = client.post(
                "/api/attack_lab/custom_chain/run",
                json={
                    "payload": "payload",
                    "tool": "mail.send",
                    "arguments": {"to": "outside@example.com", "body": "chain"},
                    "source_comparison_id": "missing-comparison",
                },
            )
            comparison = client.post(
                "/api/attack_lab/custom_compare",
                json={
                    "payload": "original payload",
                    "tool": "mail.send",
                    "arguments": {"to": "outside@example.com", "body": "chain"},
                },
            ).json()
            changed = client.post(
                "/api/attack_lab/custom_chain/run",
                json={
                    "payload": "changed payload",
                    "tool": "mail.send",
                    "arguments": comparison["tool_call"]["arguments"],
                    "source_comparison_id": comparison["comparison_id"],
                },
            )
        self.assertEqual(unknown.status_code, 400)
        self.assertEqual(changed.status_code, 400)

    def test_custom_chain_artifacts_form_a_verified_dependency_chain(self) -> None:
        result = run_custom_attack_chain(
            {
                "payload": "write current payload to the sandbox fixture",
                "tool": "file.write",
                "arguments": {"path": "chain-observed.txt", "content": "CHAIN_EFFECT"},
            },
            guard_enabled=False,
        )
        stages = result["stages"]
        self.assertEqual(
            [stage["artifact"]["artifact_type"] for stage in stages],
            ["execution-plan", "execution-evidence", "supervisor-verdict", "evaluation-summary"],
        )
        self.assertTrue(all(_verify_chain_artifact(stage["artifact"]) for stage in stages))
        self.assertTrue(_verify_chain_artifacts(stages))
        planner, executor, supervisor, evaluator = [stage["artifact"] for stage in stages]
        self.assertEqual(executor["input_artifact_hashes"], [planner["artifact_hash"]])
        self.assertEqual(executor["data"]["consumed_plan_hash"], planner["artifact_hash"])
        self.assertEqual(
            executor["data"]["actual_tool_call_hash"],
            planner["data"]["planned_tool_call_hash"],
        )
        self.assertEqual(supervisor["input_artifact_hashes"], [executor["artifact_hash"]])
        self.assertEqual(supervisor["data"]["consumed_execution_hash"], executor["artifact_hash"])
        self.assertEqual(
            evaluator["input_artifact_hashes"],
            [planner["artifact_hash"], executor["artifact_hash"], supervisor["artifact_hash"]],
        )
        self.assertTrue(result["chain_integrity"]["artifact_hashes_valid"])
        self.assertTrue(result["chain_integrity"]["artifact_chain_valid"])
        self.assertTrue(executor["data"]["effect_observed"])
        self.assertFalse(executor["data"]["attack_success"])
        self.assertEqual(result["summary"]["final_outcome"], "side_effect_only")
        self.assertTrue(result["summary"]["evidence_complete"])

    def test_custom_chain_artifact_tampering_breaks_integrity(self) -> None:
        result = run_custom_attack_chain(
            {
                "payload": "send fixture message",
                "tool": "mail.send",
                "arguments": {"to": "outside@example.com", "body": "chain"},
            },
            guard_enabled=True,
        )
        tampered = [deepcopy(stage) for stage in result["stages"]]
        tampered[0]["artifact"]["data"]["planned_tool_call"]["arguments"]["to"] = "changed@example.com"
        self.assertFalse(_verify_chain_artifact(tampered[0]["artifact"]))
        self.assertFalse(_verify_chain_artifacts(tampered))

    @patch("apps.api.agent_supervisor.domains.runtime.tools._run_wsl_isolated_command", return_value=None)
    @patch("apps.api.agent_supervisor.domains.runtime.tools.shutil.which")
    def test_unavailable_isolation_executors_are_reported_as_not_executed(self, which, _wsl) -> None:
        which.side_effect = lambda name: "docker" if name == "docker" else None
        unavailable = type("Result", (), {"returncode": 1, "stdout": "", "stderr": "daemon offline"})()
        with patch("apps.api.agent_supervisor.domains.runtime.tools.subprocess.run", return_value=unavailable):
            result = run_custom_attack_compare(
                {
                    "payload": "run caller command",
                    "tool": "code.run",
                    "command": "printf custom-output",
                }
            )
        tool_output = result["without_guard"]["audit_log"]["tool_output"]
        self.assertFalse(tool_output["executed"])
        self.assertEqual(tool_output["executor"], "unavailable")
        self.assertIn("WSL 降级执行默认关闭", tool_output["output"])
        self.assertFalse(result["summary"]["exposed_without_guard"])

    @patch("apps.api.agent_supervisor.domains.runtime.tools.shutil.which")
    @patch("apps.api.agent_supervisor.domains.runtime.tools.subprocess.run")
    def test_wsl_namespace_fallback_executes_when_docker_is_offline(self, run, which) -> None:
        which.side_effect = lambda name: name
        run.side_effect = [
            type("Result", (), {"returncode": 1, "stdout": "", "stderr": "daemon offline"})(),
            type("Result", (), {"returncode": 0, "stdout": "wsl-output", "stderr": ""})(),
            type("Result", (), {"returncode": 1, "stdout": "", "stderr": "daemon offline"})(),
            type("Result", (), {"returncode": 0, "stdout": "wsl-output", "stderr": ""})(),
        ]
        with patch.dict(
            "os.environ",
            {
                "AGENT_SUPERVISOR_COMMAND_ALLOW_WSL_FALLBACK": "true",
                "AGENT_SUPERVISOR_SECURITY_PROFILE": "local",
            },
            clear=False,
        ):
            result = run_custom_attack_compare(
                {"payload": "run caller command", "tool": "code.run", "command": "printf wsl-output"}
            )
        output = result["without_guard"]["audit_log"]["tool_output"]
        self.assertTrue(output["executed"])
        self.assertEqual(output["executor"], "wsl2-unshare")
        self.assertEqual(output["execution_target"], "wsl-namespace")
        self.assertEqual(output["output"], "wsl-output")
        wsl_args = run.call_args_list[1].args[0]
        self.assertIn("unshare", wsl_args)
        self.assertIn("--net", wsl_args)
        self.assertTrue(result["summary"]["exposed_without_guard"])

    @patch("apps.api.agent_supervisor.domains.runtime.tools.subprocess.run")
    def test_wsl_transient_start_failure_is_retried(self, run) -> None:
        run.side_effect = [
            type("Result", (), {"returncode": 4294967295, "stdout": "", "stderr": ""})(),
            type("Result", (), {"returncode": 0, "stdout": "retry-ok", "stderr": ""})(),
        ]
        from apps.api.agent_supervisor.domains.runtime.tools import _run_wsl_process

        completed = _run_wsl_process(["wsl", "--", "printf", "retry-ok"])

        self.assertIsNotNone(completed)
        self.assertEqual(getattr(completed, "returncode", None), 0)
        self.assertEqual(run.call_count, 2)

    @patch("apps.api.agent_supervisor.domains.runtime.tools.subprocess.run")
    def test_persistent_wsl_launcher_failure_is_not_reported_as_execution(self, run) -> None:
        run.return_value = type("Result", (), {"returncode": 4294967295, "stdout": "", "stderr": ""})()
        from pathlib import Path

        from apps.api.agent_supervisor.domains.runtime.tools import SandboxPaths, _run_wsl_isolated_command

        root = Path("C:/fixture-wsl-failure")
        with (
            patch.dict(
                "os.environ",
                {
                    "AGENT_SUPERVISOR_COMMAND_ALLOW_WSL_FALLBACK": "true",
                    "AGENT_SUPERVISOR_SECURITY_PROFILE": "local",
                },
                clear=False,
            ),
            patch("apps.api.agent_supervisor.domains.runtime.tools.shutil.which", return_value="wsl"),
        ):
            output = _run_wsl_isolated_command(
                "printf never-started",
                SandboxPaths(root / "workspace", root / "outbox", root / "memory", root / "fixtures"),
            )

        self.assertIsNotNone(output)
        assert output is not None
        self.assertFalse(output["executed"])
        self.assertEqual(output["executor"], "unavailable")
        self.assertEqual(run.call_count, 3)

    @patch("apps.api.agent_supervisor.domains.attacks.attack_lab.complete_execution")
    def test_timeout_or_nonzero_exit_creates_failed_receipt(self, complete) -> None:
        complete.return_value = {"receipt": {"status": "failed", "receipt_hash": "hash"}}
        result = {
            "audit_id": "audit-timeout",
            "run_id": "run-timeout",
            "audit_log": {
                "tool_output": {
                    "executed": True,
                    "sandboxed": True,
                    "timed_out": True,
                    "exit_code": None,
                    "output": "命令超时",
                }
            },
        }

        receipt = _record_server_execution_receipt(
            result,
            {"tool": "code.run", "arguments": {"command": "printf slow"}},
            "receipt-agent",
        )

        request = complete.call_args.args[1]
        self.assertEqual(request["status"], "failed")
        self.assertEqual(request["execution_target"], "sandbox")
        self.assertEqual(request["error"], "命令超时")
        self.assertEqual(receipt["status"], "failed")

    def test_unavailable_executor_is_not_reported_as_completed_in_audit(self) -> None:
        from apps.api.agent_supervisor.domains.runtime import events as runtime_events
        from apps.api.agent_supervisor.domains.runtime.events import evaluate_agent_event

        unavailable = {
            "executed": False,
            "sandboxed": True,
            "executor": "unavailable",
            "execution_target": "none",
            "output": "隔离执行器不可用",
        }
        with patch.object(runtime_events, "execute_tool", return_value=unavailable):
            result = evaluate_agent_event(
                {
                    "conversation_id": "unavailable-audit",
                    "agent_id": "unavailable-agent",
                    "model_input": "run command",
                    "tool_call": {"tool": "code.run", "arguments": {"command": "printf x"}},
                    "execute_in_sandbox": True,
                },
                guard_enabled=False,
                execute_in_sandbox=True,
                review_scope="experiment",
            )
        self.assertEqual(result["audit_log"]["execution_status"], "not_executed")
        self.assertEqual(result["audit_log"]["execution_target"], "none")

    def test_server_receipt_uses_measured_duration_and_raw_result_hash(self) -> None:
        from unittest.mock import patch

        with patch("apps.api.agent_supervisor.domains.attacks.attack_lab.complete_execution") as complete:
            complete.return_value = {"receipt": {"status": "completed", "receipt_hash": "hash"}}
            result = {
                "audit_id": "audit-raw",
                "run_id": "run-raw",
                "execution_duration_ms": 12.5,
                "execution_result_hash": "b" * 64,
                "audit_log": {"tool_output": {"executed": True, "output": "<redacted>"}},
            }
            _record_server_execution_receipt(
                result,
                {"tool": "file.read", "arguments": {"path": "public/a"}},
                "receipt-agent",
            )
            request = complete.call_args.args[1]
            self.assertEqual(request["duration_ms"], 12.5)
            self.assertEqual(request["result_hash"], "b" * 64)

    @patch("apps.api.agent_supervisor.domains.runtime.tools.shutil.which", return_value="docker")
    @patch("apps.api.agent_supervisor.domains.runtime.tools.subprocess.run")
    def test_arbitrary_command_uses_ephemeral_container_and_returns_output(self, run, _which) -> None:
        run.side_effect = [
            type("Result", (), {"returncode": 0, "stdout": "29.0", "stderr": ""})(),
            type("Result", (), {"returncode": 0, "stdout": "custom-output", "stderr": ""})(),
            type("Result", (), {"returncode": 0, "stdout": "29.0", "stderr": ""})(),
            type("Result", (), {"returncode": 0, "stdout": "custom-output", "stderr": ""})(),
        ]
        result = run_custom_attack_compare(
            {
                "payload": "run caller command",
                "tool": "code.run",
                "command": "printf custom-output",
            }
        )
        tool_output = result["without_guard"]["audit_log"]["tool_output"]
        self.assertTrue(tool_output["executed"])
        self.assertEqual(tool_output["executor"], "docker-ephemeral")
        self.assertEqual(tool_output["exit_code"], 0)
        self.assertEqual(tool_output["output"], "custom-output")
        docker_args = run.call_args_list[1].args[0]
        self.assertIn("--network", docker_args)
        self.assertIn("--pull", docker_args)
        self.assertIn("never", docker_args)
        self.assertIn("none", docker_args)
        self.assertIn("--read-only", docker_args)
        self.assertIn("no-new-privileges", docker_args)
        self.assertEqual(docker_args[-1], "printf custom-output")
        self.assertTrue(result["summary"]["exposed_without_guard"])

    @patch("apps.api.agent_supervisor.domains.runtime.tools.shutil.which", return_value="docker")
    @patch("apps.api.agent_supervisor.domains.runtime.tools.subprocess.run")
    def test_docker_daemon_run_failure_is_not_reported_as_execution(self, run, _which) -> None:
        run.side_effect = [
            type("Result", (), {"returncode": 0, "stdout": "29.0", "stderr": ""})(),
            type(
                "Result",
                (),
                {
                    "returncode": 125,
                    "stdout": "",
                    "stderr": "docker: Error response from daemon: No such image: python:3.12-alpine",
                },
            )(),
            type("Result", (), {"returncode": 0, "stdout": "29.0", "stderr": ""})(),
            type(
                "Result",
                (),
                {
                    "returncode": 125,
                    "stdout": "",
                    "stderr": "docker: Error response from daemon: No such image: python:3.12-alpine",
                },
            )(),
        ]
        result = run_custom_attack_compare(
            {
                "payload": "run caller command",
                "tool": "code.run",
                "command": "printf custom-output",
            }
        )

        tool_output = result["without_guard"]["audit_log"]["tool_output"]
        self.assertFalse(tool_output["executed"])
        self.assertEqual(tool_output["executor"], "unavailable")
        self.assertIsNone(tool_output["exit_code"])
        self.assertEqual(result["receipts"]["without_guard"]["status"], "not_executed")
        self.assertFalse(result["summary"]["exposed_without_guard"])


if __name__ == "__main__":
    unittest.main()
