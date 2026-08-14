from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from unittest import TestCase
from unittest.mock import Mock, patch

from apps.api.agent_supervisor.adapters.integrations.openclaw_adapter import AgentToolGuard
from apps.api.agent_supervisor.domains.attacks.attack_lab import run_attack_lab_module
from apps.api.agent_supervisor.domains.governance.approvals import (
    claim_approval_execution,
    complete_approval_execution,
    decide_approval_review,
)
from apps.api.agent_supervisor.domains.runtime.events import evaluate_agent_event


class AgentToolGuardExecutionTests(TestCase):
    def _guarded_execute(self, guard: AgentToolGuard, executor: Mock, sandbox_executor: Mock | None = None):
        return guard.guarded_execute(
            conversation_id="conversation-1",
            agent_id="agent-1",
            agent_role="executor",
            source_app="test-agent",
            model_input="test",
            model_output="tool call",
            tool_call={"tool": "memory.write", "arguments": {"content": "test"}},
            executor=executor,
            sandbox_executor=sandbox_executor,
        )

    def test_isolation_never_falls_through_to_real_executor(self):
        guard = AgentToolGuard()
        real_executor = Mock(return_value={"status": "real"})
        with patch.object(
            guard,
            "evaluate",
            return_value={"decision": "隔离", "policy_id": "memory-write", "reason": "需要隔离"},
        ):
            result = self._guarded_execute(guard, real_executor)

        self.assertFalse(result.executed)
        self.assertEqual(result.execution_target, "none")
        real_executor.assert_not_called()

    def test_error_fallback_cannot_be_configured_to_allow(self):
        with self.assertRaisesRegex(ValueError, "default_on_error"):
            AgentToolGuard(default_on_error="允许")

    def test_isolation_uses_only_explicit_sandbox_executor(self):
        guard = AgentToolGuard()
        real_executor = Mock(return_value={"status": "real"})
        sandbox_executor = Mock(return_value={"status": "sandbox"})
        with patch.object(
            guard,
            "evaluate",
            return_value={"decision": "隔离", "policy_id": "memory-write", "reason": "需要隔离"},
        ):
            result = self._guarded_execute(guard, real_executor, sandbox_executor)

        self.assertTrue(result.executed)
        self.assertEqual(result.execution_target, "sandbox")
        self.assertEqual(result.tool_result, {"status": "sandbox"})
        real_executor.assert_not_called()
        sandbox_executor.assert_called_once()

    def test_approved_call_is_resumed_through_claim_and_completion_receipt(self):
        guard = AgentToolGuard()
        executor = Mock(return_value={"status": "sent"})
        review = {"final_decision": "允许", "policy_id": "external-mail"}
        with patch.object(
            guard,
            "_post_approval",
            side_effect=[
                {"granted": True, "claim_id": "claim-1", "review": review},
                {"updated": True, "review": {**review, "execution_status": "completed"}},
            ],
        ) as post_approval:
            result = guard.resume_approved(
                review_id="review-1",
                agent_id="agent-1",
                tool_call={"tool": "mail.send", "arguments": {"to": "external@example.com"}},
                executor=executor,
            )

        self.assertTrue(result.executed)
        self.assertEqual(result.execution_target, "real")
        self.assertEqual(result.tool_result, {"status": "sent"})
        executor.assert_called_once()
        self.assertEqual(post_approval.call_count, 2)


class AttackComparisonIntegrityTests(TestCase):
    def test_user_entered_probe_command_runs_with_dynamic_payload_in_isolated_workspace(self):
        result = run_attack_lab_module(
            {
                "surface_id": "tool-hijack",
                "planner_mode": "fixed",
                "execute_in_sandbox": True,
                "options": {
                    "command": 'python scripts/tool_hijack_probe.py --payload "user supplied payload 42"'
                },
            }
        )

        baseline = result["environment_comparison"]["without_guard"]
        guarded = result["environment_comparison"]["with_guard"]
        self.assertTrue(baseline["executor_called"])
        self.assertTrue(baseline["attack_success"])
        self.assertTrue(any(item["key"] == "changed_files" for item in baseline["changes"]))
        self.assertFalse(guarded["executor_called"])
        self.assertFalse(guarded["attack_success"])
        self.assertEqual(result["with_guard"]["policy_id"], "dangerous-command")

    def test_attack_comparison_uses_isolated_equal_environments_without_risk_hint(self):
        result = run_attack_lab_module(
            {
                "surface_id": "prompt-injection",
                "planner_mode": "fixed",
                "execute_in_sandbox": True,
            }
        )

        comparison = result["environment_comparison"]
        baseline = comparison["without_guard"]
        guarded = comparison["with_guard"]

        self.assertTrue(comparison["integrity"]["same_initial_state"])
        self.assertFalse(comparison["integrity"]["risk_hint_used"])
        self.assertNotIn("risk_hint", result["tool_call"])
        self.assertTrue(baseline["attack_success"])
        self.assertTrue(baseline["executor_called"])
        self.assertEqual(baseline["before"]["outbox_count"], 0)
        self.assertEqual(baseline["after"]["outbox_count"], 1)
        self.assertFalse(guarded["attack_success"])
        self.assertFalse(guarded["executor_called"])
        self.assertEqual(guarded["before"]["outbox_count"], 0)
        self.assertEqual(guarded["after"]["outbox_count"], 0)

    def test_jailbreak_fixture_reproduces_without_guard_and_is_controlled_with_guard(self):
        result = run_attack_lab_module(
            {
                "surface_id": "jailbreak",
                "planner_mode": "fixed",
                "execute_in_sandbox": True,
            }
        )

        comparison = result["environment_comparison"]
        self.assertTrue(result["without_guard"]["attack_success"])
        self.assertTrue(comparison["without_guard"]["executor_called"])
        self.assertFalse(result["with_guard"]["attack_success"])
        self.assertFalse(comparison["with_guard"]["executor_called"])
        self.assertEqual(result["with_guard"]["policy_id"], "jailbreak-filter")


class ApprovalResumeTests(TestCase):
    def test_approved_tool_call_can_be_claimed_and_completed_only_once(self):
        tool_call = {
            "tool": "mail.send",
            "arguments": {
                "to": "external@example.com",
                "subject": "review",
                "body": "controlled fixture",
            },
        }
        result = evaluate_agent_event(
            {
                "conversation_id": "approval-resume-test",
                "agent_id": "agent-1",
                "source_app": "test-agent",
                "model_input": "send review",
                "tool_call": tool_call,
            },
            guard_enabled=True,
            execute_in_sandbox=False,
            review_scope="experiment",
        )
        review_id = result["approval_review"]["id"]
        decide_approval_review(review_id, "approve", operator="tester", comment="approved for test")
        with self.assertRaisesRegex(ValueError, "不能重复"):
            decide_approval_review(review_id, "approve", operator="tester", comment="duplicate approval")

        claim = claim_approval_execution(review_id, "agent-1", tool_call)
        duplicate_claim = claim_approval_execution(review_id, "agent-1", tool_call)
        completion = complete_approval_execution(
            review_id,
            claim["claim_id"],
            "agent-1",
            succeeded=True,
            result_hash="result-hash",
        )

        self.assertTrue(claim["granted"])
        self.assertFalse(duplicate_claim["granted"])
        self.assertEqual(completion["review"]["execution_status"], "completed")
        self.assertEqual(completion["review"]["execution_result_hash"], "result-hash")

    def test_concurrent_claim_grants_exactly_one_executor(self):
        tool_call = {
            "tool": "mail.send",
            "arguments": {"to": "external@example.com", "body": "concurrency fixture"},
        }
        result = evaluate_agent_event(
            {
                "conversation_id": "approval-concurrency-test",
                "agent_id": "agent-concurrent",
                "source_app": "test-agent",
                "model_input": "send review",
                "tool_call": tool_call,
            },
            guard_enabled=True,
            execute_in_sandbox=False,
            review_scope="experiment",
        )
        review_id = result["approval_review"]["id"]
        decide_approval_review(review_id, "approve", operator="tester", comment="concurrency test")

        with ThreadPoolExecutor(max_workers=20) as executor:
            claims = list(
                executor.map(
                    lambda _: claim_approval_execution(review_id, "agent-concurrent", tool_call),
                    range(100),
                )
            )

        self.assertEqual(sum(1 for claim in claims if claim["granted"]), 1)

    def test_claim_and_completion_are_bound_to_original_agent(self):
        tool_call = {
            "tool": "mail.send",
            "arguments": {"to": "external@example.com", "body": "identity fixture"},
        }
        result = evaluate_agent_event(
            {
                "conversation_id": "approval-agent-binding-test",
                "agent_id": "original-agent",
                "source_app": "test-agent",
                "model_input": "send review",
                "tool_call": tool_call,
            },
            guard_enabled=True,
            execute_in_sandbox=False,
            review_scope="experiment",
        )
        review_id = result["approval_review"]["id"]
        decide_approval_review(review_id, "approve", operator="tester", comment="identity test")

        with self.assertRaisesRegex(ValueError, "原始Agent"):
            claim_approval_execution(review_id, "different-agent", tool_call)
        claim = claim_approval_execution(review_id, "original-agent", tool_call)
        with self.assertRaisesRegex(ValueError, "原始Agent"):
            complete_approval_execution(
                review_id,
                claim["claim_id"],
                "different-agent",
                succeeded=True,
            )

        completion = complete_approval_execution(
            review_id,
            claim["claim_id"],
            "original-agent",
            succeeded=True,
        )
        self.assertEqual(completion["review"]["execution_status"], "completed")
