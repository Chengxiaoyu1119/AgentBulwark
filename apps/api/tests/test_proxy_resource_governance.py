from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from apps.api.agent_supervisor.adapters.proxy.openai_proxy import run_openai_proxy_completion
from apps.api.agent_supervisor.adapters.proxy.resource_governance import (
    ProxyResourceLimitError,
    acquire_resource_lease,
    estimate_request_plan,
    reset_resource_governance,
    resource_snapshot,
)
from apps.api.agent_supervisor.main import app
from apps.api.agent_supervisor.storage.database import load_audit_log

_MULTI_PROCESS_SCRIPT = r'''
import json
import os
import sys
from apps.api.agent_supervisor.adapters.proxy.resource_governance import acquire_resource_lease, estimate_request_plan

plan = estimate_request_plan({"model": "fixture", "messages": [{"role": "user", "content": "x"}], "max_tokens": 1}, agent_id="shared-process-agent")
try:
    lease = acquire_resource_lease(plan)
except Exception as exc:
    print(json.dumps({"ok": False, "error": type(exc).__name__, "resource": getattr(exc, "resource", "")}), flush=True)
    raise SystemExit(0)
print(json.dumps({"ok": True, "lease_id": lease.lease_id}), flush=True)
input()
'''


class ProxyResourceGovernanceTests(unittest.TestCase):
    ENV_KEYS = {
        "AGENT_SUPERVISOR_PROXY_RESOURCE_GOVERNANCE_ENABLED",
        "AGENT_SUPERVISOR_PROXY_MAX_CONCURRENCY_PER_AGENT",
        "AGENT_SUPERVISOR_PROXY_TOKEN_BUDGET_PER_MINUTE",
        "AGENT_SUPERVISOR_PROXY_COST_BUDGET_PER_MINUTE_USD",
        "AGENT_SUPERVISOR_PROXY_DEFAULT_OUTPUT_TOKENS",
        "AGENT_SUPERVISOR_PROXY_MANAGED_CONTEXT_TOKENS",
        "AGENT_SUPERVISOR_PROXY_INPUT_COST_PER_1K_USD",
        "AGENT_SUPERVISOR_PROXY_OUTPUT_COST_PER_1K_USD",
        "AGENT_SUPERVISOR_AUTH_DISABLED",
        "AGENT_SUPERVISOR_AGENT_TOKENS_JSON",
        "AGENT_SUPERVISOR_PROXY_RATE_LIMIT_PER_MINUTE",
    }

    def setUp(self) -> None:
        self._env = {key: os.environ.get(key) for key in self.ENV_KEYS}
        reset_resource_governance()

    def tearDown(self) -> None:
        for key, value in self._env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        reset_resource_governance()

    def test_managed_plan_reserves_every_possible_provider_round(self) -> None:
        plan = estimate_request_plan(
            {
                "model": "fixture-model",
                "messages": [{"role": "user", "content": "hello"}],
                "n": 2,
                "max_tokens": 10,
            },
            agent_id="agent-managed",
            mode="managed",
            managed_rounds=3,
        )

        self.assertEqual(plan.provider_calls, 4)
        self.assertEqual(plan.completions, 2)
        self.assertEqual(plan.output_tokens_per_completion, 10)
        self.assertGreaterEqual(plan.estimated_tokens, 4 * 2 * 10)

    def test_max_output_tokens_participates_in_resource_reservation(self) -> None:
        plan = estimate_request_plan(
            {
                "model": "fixture-model",
                "messages": [{"role": "user", "content": "hello"}],
                "max_output_tokens": 321,
            },
            agent_id="agent-output-limit",
        )

        self.assertEqual(plan.output_tokens_per_completion, 321)

    def test_concurrency_rejection_is_atomic_and_releases_after_settle(self) -> None:
        os.environ["AGENT_SUPERVISOR_PROXY_MAX_CONCURRENCY_PER_AGENT"] = "1"
        plan = estimate_request_plan(
            {"model": "fixture", "messages": [{"role": "user", "content": "x"}]},
            agent_id="agent-concurrency",
        )
        first = acquire_resource_lease(plan)
        with self.assertRaises(ProxyResourceLimitError) as context:
            acquire_resource_lease(plan)
        self.assertEqual(context.exception.resource, "concurrency")
        self.assertEqual(resource_snapshot("agent-concurrency")["in_flight"], 1)
        first.settle(actual_tokens=1, provider_called=True)
        second = acquire_resource_lease(plan)
        second.settle(actual_tokens=0, provider_called=False)
        self.assertEqual(resource_snapshot("agent-concurrency")["in_flight"], 0)

    def test_token_budget_rejection_creates_provider_not_called_audit(self) -> None:
        os.environ["AGENT_SUPERVISOR_PROXY_TOKEN_BUDGET_PER_MINUTE"] = "15"
        os.environ["AGENT_SUPERVISOR_PROXY_DEFAULT_OUTPUT_TOKENS"] = "4"
        payload = {
            "model": "fixture-model",
            "messages": [{"role": "user", "content": "hello"}],
        }
        context = {"role": "executor", "agent_id": "budget-agent", "session_id": "budget-session"}
        provider_response = {
            "response": {
                "id": "budget-response",
                "object": "chat.completion",
                "created": 1,
                "model": "fixture-model",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}],
                "usage": {"total_tokens": 5},
            },
            "provider": "fixture-provider",
            "model": "fixture-model",
            "mode": "real-api",
            "request_hash": "a" * 64,
            "provider_response_hash": "b" * 64,
            "provider_response_id": "budget-response",
            "provider_failures": [],
        }
        with patch(
            "apps.api.agent_supervisor.adapters.proxy.openai_proxy.forward_openai_chat_completion",
            return_value=provider_response,
        ) as forward:
            run_openai_proxy_completion(payload, security_context=context)
            with self.assertRaises(ProxyResourceLimitError) as error:
                run_openai_proxy_completion(payload, security_context=context)

        self.assertEqual(forward.call_count, 1)
        self.assertEqual(error.exception.resource, "token-budget")
        self.assertTrue(error.exception.audit_id)
        audit = load_audit_log(error.exception.audit_id)
        self.assertIsNotNone(audit)
        assert audit is not None
        self.assertEqual(audit["decision"], "拒绝")
        self.assertEqual(audit["policy_id"], "resource-governance")
        self.assertEqual(audit["execution_evidence"], "server-observed")
        self.assertTrue(audit["execution_observed_by_server"])
        self.assertFalse(audit["stage_context"]["provider_called"])

    def test_provider_exception_does_not_leave_concurrency_lease_stuck(self) -> None:
        os.environ["AGENT_SUPERVISOR_PROXY_MAX_CONCURRENCY_PER_AGENT"] = "1"
        plan = estimate_request_plan(
            {"model": "fixture", "messages": [{"role": "user", "content": "x"}]},
            agent_id="agent-release",
        )
        lease = acquire_resource_lease(plan)
        lease.settle(actual_tokens=None, provider_called=True)
        recovered = acquire_resource_lease(plan)
        recovered.settle(actual_tokens=0, provider_called=False)
        self.assertEqual(resource_snapshot("agent-release")["in_flight"], 0)

    def test_cost_budget_charges_measured_usage_when_provider_omits_price(self) -> None:
        os.environ["AGENT_SUPERVISOR_PROXY_COST_BUDGET_PER_MINUTE_USD"] = "0.02"
        os.environ["AGENT_SUPERVISOR_PROXY_INPUT_COST_PER_1K_USD"] = "1"
        os.environ["AGENT_SUPERVISOR_PROXY_OUTPUT_COST_PER_1K_USD"] = "1"
        plan = estimate_request_plan(
            {
                "model": "fixture",
                "messages": [{"role": "user", "content": "hello"}],
                "max_tokens": 4,
            },
            agent_id="agent-cost",
        )
        first = acquire_resource_lease(plan)
        settlement = first.settle(actual_tokens=plan.estimated_tokens, provider_called=True)
        self.assertGreater(settlement["charged_cost_usd"], 0)
        with self.assertRaises(ProxyResourceLimitError) as context:
            acquire_resource_lease(plan)
        self.assertEqual(context.exception.resource, "cost-budget")

    def test_cost_budget_fails_closed_without_unit_prices(self) -> None:
        os.environ["AGENT_SUPERVISOR_PROXY_COST_BUDGET_PER_MINUTE_USD"] = "1"
        plan = estimate_request_plan(
            {"model": "fixture", "messages": [{"role": "user", "content": "hello"}]},
            agent_id="agent-unpriced",
        )
        with self.assertRaises(ProxyResourceLimitError) as context:
            acquire_resource_lease(plan)
        self.assertEqual(context.exception.resource, "cost-pricing")

    def test_http_route_returns_429_and_audit_when_resource_lease_is_rejected(self) -> None:
        os.environ["AGENT_SUPERVISOR_AUTH_DISABLED"] = "false"
        os.environ["AGENT_SUPERVISOR_AGENT_TOKENS_JSON"] = '{"http-budget-agent":"http-budget-token"}'
        os.environ["AGENT_SUPERVISOR_PROXY_RATE_LIMIT_PER_MINUTE"] = "0"
        os.environ["AGENT_SUPERVISOR_PROXY_TOKEN_BUDGET_PER_MINUTE"] = "15"
        os.environ["AGENT_SUPERVISOR_PROXY_DEFAULT_OUTPUT_TOKENS"] = "4"
        payload = {
            "model": "fixture-model",
            "messages": [{"role": "user", "content": "hello"}],
        }
        provider_response = {
            "response": {
                "id": "http-budget-response",
                "object": "chat.completion",
                "created": 1,
                "model": "fixture-model",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}],
                "usage": {"total_tokens": 5},
            },
            "provider": "fixture-provider",
            "model": "fixture-model",
            "mode": "real-api",
            "request_hash": "a" * 64,
            "provider_response_hash": "b" * 64,
            "provider_response_id": "http-budget-response",
            "provider_failures": [],
        }
        with patch(
            "apps.api.agent_supervisor.adapters.proxy.openai_proxy.forward_openai_chat_completion",
            return_value=provider_response,
        ) as forward:
            with TestClient(app) as client:
                headers = {"Authorization": "Bearer http-budget-token"}
                self.assertEqual(client.post("/v1/chat/completions", json=payload, headers=headers).status_code, 200)
                response = client.post("/v1/chat/completions", json=payload, headers=headers)

        self.assertEqual(response.status_code, 429)
        detail = response.json()["detail"]
        self.assertEqual(detail["resource"], "token-budget")
        self.assertFalse(detail["provider_called"])
        self.assertTrue(detail["audit_id"])
        self.assertEqual(forward.call_count, 1)

    def test_managed_budget_rejection_happens_before_first_round(self) -> None:
        os.environ["AGENT_SUPERVISOR_PROXY_TOKEN_BUDGET_PER_MINUTE"] = "20"
        os.environ["AGENT_SUPERVISOR_PROXY_DEFAULT_OUTPUT_TOKENS"] = "4"
        payload = {
            "model": "fixture-model",
            "messages": [{"role": "user", "content": "hello"}],
            "agent_supervisor": {"mode": "managed", "max_tool_rounds": 3},
        }
        context = {"role": "executor", "agent_id": "managed-budget-agent", "session_id": "managed-budget-session"}
        with patch(
            "apps.api.agent_supervisor.adapters.proxy.openai_proxy.forward_openai_chat_completion"
        ) as forward:
            with self.assertRaises(ProxyResourceLimitError) as error:
                run_openai_proxy_completion(payload, security_context=context)

        self.assertEqual(error.exception.resource, "token-budget")
        plan = error.exception.plan
        self.assertIsNotNone(plan)
        assert plan is not None
        self.assertEqual(plan.provider_calls, 4)
        self.assertGreater(plan.estimated_tokens, 20)
        forward.assert_not_called()

    def test_pre_provider_model_policy_rejection_does_not_charge_provider_quota(self) -> None:
        os.environ["AGENT_SUPERVISOR_PROXY_TOKEN_BUDGET_PER_MINUTE"] = "10000"
        os.environ["AGENT_SUPERVISOR_PROXY_DEFAULT_OUTPUT_TOKENS"] = "32"
        payload = {
            "model": "unregistered-model",
            "messages": [{"role": "user", "content": "hello"}],
        }
        context = {"role": "executor", "agent_id": "quota-policy-agent", "session_id": "quota-policy-session"}
        settings = {
            "require_agent_model_registration": True,
            "agent_model_allowlists": {},
            "require_agent_capability_registration": False,
            "require_agent_context_registration": False,
        }
        with (
            patch("apps.api.agent_supervisor.adapters.proxy.openai_proxy.get_policy_settings", return_value=settings),
            patch("apps.api.agent_supervisor.adapters.proxy.openai_proxy.forward_openai_chat_completion") as forward,
            self.assertRaisesRegex(ValueError, "未登记可用模型"),
        ):
            run_openai_proxy_completion(payload, security_context=context)

        snapshot = resource_snapshot("quota-policy-agent")
        self.assertEqual(snapshot["in_flight"], 0)
        self.assertEqual(snapshot["reserved_tokens"], 0)
        self.assertEqual(snapshot["consumed_tokens"], 0)
        forward.assert_not_called()

    def test_sqlite_shared_lease_is_atomic_across_worker_processes(self) -> None:
        os.environ["AGENT_SUPERVISOR_PROXY_MAX_CONCURRENCY_PER_AGENT"] = "1"
        os.environ["AGENT_SUPERVISOR_PROXY_TOKEN_BUDGET_PER_MINUTE"] = "100000"
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8") as handle:
            handle.write(_MULTI_PROCESS_SCRIPT)
            script_path = handle.name
        processes: list[subprocess.Popen[str]] = []
        try:
            for _ in range(2):
                child_env = os.environ.copy()
                child_env["PYTHONPATH"] = os.getcwd()
                processes.append(
                    subprocess.Popen(
                        [sys.executable, "-X", "utf8", script_path],
                        cwd=os.getcwd(),
                        env=child_env,
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                )
            outputs = []
            for process in processes:
                stdout, stderr = process.communicate("", timeout=15)
                outputs.append((stdout.strip(), stderr.strip()))
            self.assertTrue(all(stdout for stdout, _stderr in outputs), outputs)
            successes = [json.loads(stdout) for stdout, _stderr in outputs]
            self.assertEqual(sum(bool(item.get("ok")) for item in successes), 1, outputs)
            rejected = [item for item in successes if not item.get("ok")]
            self.assertEqual(rejected[0].get("resource"), "concurrency", outputs)
        finally:
            for process in processes:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)
            try:
                os.unlink(script_path)
            except OSError:
                pass

    def test_expired_shared_lease_is_reclaimed(self) -> None:
        os.environ["AGENT_SUPERVISOR_PROXY_MAX_CONCURRENCY_PER_AGENT"] = "1"
        os.environ["AGENT_SUPERVISOR_PROXY_RESOURCE_LEASE_TTL_SECONDS"] = "10"
        plan = estimate_request_plan(
            {"model": "fixture", "messages": [{"role": "user", "content": "x"}]},
            agent_id="agent-expiry",
        )
        first = acquire_resource_lease(plan)
        with patch("apps.api.agent_supervisor.adapters.proxy.resource_governance.time", return_value=first.acquired_at + 11):
            second = acquire_resource_lease(plan)
        self.assertNotEqual(first.lease_id, second.lease_id)
        second.settle(actual_tokens=0, provider_called=False)


if __name__ == "__main__":
    unittest.main()
