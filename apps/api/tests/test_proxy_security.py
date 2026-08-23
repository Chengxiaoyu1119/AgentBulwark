from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from typing import Any

from fastapi import HTTPException

from apps.api.agent_supervisor.adapters.proxy.proxy_security import (
    _rate_limit_key,
    proxy_security_snapshot,
    proxy_server_observed_receipts_required,
    require_openai_proxy_access,
    require_openai_proxy_generation,
    reset_proxy_rate_limits,
)
from apps.api.agent_supervisor.auth import require_role

_MULTI_PROCESS_RATE_LIMIT_SCRIPT = r'''
import json
from fastapi import HTTPException
from apps.api.agent_supervisor.adapters.proxy.proxy_security import _enforce_rate_limit

try:
    _enforce_rate_limit("ip:shared-worker-client")
except HTTPException as exc:
    print(json.dumps({"allowed": False, "status": exc.status_code}), flush=True)
else:
    print(json.dumps({"allowed": True}), flush=True)
'''


class ProxySecurityTest(unittest.TestCase):
    def setUp(self) -> None:
        self._env = {
            key: os.environ.get(key)
            for key in [
                "AGENT_SUPERVISOR_AUTH_DISABLED",
                "AGENT_SUPERVISOR_API_TOKEN",
                "AGENT_SUPERVISOR_PROXY_ALLOW_UNAUTHENTICATED_PUBLIC",
                "AGENT_SUPERVISOR_PROXY_ALLOW_LOCAL_UNAUTHENTICATED",
                "AGENT_SUPERVISOR_PROXY_RATE_LIMIT_PER_MINUTE",
                "AGENT_SUPERVISOR_PROXY_ENABLED",
                "AGENT_SUPERVISOR_TRUST_PROXY_HEADERS",
                "AGENT_SUPERVISOR_DEFAULT_ROLE",
                "AGENT_SUPERVISOR_API_TOKEN_EXECUTOR",
                "AGENT_SUPERVISOR_AGENT_TOKENS_JSON",
                "AGENT_SUPERVISOR_ALLOW_SHARED_EXECUTOR_TOKEN",
                "AGENT_SUPERVISOR_SECURITY_PROFILE",
                "AGENT_SUPERVISOR_PROXY_REQUIRE_TOOL_RECEIPTS",
                "AGENT_SUPERVISOR_PROXY_REQUIRE_SERVER_OBSERVED_RECEIPTS",
            ]
        }
        reset_proxy_rate_limits()

    def tearDown(self) -> None:
        for key, value in self._env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        reset_proxy_rate_limits()

    def _request(self, host: str, forwarded_for: str = "") -> Any:
        headers = {"x-forwarded-for": forwarded_for} if forwarded_for else {}
        return SimpleNamespace(headers=headers, client=SimpleNamespace(host=host))

    def test_public_proxy_is_rejected_when_auth_is_disabled(self) -> None:
        os.environ["AGENT_SUPERVISOR_AUTH_DISABLED"] = "true"
        os.environ["AGENT_SUPERVISOR_PROXY_ALLOW_UNAUTHENTICATED_PUBLIC"] = "false"

        with self.assertRaises(HTTPException) as ctx:
            require_openai_proxy_access(
                self._request("8.8.8.8"),
                authorization=None,
                x_agent_supervisor_api_token=None,
            )

        self.assertEqual(ctx.exception.status_code, 401)

    def test_proxy_does_not_trust_spoofed_forwarded_for_by_default(self) -> None:
        os.environ["AGENT_SUPERVISOR_AUTH_DISABLED"] = "true"
        os.environ["AGENT_SUPERVISOR_PROXY_ALLOW_UNAUTHENTICATED_PUBLIC"] = "false"
        os.environ["AGENT_SUPERVISOR_TRUST_PROXY_HEADERS"] = "false"

        with self.assertRaises(HTTPException) as ctx:
            require_openai_proxy_access(
                self._request("8.8.8.8", forwarded_for="127.0.0.1"),
                authorization=None,
                x_agent_supervisor_api_token=None,
            )

        self.assertEqual(ctx.exception.status_code, 401)

    def test_proxy_can_trust_forwarded_for_when_explicitly_enabled(self) -> None:
        os.environ["AGENT_SUPERVISOR_AUTH_DISABLED"] = "true"
        os.environ["AGENT_SUPERVISOR_PROXY_ALLOW_LOCAL_UNAUTHENTICATED"] = "true"
        os.environ["AGENT_SUPERVISOR_TRUST_PROXY_HEADERS"] = "true"
        os.environ["AGENT_SUPERVISOR_PROXY_RATE_LIMIT_PER_MINUTE"] = "0"

        result = require_openai_proxy_access(
            self._request("8.8.8.8", forwarded_for="127.0.0.1"),
            authorization=None,
            x_agent_supervisor_api_token=None,
        )

        self.assertEqual(result["client"], "127.0.0.1")

    def test_local_proxy_allows_local_demo_when_auth_is_disabled(self) -> None:
        os.environ["AGENT_SUPERVISOR_AUTH_DISABLED"] = "true"
        os.environ["AGENT_SUPERVISOR_PROXY_ALLOW_LOCAL_UNAUTHENTICATED"] = "true"
        os.environ["AGENT_SUPERVISOR_PROXY_RATE_LIMIT_PER_MINUTE"] = "0"

        result = require_openai_proxy_access(
            self._request("127.0.0.1"),
            authorization=None,
            x_agent_supervisor_api_token=None,
        )

        self.assertEqual(result["client"], "127.0.0.1")

    def test_proxy_requires_token_when_auth_is_enabled(self) -> None:
        os.environ["AGENT_SUPERVISOR_AUTH_DISABLED"] = "false"
        os.environ["AGENT_SUPERVISOR_API_TOKEN"] = "proxy-token"

        result = require_openai_proxy_access(self._request("8.8.8.8"), authorization="Bearer proxy-token")

        self.assertTrue(result["authenticated"])

    def test_observer_can_discover_but_cannot_generate_model_traffic(self) -> None:
        os.environ["AGENT_SUPERVISOR_AUTH_DISABLED"] = "false"
        os.environ["AGENT_SUPERVISOR_API_TOKEN"] = "read-token"
        os.environ["AGENT_SUPERVISOR_DEFAULT_ROLE"] = "observer"

        context = require_openai_proxy_access(self._request("8.8.8.8"), authorization="Bearer read-token")
        self.assertEqual(context["role"], "observer")
        with self.assertRaises(HTTPException) as ctx:
            require_openai_proxy_generation(self._request("8.8.8.8"), authorization="Bearer read-token")
        self.assertEqual(ctx.exception.status_code, 403)

    def test_executor_role_can_generate_model_traffic(self) -> None:
        os.environ["AGENT_SUPERVISOR_AUTH_DISABLED"] = "false"
        os.environ["AGENT_SUPERVISOR_AGENT_TOKENS_JSON"] = '{"proxy-agent":"exec-token"}'

        context = require_openai_proxy_generation(self._request("8.8.8.8"), authorization="Bearer exec-token")
        self.assertEqual(context["role"], "executor")
        self.assertEqual(context["agent_id"], "proxy-agent")

    def test_unbound_executor_cannot_generate_model_traffic_without_compatibility_switch(self) -> None:
        os.environ["AGENT_SUPERVISOR_AUTH_DISABLED"] = "false"
        os.environ["AGENT_SUPERVISOR_API_TOKEN_EXECUTOR"] = "shared-exec-token"
        os.environ["AGENT_SUPERVISOR_ALLOW_SHARED_EXECUTOR_TOKEN"] = "false"

        with self.assertRaises(HTTPException) as ctx:
            require_openai_proxy_generation(self._request("8.8.8.8"), authorization="Bearer shared-exec-token")

        self.assertEqual(ctx.exception.status_code, 403)

    def test_unbound_executor_can_generate_only_when_compatibility_switch_is_explicit(self) -> None:
        os.environ["AGENT_SUPERVISOR_AUTH_DISABLED"] = "false"
        os.environ["AGENT_SUPERVISOR_API_TOKEN_EXECUTOR"] = "shared-exec-token"
        os.environ["AGENT_SUPERVISOR_ALLOW_SHARED_EXECUTOR_TOKEN"] = "true"

        context = require_openai_proxy_generation(self._request("8.8.8.8"), authorization="Bearer shared-exec-token")
        self.assertEqual(context["role"], "executor")
        self.assertEqual(context["agent_id"], "")

    def test_role_requirement_does_not_promote_observer_or_analyst_into_executor(self) -> None:
        with self.assertRaises(HTTPException):
            require_role("executor", "observer")
        with self.assertRaises(HTTPException):
            require_role("executor", "analyst")
        require_role("executor", "executor")
        require_role("executor", "admin")

    def test_proxy_rate_limit_blocks_repeated_calls(self) -> None:
        os.environ["AGENT_SUPERVISOR_AUTH_DISABLED"] = "true"
        os.environ["AGENT_SUPERVISOR_PROXY_ALLOW_LOCAL_UNAUTHENTICATED"] = "true"
        os.environ["AGENT_SUPERVISOR_PROXY_RATE_LIMIT_PER_MINUTE"] = "1"
        request = self._request("127.0.0.1")

        require_openai_proxy_access(request, authorization=None, x_agent_supervisor_api_token=None)
        with self.assertRaises(HTTPException) as ctx:
            require_openai_proxy_access(request, authorization=None, x_agent_supervisor_api_token=None)

        self.assertEqual(ctx.exception.status_code, 429)

    def test_rate_limit_key_keeps_complete_token_identity(self) -> None:
        first = _rate_limit_key("127.0.0.1", "shared-prefix-token-A")
        second = _rate_limit_key("127.0.0.1", "shared-prefix-token-B")
        self.assertNotEqual(first, second)

    def test_rate_limit_is_shared_across_worker_processes(self) -> None:
        os.environ["AGENT_SUPERVISOR_PROXY_RATE_LIMIT_PER_MINUTE"] = "1"
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8") as handle:
            handle.write(_MULTI_PROCESS_RATE_LIMIT_SCRIPT)
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
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                )
            outputs = [process.communicate(timeout=15) for process in processes]
            self.assertTrue(all(stdout.strip() for stdout, _stderr in outputs), outputs)
            results = [json.loads(stdout) for stdout, _stderr in outputs]
            self.assertEqual(sum(bool(item.get("allowed")) for item in results), 1, outputs)
            rejected = [item for item in results if not item.get("allowed")]
            self.assertEqual(rejected[0].get("status"), 429, outputs)
        finally:
            for process in processes:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)
            try:
                os.unlink(script_path)
            except OSError:
                pass

    def test_production_requires_server_observed_receipts_even_when_switch_is_false(self) -> None:
        os.environ["AGENT_SUPERVISOR_SECURITY_PROFILE"] = "production"
        os.environ["AGENT_SUPERVISOR_PROXY_REQUIRE_TOOL_RECEIPTS"] = "false"
        os.environ["AGENT_SUPERVISOR_PROXY_REQUIRE_SERVER_OBSERVED_RECEIPTS"] = "false"

        snapshot = proxy_security_snapshot()

        self.assertTrue(proxy_server_observed_receipts_required())
        self.assertTrue(snapshot["server_observed_receipts_required"])
        self.assertTrue(snapshot["tool_receipts_required"])

    def test_local_profile_exposes_explicit_receipt_compatibility_posture(self) -> None:
        os.environ["AGENT_SUPERVISOR_SECURITY_PROFILE"] = "local"
        os.environ["AGENT_SUPERVISOR_PROXY_REQUIRE_SERVER_OBSERVED_RECEIPTS"] = "false"

        self.assertFalse(proxy_server_observed_receipts_required())
        self.assertFalse(proxy_security_snapshot()["server_observed_receipts_required"])

        os.environ["AGENT_SUPERVISOR_PROXY_REQUIRE_SERVER_OBSERVED_RECEIPTS"] = "true"
        self.assertTrue(proxy_server_observed_receipts_required())

    def test_production_disables_shared_executor_compatibility(self) -> None:
        os.environ["AGENT_SUPERVISOR_SECURITY_PROFILE"] = "production"
        os.environ["AGENT_SUPERVISOR_AUTH_DISABLED"] = "false"
        os.environ["AGENT_SUPERVISOR_API_TOKEN_EXECUTOR"] = "shared-exec-token"
        os.environ["AGENT_SUPERVISOR_ALLOW_SHARED_EXECUTOR_TOKEN"] = "true"

        with self.assertRaises(HTTPException) as ctx:
            require_openai_proxy_generation(
                self._request("8.8.8.8"),
                authorization="Bearer shared-exec-token",
            )

        self.assertEqual(ctx.exception.status_code, 403)
        snapshot = proxy_security_snapshot()
        self.assertTrue(snapshot["executor_identity_required"])
        self.assertFalse(snapshot["shared_executor_compatibility"])

    def test_production_allows_bound_agent_executor_token(self) -> None:
        os.environ["AGENT_SUPERVISOR_SECURITY_PROFILE"] = "production"
        os.environ["AGENT_SUPERVISOR_AUTH_DISABLED"] = "false"
        os.environ["AGENT_SUPERVISOR_AGENT_TOKENS_JSON"] = '{"proxy-agent":"bound-exec-token"}'

        context = require_openai_proxy_generation(
            self._request("8.8.8.8"),
            authorization="Bearer bound-exec-token",
        )

        self.assertEqual(context["role"], "executor")
        self.assertEqual(context["agent_id"], "proxy-agent")


if __name__ == "__main__":
    unittest.main()
