import io
import json
import os
import socket
import unittest
import urllib.error
from contextlib import nullcontext
from email.message import Message
from unittest.mock import patch

from fastapi.testclient import TestClient

from apps.api.agent_supervisor.adapters.models import model_adapter
from apps.api.agent_supervisor.main import app


class _ProviderResponse(io.BytesIO):
    status = 200

    def __init__(self, payload: dict):
        super().__init__(json.dumps(payload).encode("utf-8"))
        self._agent_supervisor_provider_network_observation = {
            "checked": True,
            "connection_pinned": True,
            "address_classification": "public",
        }


class _RaisingOpener:
    def __init__(self, error: Exception):
        self.error = error

    def open(self, request, timeout):
        del request, timeout
        raise self.error


class ProviderProbeTest(unittest.TestCase):
    def setUp(self):
        self.environment = {
            "TARGET_MODEL_PROVIDER_PRIORITY": "deepseek",
            "TARGET_DEEPSEEK_API_KEY": "probe-token",
            "TARGET_DEEPSEEK_BASE_URL": "https://provider.example",
            "TARGET_DEEPSEEK_MODEL": "probe-model",
            "MODEL_PROVIDER_PROBE_TIMEOUT_SECONDS": "2",
        }

    def test_unconfigured_provider_is_reported_without_network_call(self):
        with patch.dict(os.environ, self.environment, clear=False), patch.object(model_adapter, "_provider_open") as open_provider:
            result = model_adapter.probe_provider(profile="target", provider_id="zhipu")

        self.assertEqual(result["status"], "unconfigured")
        self.assertFalse(result["configured"])
        self.assertEqual(result["error_code"], "not-configured")
        open_provider.assert_not_called()

    def test_success_uses_one_token_chat_request_and_returns_hashes_only(self):
        response = _ProviderResponse({"id": "probe-response", "choices": [{"message": {"content": "pong"}}]})
        with (
            patch.dict(os.environ, self.environment, clear=False),
            patch.object(model_adapter, "_provider_open", return_value=nullcontext(response)) as open_provider,
        ):
            result = model_adapter.probe_provider(profile="target", provider_id="deepseek")

        self.assertEqual(result["status"], "healthy")
        self.assertTrue(result["configured"])
        self.assertEqual(result["model"], "probe-model")
        self.assertTrue(result["request_hash"])
        self.assertTrue(result["response_hash"])
        self.assertEqual(result["network_observation"]["connection_pinned"], True)
        request = open_provider.call_args.args[0]
        self.assertEqual(request.full_url, "https://provider.example/chat/completions")
        self.assertEqual(request.get_header("Authorization"), "Bearer probe-token")
        body = json.loads(request.data.decode("utf-8"))
        self.assertEqual(body["max_tokens"], 1)
        self.assertNotIn("content", result)

    def test_malformed_provider_response_is_not_marked_healthy(self):
        response = _ProviderResponse({"choices": []})
        with (
            patch.dict(os.environ, self.environment, clear=False),
            patch.object(model_adapter, "_provider_open", return_value=nullcontext(response)),
        ):
            result = model_adapter.probe_provider(profile="target", provider_id="deepseek")

        self.assertEqual(result["status"], "unhealthy")
        self.assertEqual(result["error_code"], "invalid-response")
        self.assertIn("格式", result["error"])
        self.assertTrue(result["network_observation"])
        self.assertTrue(result["network_observation"]["connection_pinned"])

    def test_provider_auth_failure_is_classified_without_echoing_body(self):
        response = _ProviderResponse({})
        error = urllib.error.HTTPError(
            "https://provider.example/chat/completions",
            401,
            "bad",
            Message(),
            response,
        )
        with (
            patch.dict(os.environ, self.environment, clear=False),
            patch.object(model_adapter, "_provider_open", side_effect=error),
        ):
            result = model_adapter.probe_provider(profile="target", provider_id="deepseek")

        self.assertEqual(result["status"], "unhealthy")
        self.assertEqual(result["error_code"], "authentication-failed")
        self.assertEqual(result["http_status"], 401)
        self.assertTrue(result["network_observation"]["connection_pinned"])
        self.assertNotIn("provider-token", result["error"])

    def test_wrapped_socket_timeout_is_classified_as_timeout(self):
        with (
            patch.dict(os.environ, self.environment, clear=False),
            patch.object(
                model_adapter,
                "_provider_open",
                side_effect=urllib.error.URLError(socket.timeout("timed out")),
            ),
        ):
            result = model_adapter.probe_provider(profile="target", provider_id="deepseek")

        self.assertEqual(result["status"], "unhealthy")
        self.assertEqual(result["error_code"], "timeout")
        self.assertEqual(result["error"], "Provider 请求超时")


class ProviderOpenEvidenceTest(unittest.TestCase):
    def test_connection_error_keeps_the_pinned_dns_snapshot(self):
        error = urllib.error.URLError("connection refused")
        opener = _RaisingOpener(error)
        request = model_adapter.urllib.request.Request(
            "https://provider.example/chat/completions",
            data=b"{}",
            method="POST",
        )
        with (
            patch.object(model_adapter, "_resolve_provider_addresses", return_value=["8.8.8.8"]),
            patch.object(model_adapter.urllib.request, "build_opener", return_value=opener),
        ):
            with self.assertRaises(urllib.error.URLError) as raised:
                model_adapter._provider_open(request, timeout=1.0)

        observation = model_adapter._provider_network_observation_from_error(raised.exception)
        self.assertEqual(observation["resolved_address_count"], 1)
        self.assertEqual(observation["address_classification"], "public")
        self.assertTrue(observation["connection_pinned"])

    def test_http_error_gets_status_and_snapshot_when_upstream_does_not_annotate(self):
        error = urllib.error.HTTPError(
            "https://provider.example/chat/completions",
            503,
            "upstream unavailable",
            Message(),
            io.BytesIO(b"provider error"),
        )
        opener = _RaisingOpener(error)
        request = model_adapter.urllib.request.Request(
            "https://provider.example/chat/completions",
            data=b"{}",
            method="POST",
        )
        with (
            patch.object(model_adapter, "_resolve_provider_addresses", return_value=["8.8.8.8"]),
            patch.object(model_adapter.urllib.request, "build_opener", return_value=opener),
        ):
            with self.assertRaises(urllib.error.HTTPError) as raised:
                model_adapter._provider_open(request, timeout=1.0)

        self.assertEqual(raised.exception.code, 503)
        observation = model_adapter._provider_network_observation_from_error(raised.exception)
        self.assertEqual(observation["resolved_address_count"], 1)
        self.assertEqual(observation["address_classification"], "public")


class ProviderProbeRouteTest(unittest.TestCase):
    def test_observer_cannot_trigger_probe_but_analyst_can(self):
        probe_result = {
            "schema_version": "agent-supervisor.provider-probe.v1",
            "profile": "target",
            "provider_id": "deepseek",
            "status": "healthy",
        }
        with (
            patch.dict(
                os.environ,
                {
                    "AGENT_SUPERVISOR_AUTH_DISABLED": "false",
                    "AGENT_SUPERVISOR_API_TOKEN_ANALYST": "analyst-token",
                    "AGENT_SUPERVISOR_API_TOKEN_OBSERVER": "observer-token",
                    "AGENT_SUPERVISOR_SECURITY_PROFILE": "local",
                },
                clear=False,
            ),
            patch("apps.api.agent_supervisor.routers.core.probe_provider", return_value=probe_result) as probe,
            TestClient(app) as client,
        ):
            observer = client.post(
                "/api/model_probe",
                json={"profile": "target", "provider_id": "deepseek"},
                headers={"Authorization": "Bearer observer-token"},
            )
            analyst = client.post(
                "/api/model_probe",
                json={"profile": "target", "provider_id": "deepseek"},
                headers={"Authorization": "Bearer analyst-token"},
            )

        self.assertEqual(observer.status_code, 403)
        self.assertEqual(analyst.status_code, 200)
        self.assertEqual(analyst.json()["status"], "healthy")
        probe.assert_called_once_with(profile="target", provider_id="deepseek")


if __name__ == "__main__":
    unittest.main()
