from __future__ import annotations

import json
import os
from unittest import TestCase
from unittest.mock import patch

from fastapi.testclient import TestClient

from apps.api.agent_supervisor.domains.runtime.gateway_trace import build_gateway_trace_index
from apps.api.agent_supervisor.main import app


def _row(
    *,
    request_id: str = "chatcmpl-trace-1",
    audit_id: str = "audit-trace-1",
    agent_id: str = "agent-a",
    decision: str = "允许",
    provider_called: bool = True,
    provider_call_id: str = "",
    policy_id: str = "default-allow",
) -> dict:
    return {
        "id": audit_id,
        "decision": decision,
        "policy_id": policy_id,
        "risk_score": 12 if decision == "允许" else 95,
        "tool": "model.respond" if not provider_call_id else "file.read",
        "arguments": {"path": "secret-not-returned"},
        "model_input": "secret prompt must not be returned",
        "model_output": "provider output must not be returned",
        "audit_hash": "a" * 64,
        "timestamp": "2026-08-18T10:00:00+00:00",
        "agent_id": agent_id,
        "execution_status": "not_executed" if decision != "允许" else "not_applicable",
        "execution_evidence": "not-executed-observed" if decision != "允许" else "",
        "execution_observed_by_server": decision != "允许",
        "stage_context": {
            "request_id": request_id,
            "session_id": "session-trace-1",
            "provider": "DeepSeek",
            "provider_profile": "target",
            "provider_model": "deepseek-test",
            "provider_response_id": "provider-response-1",
            "request_hash": "b" * 64,
            "provider_request_hash": "c" * 64,
            "provider_response_hash": "d" * 64,
            "provider_called": provider_called,
            "provider_call_id": provider_call_id,
        },
    }


class GatewayTraceTests(TestCase):
    def test_trace_groups_stages_and_never_exposes_raw_content(self) -> None:
        result = build_gateway_trace_index(
            [
                _row(),
                _row(
                    audit_id="audit-trace-2",
                    decision="拒绝",
                    provider_call_id="call-1",
                    policy_id="path-boundary",
                ),
            ]
        )

        self.assertEqual(result["schema_version"], "agent-supervisor.gateway-trace.v1")
        self.assertEqual(result["count"], 1)
        trace = result["traces"][0]
        self.assertEqual(trace["status"], "controlled")
        self.assertEqual(trace["decision"], "拒绝")
        self.assertEqual(trace["controlled_stage_count"], 1)
        self.assertEqual(trace["tool_call_stage_count"], 1)
        self.assertEqual(trace["risk_score"], 95)
        self.assertEqual(trace["primary_policy_id"], "path-boundary")
        self.assertEqual(result["summary"]["request_count"], 1)
        self.assertEqual(result["summary"]["controlled_count"], 1)
        self.assertEqual(result["summary"]["tool_call_count"], 1)
        dumped = json.dumps(result, ensure_ascii=False)
        self.assertNotIn("secret-not-returned", dumped)
        self.assertNotIn("secret prompt must not be returned", dumped)
        self.assertFalse(result["raw_content_exposed"])

    def test_trace_aggregates_provider_facts_when_first_stage_is_pre_provider(self) -> None:
        pre_provider = _row(
            audit_id="audit-trace-pre",
            provider_called=False,
            decision="允许",
        )
        pre_provider["timestamp"] = "2026-08-18T09:59:00+00:00"
        pre_provider["stage_context"].update(
            {
                "provider": "",
                "provider_profile": "",
                "provider_model": "",
                "provider_request_hash": "",
                "provider_response_hash": "",
                "provider_response_id": "",
            }
        )
        provider_stage = _row(
            audit_id="audit-trace-provider",
            provider_called=True,
            provider_call_id="call-trace-1",
        )
        provider_stage["timestamp"] = "2026-08-18T10:00:00+00:00"

        result = build_gateway_trace_index([provider_stage, pre_provider])
        trace = result["traces"][0]

        self.assertEqual(trace["provider"], "DeepSeek")
        self.assertEqual(trace["provider_profile"], "target")
        self.assertEqual(trace["model"], "deepseek-test")
        self.assertTrue(trace["provider_request_hash"])
        self.assertTrue(trace["provider_response_hash"])
        self.assertEqual(trace["first_seen"], "2026-08-18T09:59:00+00:00")
        self.assertEqual(trace["last_seen"], "2026-08-18T10:00:00+00:00")
        self.assertEqual(trace["session_id"], "session-trace-1")
        self.assertEqual(trace["agent_id"], "agent-a")

    def test_trace_endpoint_returns_redacted_operator_view(self) -> None:
        rows = [_row()]
        with (
            patch.dict(os.environ, {"AGENT_SUPERVISOR_AUTH_DISABLED": "true"}, clear=False),
            patch("apps.api.agent_supervisor.routers.proxy.latest_gateway_audit_logs", return_value=rows),
            patch("apps.api.agent_supervisor.routers.proxy.load_gateway_request_audit_events", return_value=rows),
            TestClient(app) as client,
        ):
            response = client.get("/api/gateway/traces?limit=10")
            detail = client.get("/api/gateway/traces/chatcmpl-trace-1")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["count"], 1)
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(detail.json()["request_id"], "chatcmpl-trace-1")
        self.assertNotIn("arguments", json.dumps(detail.json(), ensure_ascii=False))

    def test_executor_trace_scope_is_bound_to_authenticated_agent(self) -> None:
        rows = [_row(agent_id="agent-a"), _row(request_id="chatcmpl-trace-2", agent_id="agent-b")]

        def scoped_rows(*_args: object, **kwargs: object) -> list[dict]:
            return [row for row in rows if row["agent_id"] == kwargs.get("agent_id")]

        with (
            patch.dict(
                os.environ,
                {
                    "AGENT_SUPERVISOR_AUTH_DISABLED": "false",
                    "AGENT_SUPERVISOR_AGENT_TOKENS_JSON": '{"agent-a":"agent-a-token"}',
                    "AGENT_SUPERVISOR_ALLOW_SHARED_EXECUTOR_TOKEN": "false",
                },
                clear=False,
            ),
            patch("apps.api.agent_supervisor.routers.proxy.latest_gateway_audit_logs", side_effect=scoped_rows) as load,
            TestClient(app) as client,
        ):
            response = client.get(
                "/api/gateway/traces",
                headers={"Authorization": "Bearer agent-a-token"},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["count"], 1)
        load.assert_called_once()
        self.assertEqual(load.call_args.kwargs["agent_id"], "agent-a")
