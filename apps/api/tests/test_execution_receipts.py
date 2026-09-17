from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from apps.api.agent_supervisor.domains.runtime.events import evaluate_agent_event
from apps.api.agent_supervisor.domains.runtime.execution_receipts import (
    ExecutionReceiptConflictError,
    complete_execution,
    tool_result_hash,
    verify_execution_receipt,
)
from apps.api.agent_supervisor.domains.runtime.gateway_execution import execute_gateway_tool_call
from apps.api.agent_supervisor.storage import data as policy_data
from apps.api.agent_supervisor.storage import database


def _result_hash(value: object) -> str:
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, default=str).encode("utf-8")).hexdigest()


class ExecutionReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(prefix="execution-receipt-test-")
        self.db_patch = patch.object(database, "DB_PATH", Path(self.temp_dir.name) / "runtime.sqlite3")
        self.db_patch.start()
        self.settings_patch = patch.object(policy_data, "POLICY_SETTINGS_PATH", Path(self.temp_dir.name) / "policy_settings.json")
        self.settings_patch.start()
        Path(policy_data.POLICY_SETTINGS_PATH).write_text(
            json.dumps(
                {
                    "require_agent_capability_registration": False,
                    "require_agent_model_registration": False,
                    "require_agent_context_registration": False,
                }
            ),
            encoding="utf-8",
        )
        database.init_db()
        self.env_patch = patch.dict(
            os.environ,
            {"AGENT_SUPERVISOR_AUDIT_HMAC_KEY": "receipt-test-hmac", "AGENT_SUPERVISOR_AUDIT_HMAC_KEY_ID": "receipt-test-v1"},
            clear=False,
        )
        self.env_patch.start()

    def tearDown(self) -> None:
        self.env_patch.stop()
        self.settings_patch.stop()
        self.db_patch.stop()
        self.temp_dir.cleanup()

    def _event(self, *, tool: str = "file.read", arguments: dict[str, object] | None = None) -> dict[str, object]:
        return {
            "conversation_id": f"receipt-{tool}-{id(self)}",
            "agent_id": "receipt-agent",
            "source_app": "receipt-test",
            "model_input": "执行工具",
            "tool_call": {"tool": tool, "arguments": arguments or {"path": "public/readme.md"}},
        }

    def test_allowed_receipt_is_append_only_and_idempotent(self) -> None:
        decision = evaluate_agent_event(self._event(), guard_enabled=True)
        request = {
            "receipt_id": "receipt-1",
            "agent_id": "receipt-agent",
            "tool_call": {"tool": "file.read", "arguments": {"path": "public/readme.md"}},
            "status": "completed",
            "execution_target": "real",
            "result_hash": _result_hash({"status": "ok"}),
            "duration_ms": 8.5,
        }
        first = complete_execution(decision["audit_id"], request)
        second = complete_execution(decision["audit_id"], request)
        self.assertFalse(first["idempotent"])
        self.assertTrue(second["idempotent"])
        receipt = first["receipt"]
        self.assertEqual(receipt["execution_evidence"], "caller-declared")
        self.assertFalse(receipt["execution_observed_by_server"])
        self.assertTrue(verify_execution_receipt(receipt))
        self.assertEqual(database.latest_audit_logs(10)[0]["execution_status"], "completed")

    def test_signature_removal_invalidates_receipt(self) -> None:
        decision = evaluate_agent_event(self._event(), guard_enabled=True)
        receipt = complete_execution(
            decision["audit_id"],
            {
                "receipt_id": "receipt-signature-required",
                "agent_id": "receipt-agent",
                "tool_call": {"tool": "file.read", "arguments": {"path": "public/readme.md"}},
                "status": "completed",
                "execution_target": "real",
                "result_hash": _result_hash({"status": "ok"}),
            },
        )["receipt"]
        self.assertFalse(verify_execution_receipt({**receipt, "receipt_signature": ""}))

    def test_tampered_receipt_blocks_gateway_replay(self) -> None:
        event = {
            **self._event(),
            "source_app": "openai-compatible-proxy",
            "stage_context": {
                "session_id": "tampered-receipt-session",
                "provider_call_id": "tampered-receipt-call",
                "provider_called": True,
            },
        }
        decision = evaluate_agent_event(event, guard_enabled=True)
        receipt = complete_execution(
            decision["audit_id"],
            {
                "receipt_id": "tampered-receipt-source",
                "agent_id": "receipt-agent",
                "tool_call": event["tool_call"],
                "status": "completed",
                "execution_target": "real",
                "result_hash": _result_hash({"status": "ok"}),
            },
        )["receipt"]
        tampered = {**receipt, "receipt_hash": "0" * 64}
        self.assertFalse(verify_execution_receipt(tampered))
        with (
            patch(
                "apps.api.agent_supervisor.domains.runtime.gateway_execution.load_execution_receipt",
                return_value=tampered,
            ),
            patch("apps.api.agent_supervisor.domains.runtime.gateway_execution.execute_tool") as execute,
        ):
            with self.assertRaisesRegex(ValueError, "完整性校验失败"):
                execute_gateway_tool_call(
                    decision["audit_id"],
                    agent_id="receipt-agent",
                    session_id="tampered-receipt-session",
                    provider_call_id="tampered-receipt-call",
                )
        execute.assert_not_called()

    def test_conflicting_retry_and_tool_mismatch_are_rejected(self) -> None:
        decision = evaluate_agent_event(self._event(), guard_enabled=True)
        request = {
            "receipt_id": "receipt-conflict",
            "agent_id": "receipt-agent",
            "tool_call": {"tool": "file.read", "arguments": {"path": "public/readme.md"}},
            "status": "completed",
            "execution_target": "real",
            "result_hash": _result_hash({"status": "ok"}),
        }
        complete_execution(decision["audit_id"], request)
        with self.assertRaises(ExecutionReceiptConflictError):
            complete_execution(decision["audit_id"], {**request, "result_hash": _result_hash({"status": "different"})})
        with self.assertRaisesRegex(ValueError, "工具调用"):
            complete_execution(
                decision["audit_id"],
                {**request, "receipt_id": "receipt-other", "tool_call": {"tool": "file.read", "arguments": {"path": "public/other.md"}}},
            )

    def test_control_decisions_require_non_execution_receipt(self) -> None:
        decision = evaluate_agent_event(self._event(tool="mail.send", arguments={"to": "outside@example.com", "body": "fixture"}), guard_enabled=True)
        self.assertIn(decision["decision"], {"询问", "拒绝"})
        request = {
            "receipt_id": "receipt-control",
            "agent_id": "receipt-agent",
            "tool_call": {"tool": "mail.send", "arguments": {"to": "outside@example.com", "body": "fixture"}},
            "status": "not_executed",
            "execution_target": "none",
        }
        receipt = complete_execution(decision["audit_id"], request)["receipt"]
        self.assertTrue(receipt["control_verified"])
        with self.assertRaisesRegex(ValueError, "只能提交"):
            complete_execution(decision["audit_id"], {**request, "receipt_id": "receipt-bad", "status": "completed", "execution_target": "real", "result_hash": _result_hash("x")})

    def test_custom_mapping_preserves_original_hash(self) -> None:
        policy_data.update_policy_settings(
            {
                "agent_tool_allowlists": {"receipt-agent": ["browser.open"]},
                "agent_tool_mappings": {
                    "receipt-agent": {
                        "browser.open": {
                            "capability": "api.call",
                            "argument_mapping": {"url": "endpoint", "http_method": "method"},
                            "required_arguments": ["url"],
                        }
                    }
                },
            }
        )
        event = self._event(tool="browser.open", arguments={"url": "/health", "http_method": "GET"})
        decision = evaluate_agent_event(event, guard_enabled=True)
        self.assertEqual(decision["audit_log"]["standard_capability"], "api.call")
        self.assertEqual(decision["audit_log"]["standard_arguments"]["endpoint"], "/health")
        receipt = complete_execution(
            decision["audit_id"],
            {
                "receipt_id": "custom-tool-receipt",
                "agent_id": "receipt-agent",
                "tool_call": event["tool_call"],
                "status": "completed",
                "execution_target": "real",
                "result_hash": _result_hash({"status": "ok"}),
            },
        )["receipt"]
        self.assertEqual(receipt["tool_call_hash"], decision["audit_log"]["tool_call_hash"])

    def test_gateway_execution_is_idempotent_and_hash_bound(self) -> None:
        event = {
            **self._event(tool="file.read", arguments={"path": "public/项目说明.md"}),
            "source_app": "openai-compatible-proxy",
            "stage_context": {"session_id": "receipt-replay-session", "provider_call_id": "receipt-replay-call", "provider_called": True},
        }
        decision = evaluate_agent_event(event, guard_enabled=True)
        first = execute_gateway_tool_call(decision["audit_id"], agent_id="receipt-agent", session_id="receipt-replay-session", provider_call_id="receipt-replay-call")
        second = execute_gateway_tool_call(decision["audit_id"], agent_id="receipt-agent", session_id="receipt-replay-session", provider_call_id="receipt-replay-call")
        self.assertTrue(second["idempotent"])
        self.assertEqual(second["tool_result_hash"], first["tool_result_hash"])
        self.assertEqual(tool_result_hash(second["tool_result"]), second["tool_result_hash"])

    def test_server_observed_receipt_is_projected_into_audit_reader(self) -> None:
        event = {
            **self._event(tool="file.read", arguments={"path": "public/项目说明.md"}),
            "source_app": "openai-compatible-proxy",
            "stage_context": {
                "session_id": "audit-projection-session",
                "provider_call_id": "audit-projection-call",
                "provider_called": True,
            },
        }
        with patch.dict(os.environ, {"AGENT_SUPERVISOR_AUDIT_HMAC_KEY": ""}, clear=False):
            decision = evaluate_agent_event(event, guard_enabled=True)
            execute_gateway_tool_call(
                decision["audit_id"],
                agent_id="receipt-agent",
                session_id="audit-projection-session",
                provider_call_id="audit-projection-call",
            )
            audit = next(item for item in database.latest_audit_logs(20) if item["id"] == decision["audit_id"])

        self.assertEqual(audit["execution_evidence"], "server-observed")
        self.assertTrue(audit["execution_observed_by_server"])
        self.assertTrue(audit["tool_output"]["executed"])
        self.assertEqual(audit["execution_target"], "local-runtime")
        self.assertEqual(audit["evidence_status"], "verified")

    def test_gateway_execution_rejects_caller_declared_receipt(self) -> None:
        event = {
            **self._event(),
            "source_app": "openai-compatible-proxy",
            "stage_context": {"session_id": "caller-receipt-session", "provider_call_id": "caller-receipt-call", "provider_called": True},
        }
        decision = evaluate_agent_event(event, guard_enabled=True)
        complete_execution(
            decision["audit_id"],
            {
                "receipt_id": "caller-declared-first",
                "agent_id": "receipt-agent",
                "tool_call": event["tool_call"],
                "status": "completed",
                "execution_target": "real",
                "result_hash": _result_hash({"claimed": True}),
            },
        )
        with self.assertRaisesRegex(ValueError, "调用方声明"):
            execute_gateway_tool_call(decision["audit_id"], agent_id="receipt-agent", session_id="caller-receipt-session", provider_call_id="caller-receipt-call")


if __name__ == "__main__":
    unittest.main()
