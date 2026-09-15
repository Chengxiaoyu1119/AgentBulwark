from __future__ import annotations

from datetime import datetime, timezone
from unittest import TestCase
from unittest.mock import patch

from apps.api.agent_supervisor.domains.runtime.operational_overview import build_operational_overview


def _audit(*, audit_id: str, request_id: str, decision: str, source_app: str = "openai-compatible-proxy") -> dict:
    return {
        "id": audit_id,
        "decision": decision,
        "policy_id": "policy-runtime",
        "tool": "model.respond",
        "risk_score": 90 if decision != "允许" else 5,
        "execution_receipt_expected": decision == "允许",
        "execution_receipt": None,
        "evidence_status": "verified",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_app": source_app,
        "stage_context": {"request_id": request_id, "provider_called": decision == "允许"},
    }


class OperationalOverviewTests(TestCase):
    def test_groups_live_gateway_stages_and_keeps_empty_buckets_real(self) -> None:
        rows = [
            _audit(audit_id="audit-allow", request_id="request-1", decision="允许"),
            _audit(audit_id="audit-deny", request_id="request-1", decision="拒绝"),
            _audit(audit_id="audit-mcp", request_id="mcp-1", decision="询问", source_app="mcp-gateway"),
        ]
        with (
            patch(
                "apps.api.agent_supervisor.domains.runtime.operational_overview.operational_audit_logs",
                return_value=rows,
            ),
            patch(
                "apps.api.agent_supervisor.domains.runtime.operational_overview.list_approval_reviews",
                return_value={"reviews": [], "summary": {}},
            ),
            patch(
                "apps.api.agent_supervisor.domains.runtime.operational_overview.list_execution_receipts",
                return_value={"receipts": [], "gateway_execution_claims": [], "summary": {}},
            ),
            patch(
                "apps.api.agent_supervisor.domains.runtime.operational_overview.build_runtime_status",
                return_value={
                    "models": {"global": [], "target": [{"configured": True, "mode": "real-api"}]},
                    "proxy": {
                        "enabled": True,
                        "tool_receipts_required": True,
                        "server_observed_receipts_required": True,
                    },
                    "gateway_evidence": {"fingerprint": "runtime"},
                    "mcp": {"configured": True, "enabled": True, "guard_enabled": True},
                },
            ),
        ):
            result = build_operational_overview(role="admin")

        self.assertEqual(result["data_status"], "live")
        self.assertEqual(result["summary"]["request_count"], 2)
        self.assertEqual(result["summary"]["controlled_count"], 2)
        self.assertEqual(result["summary"]["denied_count"], 1)
        self.assertEqual(result["summary"]["approval_count"], 1)
        self.assertEqual(sum(item["request_count"] for item in result["trend"]), 2)
        self.assertEqual(result["readiness"]["gateway"]["status"], "ready")
        self.assertEqual(result["readiness"]["mcp"]["status"], "ready")
        self.assertEqual(len(result["activity"]), 2)

    def test_storage_failure_is_explicitly_degraded_instead_of_zeroing_live_data(self) -> None:
        with patch(
            "apps.api.agent_supervisor.domains.runtime.operational_overview.operational_audit_logs",
            side_effect=RuntimeError("database unavailable"),
        ):
            result = build_operational_overview()

        self.assertEqual(result["data_status"], "degraded")
        self.assertIsNone(result["summary"]["request_count"])
        self.assertEqual(result["source_errors"], [{"source": "audit_logs", "error": "RuntimeError"}])
        self.assertEqual(result["action_queue"][0]["id"], "operational-source-errors")
