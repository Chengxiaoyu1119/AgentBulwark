from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from apps.api.agent_supervisor.domains.governance.approvals import (
    _review_scope,
    create_approval_review,
    list_approval_reviews,
)
from apps.api.agent_supervisor.storage import database


class ApprovalScopeTest(unittest.TestCase):
    def test_review_scopes_are_filterable_without_schema_migration(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime_dir = Path(temp_dir)
            with (
                patch.object(database, "RUNTIME_DIR", runtime_dir),
                patch.object(database, "DB_PATH", runtime_dir / "approval-scopes.sqlite3"),
            ):
                database.init_db()
                demo_review = create_approval_review(
                    _event("demo"),
                    _supervisor_result("audit-demo"),
                    review_scope="demo",
                )
                experiment_review = create_approval_review(
                    _event("experiment"),
                    _supervisor_result("audit-experiment"),
                    review_scope="experiment",
                )
                all_reviews = list_approval_reviews(limit=10)
                demo_reviews = list_approval_reviews(limit=10, scope="demo")
                operational_reviews = list_approval_reviews(limit=10, scope="operational")

        self.assertIsNotNone(demo_review)
        self.assertIsNotNone(experiment_review)
        self.assertEqual(all_reviews["summary"]["total"], 2)
        self.assertEqual(all_reviews["summary"]["scope_counts"]["demo"], 1)
        self.assertEqual(all_reviews["summary"]["scope_counts"]["experiment"], 1)
        self.assertEqual(demo_reviews["summary"]["total"], 1)
        self.assertEqual(demo_reviews["reviews"][0]["scope"], "demo")
        self.assertEqual(operational_reviews["summary"]["total"], 0)

    def test_legacy_demo_and_experiment_records_are_classified_by_full_identity(self) -> None:
        self.assertEqual(
            _review_scope(
                {
                    "source_app": "JudgeDemo",
                    "agent_id": "judge-demo-agent",
                    "conversation_id": "judge-demo-mail",
                }
            ),
            "demo",
        )
        self.assertEqual(
            _review_scope(
                {
                    "source_app": "智安哨本地渗透学习靶场",
                    "agent_id": "vulnerable-learning-agent",
                    "conversation_id": "learning-run-1",
                }
            ),
            "experiment",
        )
        self.assertEqual(
            _review_scope(
                {
                    "source_app": "JudgeDemo",
                    "agent_id": "external-agent",
                    "conversation_id": "external-conversation",
                }
            ),
            "operational",
        )


def _event(suffix: str) -> dict[str, object]:
    return {
        "source_app": "ScopeTest",
        "agent_id": "scope-test-agent",
        "conversation_id": f"scope-{suffix}",
        "model_input": "发送测试摘要。",
        "model_output": "准备调用邮件工具。",
        "tool_call": {
            "tool": "mail.send",
            "arguments": {"to": "outside@example.com", "subject": "test", "body": "summary"},
        },
    }


def _supervisor_result(audit_id: str) -> dict[str, object]:
    return {
        "decision": "询问",
        "run_id": f"run-{audit_id}",
        "policy_id": "external-mail",
        "risk_level": "high",
        "risk_score": 80,
        "risk_factors": ["外部收件人"],
        "anomaly_score": 60,
        "anomaly_signals": ["外发"],
        "reason": "外部邮件需要人工确认。",
        "recommendation": "核对收件人。",
        "audit_log": {
            "id": audit_id,
            "run_id": f"run-{audit_id}",
            "tool": "mail.send",
            "arguments": {"to": "outside@example.com"},
            "policy_id": "external-mail",
            "risk_level": "high",
            "risk_score": 80,
            "audit_hash": f"hash-{audit_id}",
            "previous_hash": "",
        },
    }


if __name__ == "__main__":
    unittest.main()
