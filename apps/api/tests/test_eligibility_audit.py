from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scripts.audit_shanghai_eligibility import audit, build_markdown


class EligibilityAuditTest(unittest.TestCase):
    def test_history_without_local_award_match_requires_attestation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            history = root / "docs" / "长城信息安全"
            awards = root / "docs" / "上海信息安全"
            history.mkdir(parents=True)
            awards.mkdir(parents=True)
            (history / "智安哨-作品报告.docx").write_bytes(b"fixture")
            (awards / "2025获奖名单.txt").write_text("本地没有可解析的获奖名单文件。", encoding="utf-8")

            report = audit(root)
            markdown = build_markdown(report)

        self.assertEqual(report["status"], "needs-team-attestation")
        self.assertTrue(report["prior_submission_detected"])
        self.assertFalse(report["local_award_match_found"])
        self.assertTrue(report["lineage_assessment"]["shared_brand"])
        self.assertNotIn("- 未发现\n\n### 本地获奖名单", markdown)


if __name__ == "__main__":
    unittest.main()
