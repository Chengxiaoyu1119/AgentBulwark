from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from zipfile import ZipFile

from apps.api.agent_supervisor.domains.reports.readiness import _pending_markers


class MaterialReadinessTest(unittest.TestCase):
    def test_research_limitation_is_not_treated_as_submission_placeholder(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "技术报告.docx"
            with ZipFile(path, "w") as archive:
                archive.writestr(
                    "word/document.xml",
                    "<document><p>第三方验证仍待补充；个人信息待填写。</p></document>",
                )

            self.assertEqual(_pending_markers(path), ["待填写"])

    def test_registration_filename_keeps_specific_personal_data_marker(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "报名表-待补个人信息.xlsx"
            with ZipFile(path, "w") as archive:
                archive.writestr("xl/workbook.xml", "<workbook />")

            self.assertEqual(_pending_markers(path), ["待补个人信息"])


if __name__ == "__main__":
    unittest.main()
