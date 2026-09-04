from __future__ import annotations

import unittest

from apps.api.agent_supervisor.domains.attacks.penetration_lab import (
    _compromised_assets,
    list_learning_scenarios,
    run_learning_attack,
)


class PenetrationLearningLabTests(unittest.TestCase):
    def test_learning_lab_covers_seven_required_attack_surfaces(self) -> None:
        response = list_learning_scenarios()
        scenario_ids = {item["id"] for item in response["scenarios"]}

        self.assertEqual(response["scenario_count"], 7)
        self.assertEqual(
            scenario_ids,
            {
                "prompt-injection-mail",
                "system-prompt-leak",
                "sensitive-file-read",
                "tool-hijack-rce",
                "memory-poison-persist",
                "environment-context-pollution",
                "bulk-api-export",
            },
        )

    def test_every_learning_attack_has_vulnerable_and_guarded_result(self) -> None:
        for scenario in list_learning_scenarios()["scenarios"]:
            with self.subTest(scenario=scenario["id"]):
                result = run_learning_attack(
                    {
                        "scenario_id": scenario["id"],
                        "execute_in_sandbox": True,
                    }
                )

                self.assertTrue(result["summary"]["exploited_without_guard"])
                self.assertTrue(result["summary"]["blocked_with_guard"])
                self.assertEqual(result["vulnerable"]["decision"], "允许")
                self.assertIn(result["guarded"]["decision"], {"拒绝", "询问", "隔离"})
                self.assertTrue(result["summary"]["compromised_assets"])
                self.assertEqual(result["scenario"]["tool"], scenario["tool"])

    def test_tool_hijack_asset_survives_empty_probe_output(self) -> None:
        assets = _compromised_assets(
            "",
            tool_call={"tool": "code.run", "arguments": {"command": "python --payload powershell -enc <redacted>"}},
        )

        self.assertIn("危险命令载荷", assets)


if __name__ == "__main__":
    unittest.main()
