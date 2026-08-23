from __future__ import annotations

import unittest

from apps.api.tests.fixtures.mcp_echo_server import _handle


class McpEchoFixtureContextTest(unittest.TestCase):
    def test_fixture_exposes_real_context_entries_and_reads(self) -> None:
        initialize = _handle(
            {
                "jsonrpc": "2.0",
                "id": "initialize",
                "method": "initialize",
                "params": {},
            }
        )
        self.assertEqual(
            initialize["result"]["capabilities"],
            {
                "tools": {},
                "resources": {"listChanged": False, "subscribe": False},
                "prompts": {"listChanged": False},
            },
        )

        resource_list = _handle({"jsonrpc": "2.0", "id": "resources", "method": "resources/list"})
        template_list = _handle(
            {"jsonrpc": "2.0", "id": "templates", "method": "resources/templates/list"}
        )
        prompt_list = _handle({"jsonrpc": "2.0", "id": "prompts", "method": "prompts/list"})

        resource = resource_list["result"]["resources"][0]
        template = template_list["result"]["resourceTemplates"][0]
        prompt = prompt_list["result"]["prompts"][0]
        self.assertEqual(resource["uri"], "fixture://public/project-overview")
        self.assertEqual(template["uriTemplate"], "fixture://public/{name}")
        self.assertEqual(prompt["name"], "fixture-summary")

        read = _handle(
            {
                "jsonrpc": "2.0",
                "id": "read",
                "method": "resources/read",
                "params": {"uri": resource["uri"]},
            }
        )
        prompt_get = _handle(
            {
                "jsonrpc": "2.0",
                "id": "prompt-get",
                "method": "prompts/get",
                "params": {"name": prompt["name"], "arguments": {"topic": "边界"}},
            }
        )
        self.assertIn("公开 Fixture", read["result"]["contents"][0]["text"])
        self.assertIn("边界", prompt_get["result"]["messages"][0]["content"]["text"])


if __name__ == "__main__":
    unittest.main()
