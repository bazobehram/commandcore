"""Regression checks for the compact shell receipt and command preview policy."""

import unittest
from types import SimpleNamespace

from commandcore_server import shell_receipt
from commandcore_server.mcp import MCPHandler
from commandcore_server.web_assets import web_asset

UUID = "bda4d9b2-4c8e-4483-ab71-cb18d9b3d74a"


class ShellPreviewTests(unittest.TestCase):
    def test_normal_commands_remain_visible(self):
        for cmd in (
            "git status",
            "ls -la /srv/project-private",
            "grep -R password source",
            "npm run build",
            "python3 -m unittest discover",
            "docker ps",
        ):
            with self.subTest(command=cmd):
                p = shell_receipt._cc_safe_shell_display({"command": cmd})
                self.assertEqual(p, {"command": cmd, "visibility": "visible"})

    def test_known_secret_values_are_masked(self):
        for cmd in (
            "export API_KEY=example_fake_value",
            "echo TOKEN=example_fake_value",
            "tool --token=example_fake_value",
            "echo " + "sk-" + "exampleFAKETOKENABCDEFGHIJK",
        ):
            with self.subTest(command=cmd):
                p = shell_receipt._cc_safe_shell_display({"command": cmd})
                self.assertEqual(p["visibility"], "redacted")
                self.assertNotIn("example_fake_value", p["command"])
                self.assertIn("[REDACTED]", p["command"])

    def test_high_risk_commands_and_env_hidden(self):
        for cmd in (
            "cat /tmp/.env",
            "cat /tmp/.ssh/id_ed25519",
            "printenv",
            "echo $API_KEY",
            "curl -H 'Authorization: Bearer example' https://example.org",
        ):
            with self.subTest(command=cmd):
                self.assertEqual(
                    shell_receipt._cc_safe_shell_display({"command": cmd}),
                    {"command": "", "visibility": "withheld"},
                )
        self.assertEqual(
            shell_receipt._cc_safe_shell_display(
                {"command": "git status", "env": {"VAR": "value"}}
            )["visibility"],
            "withheld",
        )

    @staticmethod
    def card(cmd, stdout="some output"):
        payload = {
            "_ui_operation": {
                "operation_id": UUID,
                "device": "test-node",
                "duration_ms": 17,
            },
            "execution_id": UUID,
            "status": "ok",
            "exit_code": 0,
            "stdout": stdout,
            "stderr": "",
        }
        return shell_receipt.build_shell_card({"command": cmd}, payload)

    def test_safe_result_contains_command_and_output(self):
        card = self.card("git status", "clean")
        self.assertEqual(card["operation_id"], UUID)
        self.assertEqual(card["command_visibility"], "visible")
        self.assertEqual(card["command"], "git status")
        self.assertEqual(card["stdout"], "clean")

    def test_sensitive_command_does_not_echo_raw_stdout(self):
        card = self.card("export API_KEY=example_fake_value", "example_fake_value")
        self.assertEqual(card["command_visibility"], "redacted")
        self.assertEqual(card["stdout"], "")
        self.assertNotIn("example_fake_value", str(card))
        card = self.card("cat /tmp/.env", "unknown_secret")
        self.assertEqual(card["command_visibility"], "withheld")
        self.assertEqual(card["command"], "")
        self.assertEqual(card["stdout"], "")

    def test_output_labels_masked(self):
        card = self.card(
            "git status", "API_KEY=example_fake_value\nBearer demo_secret_value"
        )
        self.assertNotIn("example_fake_value", card["stdout"])
        self.assertNotIn("demo_secret_value", card["stdout"])

    def test_asset_contains_handshake_and_fixed_uuid_pattern(self):
        html = web_asset("shell-compact-v25.html").read_text(encoding="utf-8")
        self.assertIn("ui/initialize", html)
        self.assertIn("ui/notifications/initialized", html)
        self.assertIn("(?:[0-9a-f]{4}-){3}", html)
        self.assertNotIn(
            "Command preview protected because the text may contain credentials.",
            html,
        )
        self.assertIn("Loading command preview", html)
        self.assertIn("V25", html)

    def test_mcp_advertises_shell_v25(self):
        service = SimpleNamespace(live_activity=SimpleNamespace(), db=SimpleNamespace())
        handler = MCPHandler(
            service,
            SimpleNamespace(inc=lambda *args: None),
            "test-release",
            definitions=[
                {
                    "name": "shell.exec",
                    "description": "Run a command",
                    "inputSchema": {"type": "object", "properties": {}},
                }
            ],
        )
        self.assertEqual(handler.ui_specs["shell.exec"][0], shell_receipt.SHELL_UI_URI)
        self.assertIn(shell_receipt.SHELL_UI_URI, handler.ui_resources)
        tool = next(x for x in handler.definitions if x["name"] == "shell.exec")
        self.assertEqual(tool["_meta"]["ui"]["resourceUri"], shell_receipt.SHELL_UI_URI)


if __name__ == "__main__":
    unittest.main()
