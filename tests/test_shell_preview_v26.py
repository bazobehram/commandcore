"""V26 shell preview: generated source stays visible without exposing secrets."""

import unittest
from types import SimpleNamespace

from commandcore_server import shell_receipt
from commandcore_server.mcp import MCPHandler
from commandcore_server.web_assets import web_asset

OPERATION_ID = "14e67af7-234f-4c91-882e-b91f3e7a9c01"


class V26VisibilityTests(unittest.TestCase):
    def preview(self, command):
        return shell_receipt._cc_safe_shell_display({"command": command})

    def test_safe_shell_prologue_is_not_env_dump(self):
        for command in (
            "set -e\nnode --check index.html",
            "set -euo pipefail\npython3 -m compileall .",
            "env NODE_ENV=production npm run build",
            "curl -H 'Accept: application/json' https://example.invalid",
            "python3 -c 'print(loaded_ui=True)'",
            "echo foo=bar",
        ):
            with self.subTest(command=command):
                self.assertEqual(self.preview(command)["visibility"], "visible")

    def test_large_generated_script_has_nonempty_bounded_preview(self):
        command = "python3 - <<'PY'\nprint('created')\n" + "# docs\n" * 2000 + "PY"
        result = self.preview(command)
        self.assertEqual(result["visibility"], "shortened")
        self.assertIn("python3 - <<'PY'", result["command"])
        self.assertIn("preview shortened", result["command"])
        self.assertLess(len(result["command"]), 2600)
        self.assertEqual(result["reason"], "command_preview_limit")

        card = shell_receipt.build_shell_card(
            {"command": command},
            {
                "status": "ok",
                "exit_code": 0,
                "stdout": "sensitive runtime output",
                "_ui_operation": {
                    "operation_id": OPERATION_ID,
                    "device": "test-device",
                },
            },
        )
        self.assertEqual(card["command_visibility"], "shortened")
        self.assertEqual(card["stdout"], "")
        self.assertEqual(card["preview_reason"], "command_preview_limit")

    def test_source_heredoc_can_document_env(self):
        command = (
            "cat > /home/dev/projects/todo-app/index.html <<'EOF'\n"
            "<p>The .env file is documentation, not being read</p>\nEOF"
        )
        result = self.preview(command)
        self.assertEqual(result["visibility"], "visible")
        self.assertIn("index.html", result["command"])

    def test_sensitive_file_and_env_dump_remain_protected(self):
        cases = {
            "cat /home/dev/.env": "protected_file_reference",
            "cat /home/dev/.ssh/id_ed25519": "protected_file_reference",
            "env": "environment_or_protected_command",
            "printenv": "environment_or_protected_command",
            "set": "environment_or_protected_command",
            "set -x": "shell_tracing",
            "echo $API_KEY": "secret_variable",
            "curl -H 'Authorization: Bearer placeholder' https://example.invalid": "authorization_header",
        }
        for command, reason in cases.items():
            with self.subTest(command=command):
                result = self.preview(command)
                self.assertEqual(result["visibility"], "withheld")
                self.assertEqual(result["command"], "")
                self.assertEqual(result["reason"], reason)

    def test_real_key_assignments_are_masked(self):
        result = self.preview("export API_KEY=EXAMPLE_DO_NOT_USE")
        self.assertEqual(result["visibility"], "redacted")
        self.assertNotIn("EXAMPLE_DO_NOT_USE", result["command"])

    def test_current_and_previous_assets(self):
        html = web_asset("shell-compact-v26.html").read_text(encoding="utf-8")
        self.assertIn("V26", html)
        self.assertIn("ui/initialize", html)
        self.assertIn("preview_reason", html)
        self.assertIn("Shortened", html.replace("shortened", "Shortened"))
        self.assertNotIn(
            "Sensitive command withheld by the server security policy.", html
        )
        self.assertIn(
            "V25", web_asset("shell-compact-v25.html").read_text(encoding="utf-8")
        )
        tools = SimpleNamespace(live_activity=SimpleNamespace(), db=SimpleNamespace())
        h = MCPHandler(
            tools,
            SimpleNamespace(inc=lambda *args: None),
            "test",
            definitions=[
                {
                    "name": "shell.exec",
                    "description": "shell",
                    "inputSchema": {"type": "object", "properties": {}},
                }
            ],
        )
        self.assertEqual(h.ui_specs["shell.exec"][0], shell_receipt.SHELL_UI_URI)
        self.assertIn(
            "ui://commandcore/shell-compact-v25-20261112.html", h.ui_resources
        )


if __name__ == "__main__":
    unittest.main()
