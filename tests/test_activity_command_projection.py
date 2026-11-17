"""Fail-closed tests for the bounded Activity command preview grammar."""
import json
import unittest

from commandcore_server.activity_trace import safe_trace
from commandcore_server.activity_visibility import command_projection, safe_operation_detail


class SafeActivityCommandTests(unittest.TestCase):
    def test_trivial_developer_commands_have_validated_visibility(self):
        examples = (
            "pwd",
            "uname -a",
            "ls -la .",
            "df -h",
            "du -sh ./build",
            "git status --short",
            "git diff --stat",
            "git branch --show-current",
            "python3 --version",
            "python3 -m pytest -q tests",
            "pytest -q tests",
            "npm ci",
            "npm run build",
            "cargo fmt --check",
            "pip list",
        )
        for command in examples:
            with self.subTest(command=command):
                r = command_projection(command)
                self.assertEqual(r["command_visibility"], "validated")
                self.assertIn("command_display", r)
                self.assertEqual(r["command_steps"], [r["command_display"]])

    def test_safe_multistep_operator_structure(self):
        detail = safe_trace("shell.exec", {"command": "pwd && git status; npm test"})
        self.assertEqual(detail["command_visibility"], "validated")
        self.assertEqual(detail["step_operators"], ["&&", ";"])
        self.assertEqual(detail["command_steps"], ["pwd", "git status", "npm test"])
        self.assertEqual(detail["command_display"], "pwd && git status ; npm test")

    def test_unsupported_arguments_remain_structural(self):
        r = command_projection("python3 -c 'print(123)'")
        self.assertEqual(r["command_visibility"], "structure")
        self.assertNotIn("command_display", r)
        self.assertEqual(r["command_steps"], ["python3 (arguments withheld)"])
        r = command_projection("pwd && nonsense --unreviewed")
        self.assertEqual(r["command_visibility"], "structure")
        self.assertEqual(r["command_steps"][0], "pwd (arguments withheld)")
        self.assertIn("unrecognized command", r["command_steps"][1])
        self.assertNotIn("nonsense", json.dumps(r))

    def test_sensitive_and_secret_commands_never_copy_values(self):
        secret = "fixture-private-value-DO-NOT-DISPLAY"
        commands = (
            "ls /tmp/.env",
            "ls /home/operator/.ssh/id_rsa",
            "echo bearer " + secret,
            "curl -H 'Authorization: Bearer " + secret + "' https://example.org/",
            "export API_KEY=" + secret,
            "python3 -c 'print(\"" + secret + "\")'",
            "ls " + secret,
            "ls sk-" + "f" * 30,
            "ls ghp_" + "a" * 35,
            "ls /tmp/" + "0123456789abcdef" * 3,
        )
        for command in commands:
            with self.subTest(prefix=command.split()[0]):
                result = command_projection(command)
                self.assertEqual(result["command_visibility"], "withheld")
                self.assertNotIn("command_display", result)
                self.assertNotIn(secret, json.dumps(result))
                self.assertNotIn("ghp_", json.dumps(result))
                self.assertNotIn("sk-", json.dumps(result))

    def test_structural_parser_rejects_unreviewed_shell_syntax(self):
        for command in (
            "ls -la &&",
            "&& pwd",
            "pwd && ; ls",
            "ls '&&'",
            "pwd" + "\n" + "git status",
            "pwd $(id)",
            "pwd " + chr(96) + "id" + chr(96),
            "pwd > /tmp/log",
            "ls /tmp/a\\b",
            "pwd" + "\x1b[31m",
            "ls /tmp/a%0a",
            "git -c core.hooksPath=/tmp status",
        ):
            with self.subTest(command=command[:35]):
                self.assertEqual(command_projection(command)["command_visibility"], "withheld")

    def test_environment_override_withholds_even_safe_command(self):
        detail = safe_operation_detail(
            "shell.exec",
            {"command": "pwd", "env": {"API_TOKEN": "fixture-opaque-secret"}},
        )
        self.assertEqual(detail["command_visibility"], "withheld")
        self.assertNotIn("command_display", detail)
        self.assertNotIn("fixture-opaque-secret", json.dumps(detail))

    def test_browser_and_other_tools_are_unaffected(self):
        detail = safe_operation_detail("browser.open", {"url": "https://example.org/a"})
        self.assertEqual(detail["public_url"], "https://example.org/")
        self.assertNotIn("command_display", detail)
        self.assertNotIn("command_steps", detail)
        fs = safe_operation_detail("fs.stat", {"path": "/tmp/file.txt"})
        self.assertNotIn("command_visibility", fs)

    def test_oversized_invalid_inputs_rejected(self):
        for command in (None, 0, {}, "", "a" * 5000, "ls " + "a" * 500):
            self.assertEqual(command_projection(command)["command_visibility"], "withheld")

    def test_short_filename_can_be_quoted_but_shell_operator_cannot(self):
        r = command_projection("ls 'project files'")
        self.assertEqual(r["command_visibility"], "validated")
        self.assertEqual(r["command_display"], "ls 'project files'")
        self.assertEqual(command_projection("ls 'project|files'")["command_visibility"], "withheld")


if __name__ == "__main__":
    unittest.main()
