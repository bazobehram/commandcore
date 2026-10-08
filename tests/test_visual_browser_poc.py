"""Safety and MCP serialization tests for the opt-in visual browser preview."""

import unittest

from commandcore_server.browser_gateway import (
    BROWSER_TOOL_NAMES,
    BrowserError,
    BrowserGateway,
    OwnedSession,
    check_url,
)
from commandcore_server.config import Settings
from commandcore_server.mcp import _tool_result
from commandcore_server.models import Principal
from commandcore_server.permissions import allowed
from commandcore_server.tools import TOOL_DEFINITIONS, ToolError, ToolService


class BrowserSurfaceTests(unittest.TestCase):
    def test_allowlisted_https_only(self):
        self.assertEqual(
            check_url("https://example.com/path", ("example.com",)),
            "https://example.com/path",
        )
        self.assertEqual(
            check_url("https://docs.example.com/", ("*.example.com",)),
            "https://docs.example.com/",
        )
        for url in (
            "http://example.com",
            "file:///etc/passwd",
            "https://127.0.0.1",
            "https://localhost/",
            "https://example.com:3999/",
            "https://evil-example.com",
            "https://user:password@example.com/",
            "https://example.com.evil.test",
            "https://[::1]/",
            "https://example.com:bad/",
        ):
            with self.subTest(url=url), self.assertRaises(BrowserError):
                check_url(url, ("example.com",))

    def test_all_browser_tools_require_standard_scope(self):
        tools = {t["name"]: t for t in TOOL_DEFINITIONS}
        self.assertEqual(set(tools) & BROWSER_TOOL_NAMES, BROWSER_TOOL_NAMES)
        for name in BROWSER_TOOL_NAMES:
            with self.subTest(name=name):
                self.assertFalse(allowed("READ_ONLY", name))
                self.assertTrue(allowed("STANDARD", name))
                self.assertEqual(
                    tools[name]["securitySchemes"][0]["scopes"],
                    ["commandcore:standard"],
                )

    def test_images_are_not_duplicated_as_text(self):
        result = _tool_result(
            {"title": "Example Domain", "screenshot_base64": "iVBORw0KGgo="},
            modern=True,
        )
        self.assertEqual(
            result["content"][1],
            {"type": "image", "mimeType": "image/png", "data": "iVBORw0KGgo="},
        )
        self.assertNotIn("screenshot_base64", result["structuredContent"])
        self.assertNotIn("iVBORw", result["content"][0]["text"])

    def test_browser_feature_is_opt_in(self):
        settings = Settings(api_token="x" * 40, panel_session_secret="y" * 40)
        self.assertFalse(settings.browser_enabled)
        enabled = Settings(
            api_token="x" * 40,
            panel_session_secret="y" * 40,
            browser_enabled=True,
            browser_allow_hosts=("example.com",),
        )
        enabled.validate()
        with self.assertRaises(RuntimeError):
            Settings(
                api_token="x" * 40,
                panel_session_secret="y" * 40,
                browser_enabled=True,
                browser_allow_hosts=(),
            ).validate()

    def test_multiple_browser_owners_explicitly_disabled(self):
        with self.assertRaisesRegex(ValueError, "one active owner"):
            BrowserGateway(
                base_url="http://steel:3000",
                cdp_url="ws://steel:3000",
                allow_hosts=("example.com",),
                max_sessions=2,
            )


class FakeDb:
    def __init__(self):
        self.events = []

    def add_audit(self, **kwargs):
        self.events.append(kwargs)


class BrowserAuthorizationTests(unittest.IsolatedAsyncioTestCase):
    async def test_scope_denies_read_token_even_for_observe(self):
        db = FakeDb()
        svc = ToolService(db, None, 300, browser=None)
        principal = Principal(
            subject="alice", auth_kind="oauth2", scopes=("commandcore:read",)
        )
        with self.assertRaises(ToolError) as ctx:
            await svc.call(principal, "browser.observe", {})
        self.assertEqual(ctx.exception.code, "insufficient_scope")
        self.assertEqual(db.events[0]["status"], "error")

    async def test_disabled_is_fail_closed_with_standard_token(self):
        db = FakeDb()
        svc = ToolService(db, None, 300, browser=None)
        principal = Principal(
            subject="alice", auth_kind="oauth2", scopes=("commandcore:standard",)
        )
        with self.assertRaises(ToolError) as ctx:
            await svc.call(principal, "browser.observe", {})
        self.assertEqual(ctx.exception.code, "browser_disabled")
        self.assertEqual(db.events[0]["status"], "error")

    async def test_second_owner_is_denied_before_steel_call(self):
        gateway = BrowserGateway(
            base_url="http://steel:3000",
            cdp_url="ws://steel:3000",
            allow_hosts=("example.com",),
        )
        gateway.sessions[("issuer", "alice", "client")] = OwnedSession("alice-session")
        with self.assertRaisesRegex(BrowserError, "maximum concurrent"):
            await gateway._new_session(("issuer", "bob", "client"))


if __name__ == "__main__":
    unittest.main()
