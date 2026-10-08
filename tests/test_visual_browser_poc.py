"""Safety and MCP serialization tests for the opt-in visual browser preview."""

import asyncio

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


class BrowserReleaseContractTests(unittest.IsolatedAsyncioTestCase):
    async def test_release_uses_post_endpoint_and_checks_ack(self):
        from unittest.mock import patch

        class Response:
            def raise_for_status(self):
                pass

            def json(self):
                return {"status": "released"}

        class Client:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                pass

            async def post(self, url):
                self.url = url
                return Response()

        client = Client()
        gateway = BrowserGateway(
            base_url="http://steel:3000",
            cdp_url="ws://steel:3000",
            allow_hosts=("example.com",),
        )
        owner = ("issuer", "account", "client")
        gateway.sessions[owner] = OwnedSession("f" * 36)
        with patch(
            "commandcore_server.browser_gateway.httpx.AsyncClient", return_value=client
        ):
            result = await gateway._release(owner)
        self.assertTrue(result["closed"])
        self.assertEqual(
            client.url, "http://steel:3000/v1/sessions/" + "f" * 36 + "/release"
        )
        self.assertNotIn(owner, gateway.sessions)


class BrowserTargetOwnershipTests(unittest.IsolatedAsyncioTestCase):
    async def test_browser_attaches_pinned_tab_not_first_visible_tab(self):
        from commandcore_server.browser_gateway import CDP

        class CDPFixture(CDP):
            def __init__(self):
                self.commands = []

            async def send(self, method, params=None, session=None):
                self.commands.append((method, params or {}, session))
                if method == "Target.getTargets":
                    return {
                        "targetInfos": [
                            {
                                "type": "page",
                                "targetId": "unrelated",
                                "url": "https://other.invalid/",
                            },
                            {
                                "type": "page",
                                "targetId": "owned",
                                "url": "https://example.com/",
                            },
                        ]
                    }
                if method == "Target.attachToTarget":
                    return {"sessionId": "owned-session"}
                return {}

        fixture = CDPFixture()
        session, target = await fixture.attach_page("owned")
        self.assertEqual((session, target), ("owned-session", "owned"))
        attached = [
            params["targetId"]
            for method, params, _ in fixture.commands
            if method == "Target.attachToTarget"
        ]
        self.assertEqual(attached, ["owned"])
        with self.assertRaisesRegex(BrowserError, "disappeared"):
            await fixture.attach_page("missing")


class BrowserHumanHandoffTests(unittest.IsolatedAsyncioTestCase):
    async def test_handoff_pauses_agent_and_is_subject_scoped(self):
        gateway = BrowserGateway(
            base_url="http://steel:3000",
            cdp_url="ws://steel:3000",
            allow_hosts=("example.com",),
            public_base_url="http://127.0.0.1:3898",
        )
        owner = ("issuer", "alice", "client")
        gateway.sessions[owner] = OwnedSession("a" * 36, target_id="owned-tab")
        handoff = gateway._handoff(owner)
        self.assertEqual(handoff["expires_in_seconds"], 600)
        with self.assertRaisesRegex(BrowserError, "already active"):
            gateway._handoff(owner)
        token = handoff["handoff_url"].rsplit("/", 1)[-1]
        self.assertEqual(gateway.handoff_owner(token, "alice", "issuer"), owner)
        with self.assertRaises(BrowserError):
            gateway.handoff_owner(token, "bob", "issuer")
        with self.assertRaisesRegex(BrowserError, "paused"):
            await gateway.call(
                subject="alice",
                issuer="issuer",
                client_id="client",
                name="browser.observe",
                args={},
            )
        self.assertEqual(
            await gateway.human_resume(token, "alice", "issuer"),
            {"state": "resumed_for_agent"},
        )
        with self.assertRaises(BrowserError):
            gateway.handoff_owner(token, "alice", "issuer")

    async def test_expired_handoff_does_not_authorize_human(self):
        gateway = BrowserGateway(
            base_url="http://steel:3000",
            cdp_url="ws://steel:3000",
            allow_hosts=("example.com",),
            public_base_url="http://127.0.0.1:3898",
        )
        owner = ("issuer", "alice", "client")
        gateway.sessions[owner] = OwnedSession("a" * 36)
        token = gateway._handoff(owner)["handoff_url"].rsplit("/", 1)[-1]
        gateway.sessions[owner].handoff_until = 0
        with self.assertRaises(BrowserError):
            gateway.handoff_owner(token, "alice", "issuer")
        self.assertIsNone(gateway.sessions[owner].handoff_token)
        self.assertTrue(gateway.sessions[owner].paused_for_human)
        with self.assertRaisesRegex(BrowserError, "paused"):
            await gateway.call(
                subject="alice",
                issuer="issuer",
                client_id="client",
                name="browser.observe",
                args={},
            )

    async def test_external_http_handoff_is_rejected(self):
        gateway = BrowserGateway(
            base_url="http://steel:3000",
            cdp_url="ws://steel:3000",
            allow_hosts=("example.com",),
            public_base_url="http://commandcore.example.com",
        )
        owner = ("issuer", "alice", "client")
        gateway.sessions[owner] = OwnedSession("a" * 36)
        with self.assertRaisesRegex(BrowserError, "HTTPS"):
            gateway._handoff(owner)


class BrowserHandoffRaceTests(unittest.IsolatedAsyncioTestCase):
    async def test_agent_queued_before_handoff_must_recheck_lock(self):
        gateway = BrowserGateway(
            base_url="http://steel:3000",
            cdp_url="ws://steel:3000",
            allow_hosts=("example.com",),
            public_base_url="http://127.0.0.1:3898",
        )
        owner = ("issuer", "alice", "client")
        entry = OwnedSession("b" * 36)
        gateway.sessions[owner] = entry
        async with entry.lock:
            task = asyncio.create_task(
                gateway.call(
                    subject="alice",
                    issuer="issuer",
                    client_id="client",
                    name="browser.observe",
                    args={},
                )
            )
            await asyncio.sleep(0)
            gateway._handoff(owner)
            self.assertFalse(task.done())
        with self.assertRaisesRegex(BrowserError, "paused"):
            await task

    async def test_human_queued_before_resume_must_recheck_token(self):
        gateway = BrowserGateway(
            base_url="http://steel:3000",
            cdp_url="ws://steel:3000",
            allow_hosts=("example.com",),
            public_base_url="http://127.0.0.1:3898",
        )
        owner = ("issuer", "alice", "client")
        entry = OwnedSession("c" * 36)
        gateway.sessions[owner] = entry
        token = gateway._handoff(owner)["handoff_url"].rsplit("/", 1)[-1]
        async with entry.lock:
            task = asyncio.create_task(
                gateway.human_call(
                    token, "alice", "browser.observe", {}, issuer="issuer"
                )
            )
            await asyncio.sleep(0)
            entry.handoff_token = None
            entry.paused_for_human = False
            self.assertFalse(task.done())
        with self.assertRaisesRegex(BrowserError, "handoff not found"):
            await task

    async def test_resume_waits_for_inflight_human_action(self):
        gateway = BrowserGateway(
            base_url="http://steel:3000",
            cdp_url="ws://steel:3000",
            allow_hosts=("example.com",),
            public_base_url="http://127.0.0.1:3898",
        )
        owner = ("issuer", "alice", "client")
        entry = OwnedSession("d" * 36)
        gateway.sessions[owner] = entry
        token = gateway._handoff(owner)["handoff_url"].rsplit("/", 1)[-1]
        async with entry.lock:
            task = asyncio.create_task(gateway.human_resume(token, "alice", "issuer"))
            await asyncio.sleep(0)
            self.assertFalse(task.done())
            self.assertTrue(entry.paused_for_human)
        self.assertEqual((await task)["state"], "resumed_for_agent")
        self.assertFalse(entry.paused_for_human)

    async def test_handoff_subject_and_issuer_are_required(self):
        gateway = BrowserGateway(
            base_url="http://steel:3000",
            cdp_url="ws://steel:3000",
            allow_hosts=("example.com",),
            public_base_url="http://127.0.0.1:3898",
        )
        owner = ("issuer-one", "alice", "client")
        gateway.sessions[owner] = OwnedSession("e" * 36)
        token = gateway._handoff(owner)["handoff_url"].rsplit("/", 1)[-1]
        with self.assertRaises(BrowserError):
            gateway.handoff_owner(token, "alice", "different-issuer")
        self.assertEqual(gateway.handoff_owner(token, "alice", "issuer-one"), owner)
