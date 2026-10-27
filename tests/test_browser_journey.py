import ast
import pathlib
import time
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from commandcore_server.auth import READ_SCOPE, STANDARD_SCOPE
from commandcore_server.browser_gateway import (
    BrowserError,
    BrowserGateway,
    OwnedSession,
)
from commandcore_server.models import Principal
from commandcore_server.tools import TOOL_DEFINITIONS, ToolError, ToolService


class Connection:
    async def __aenter__(self):
        return object()

    async def __aexit__(self, *args):
        return False


class JourneyTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.g = BrowserGateway(
            base_url="http://steel:3000",
            cdp_url="ws://steel:3000",
            allow_hosts=("*",),
            public_base_url="https://commandcore.test",
        )
        self.owner = ("https://idp.test", "owner", "app")
        self.e = OwnedSession("a" * 36, target_id="b" * 36)
        self.g.sessions[self.owner] = self.e
        self.cdp = MagicMock()
        self.cdp.attach_page = AsyncMock(return_value=("session", "b" * 36))
        self.cdp.send = AsyncMock(return_value={})

    def patches(self):
        return (
            patch.object(
                self.g, "_cdp_socket_uri", new=AsyncMock(return_value="ws://test")
            ),
            patch(
                "commandcore_server.browser_gateway.websockets.connect",
                return_value=Connection(),
            ),
            patch("commandcore_server.browser_gateway.CDP", return_value=self.cdp),
            patch("commandcore_server.browser_gateway.asyncio.sleep", new=AsyncMock()),
        )

    async def perform(self, name, args):
        with self.patches()[0], self.patches()[1], self.patches()[2], self.patches()[3]:
            await self.g._perform_action(self.owner, self.e, name, args)

    async def call(self, name, args=None, subject="owner"):
        return await self.g.call(
            issuer=self.owner[0],
            subject=subject,
            client_id=self.owner[2],
            name=name,
            args=args or {},
        )

    def publish(
        self, url="https://example.com/page?q=public", name="browser.open", args=None
    ):
        self.g._publish_frame(
            self.e,
            {"screenshot_base64": "iVBORw0KGgo=", "title": "Example", "url": url},
            name,
            args or {},
            human=False,
        )

    def ref(self, **override):
        item = {
            "page": "https://example.com/",
            "href": "https://example.org/product",
            "target": "https://example.org/product",
            "position": 2,
            "label": "Product details",
            "expires": time.monotonic() + 90,
        }
        item.update(override)
        self.e.link_targets["r" * 24] = item
        return item

    async def test_links_have_only_opaque_refs_labels_and_sites(self):
        self.cdp.send = AsyncMock(
            return_value={
                "result": {
                    "value": {
                        "url": "https://example.com/",
                        "links": [
                            {
                                "position": 1,
                                "label": "Product",
                                "href": "https://example.org/product?variant=blue",
                            },
                            {
                                "position": 2,
                                "label": "Add to cart",
                                "href": "https://example.org/cart/add",
                            },
                            {
                                "position": 3,
                                "label": "A",
                                "href": "https://example.org/checkout",
                            },
                            {
                                "position": 4,
                                "label": "B",
                                "href": "https://example.org/page?token=secret",
                            },
                            {
                                "position": 5,
                                "label": "C",
                                "href": "javascript:alert(1)",
                            },
                        ],
                    }
                }
            }
        )
        with self.patches()[0], self.patches()[1], self.patches()[2]:
            result = await self.g._visible_links(self.e)
        self.assertEqual(result["count"], 1)
        self.assertEqual(set(result["links"][0]), {"link_ref", "label", "site"})
        self.assertEqual(len(result["links"][0]["link_ref"]), 24)
        self.assertNotIn("variant", str(result))
        self.assertNotIn("secret", str(result))
        expression = self.cdp.send.await_args.args[1]["expression"]
        for text in [
            "document.elementFromPoint",
            '[aria-hidden="true"]',
            "form,button",
            "hasAttribute('download')",
        ]:
            self.assertIn(text, expression)
        self.assertNotIn("document.cookie", expression)
        self.assertNotIn(".value", expression)

    async def test_follow_revalidates_then_navigates_without_mouse_input(self):
        item = self.ref()
        self.cdp.send = AsyncMock(
            side_effect=[
                {
                    "result": {
                        "value": {
                            "valid": True,
                            "url": item["page"],
                            "href": item["href"],
                            "label": item["label"],
                        }
                    }
                },
                {},
            ]
        )
        args = {"link_ref": "r" * 24}
        await self.perform("browser.follow", args)
        self.assertEqual(
            [c.args[0] for c in self.cdp.send.await_args_list],
            ["Runtime.evaluate", "Page.navigate"],
        )
        self.assertEqual(
            self.cdp.send.await_args_list[1].args[1], {"url": item["target"]}
        )
        self.assertFalse(self.e.link_targets)

    async def test_expired_reference_never_dispatches(self):
        self.ref(expires=0)
        with self.assertRaisesRegex(BrowserError, "expired"):
            await self.perform("browser.follow", {"link_ref": "r" * 24})
        self.cdp.send.assert_not_awaited()

    async def test_foreign_or_used_reference_never_dispatches(self):
        self.ref()
        with self.assertRaises(BrowserError):
            await self.perform("browser.follow", {"link_ref": "z" * 24})
        self.assertFalse(self.e.link_targets)
        self.cdp.send.assert_not_awaited()

    async def test_changed_covered_or_redirected_link_never_navigates(self):
        for field, value in [
            ("valid", False),
            ("href", "https://evil.invalid/"),
            ("url", "https://example.com/new"),
            ("label", "Pay now"),
        ]:
            with self.subTest(field=field):
                item = self.ref()
                now = {
                    "valid": True,
                    "url": item["page"],
                    "href": item["href"],
                    "label": item["label"],
                }
                now[field] = value
                self.cdp.send = AsyncMock(return_value={"result": {"value": now}})
                with self.assertRaisesRegex(BrowserError, "changed"):
                    await self.perform("browser.follow", {"link_ref": "r" * 24})
                self.assertEqual(
                    [c.args[0] for c in self.cdp.send.await_args_list],
                    ["Runtime.evaluate"],
                )

    async def test_back_and_forward_use_get_navigation_not_browser_history_replay(self):
        self.publish("https://example.com/one")
        self.publish("https://example.com/two")
        args = {}
        await self.perform("browser.back", args)
        self.assertEqual(args["_navigation_index"], 0)
        self.assertEqual(self.cdp.send.await_args.args[0], "Page.navigate")
        self.publish("https://example.com/one", "browser.back", args)
        self.assertFalse(self.g._frame(self.e, {})["can_go_back"])
        self.assertTrue(self.g._frame(self.e, {})["can_go_forward"])
        args = {}
        await self.perform("browser.forward", args)
        self.assertEqual(args["_navigation_index"], 1)
        self.publish("https://example.com/two", "browser.forward", args)
        self.assertFalse(self.g._frame(self.e, {})["can_go_forward"])

    async def test_empty_history_never_dispatches(self):
        for name in ["browser.back", "browser.forward"]:
            with self.assertRaises(BrowserError):
                await self.perform(name, {})
        self.cdp.send.assert_not_awaited()

    def test_history_bound_forward_branch_and_query_redaction(self):
        for i in range(25):
            self.publish("https://example.com/p" + str(i) + "?secret=value")
        self.assertEqual(len(self.e.navigation_pages), 20)
        self.assertNotIn("secret", str(self.g._frame(self.e, {})["recent_pages"]))
        self.publish(
            "https://example.com/p20", "browser.back", {"_navigation_index": 15}
        )
        self.publish("https://example.com/new")
        self.assertEqual(len(self.e.navigation_pages), 17)
        self.assertFalse(self.g._frame(self.e, {})["can_go_forward"])

    async def test_private_handoff_clears_history_and_refs_and_hides_metadata(self):
        self.publish()
        self.ref()
        await self.call("browser.handoff")
        self.assertFalse(self.e.navigation_pages)
        self.assertFalse(self.e.link_targets)
        frame = await self.call("browser.frame")
        for key in [
            "recent_pages",
            "can_go_back",
            "can_go_forward",
            "url",
            "screenshot_base64",
        ]:
            self.assertNotIn(key, frame)
        for name in [
            "browser.links",
            "browser.follow",
            "browser.back",
            "browser.forward",
        ]:
            with self.assertRaisesRegex(BrowserError, "paused for human"):
                await self.call(
                    name, {"link_ref": "r" * 24} if name == "browser.follow" else {}
                )

    async def test_other_owner_cannot_read_or_navigate(self):
        self.publish()
        self.ref()
        for name in [
            "browser.links",
            "browser.follow",
            "browser.back",
            "browser.forward",
        ]:
            with self.assertRaisesRegex(BrowserError, "no browser session"):
                await self.call(name, subject="other")
        self.assertTrue(self.e.link_targets)

    async def test_uncertain_navigation_clears_history_and_does_not_retry(self):
        self.publish()
        args = {}

        async def uncertain(*a, **kw):
            a[3]["_navigation_dispatched"] = True
            raise RuntimeError("capture failed")

        with (
            patch.object(
                self.g, "_perform_action", new=AsyncMock(side_effect=uncertain)
            ) as action,
            self.assertRaises(RuntimeError),
        ):
            await self.call("browser.back", args)
        self.assertEqual(action.await_count, 1)
        self.assertFalse(self.e.navigation_pages)
        self.assertFalse(self.e.action_running)

    def test_navigation_policy_rejects_action_and_credential_links(self):
        for url in [
            "https://example.com/checkout",
            "https://example.com/delete/",
            "https://example.com/p?token=x",
            "https://example.com/p?action=delete",
            "https://user:secret@example.com/",
            "http://example.com/",
        ]:
            with self.subTest(url=url), self.assertRaises(BrowserError):
                self.g._navigation_url(url)
        self.assertEqual(
            self.g._navigation_url(
                "https://www.google.com/url?q=https%3A%2F%2Fexample.org%2Fproduct"
            ),
            "https://example.org/product",
        )

    def test_success_and_inflight_status_are_distinct(self):
        self.assertEqual(self.g._action_label("browser.open"), "Navigating")
        self.publish()
        self.assertEqual(self.e.last_action, "Page opened")
        self.assertEqual(self.e.recent_actions[-1]["status"], "ok")

    def test_toolservice_isolation_implementation_unchanged(self):
        # Port the b10 candidate isolation gate without /test/ fixture paths.
        # A changed ToolService requires an explicit baseline review.
        import hashlib

        path = (
            pathlib.Path(__file__).resolve().parents[1]
            / "apps/server/commandcore_server/tools.py"
        )
        source = path.read_text()
        cls = next(
            n
            for n in ast.walk(ast.parse(source))
            if isinstance(n, ast.ClassDef) and n.name == "ToolService"
        )
        segment = ast.get_source_segment(source, cls)
        self.assertEqual(
            hashlib.sha256(segment.encode()).hexdigest(),
            # Timeline integration adds observation hooks to ToolService;
            # Browser ownership and lease handling remain covered below.
            "caf58a4b4cefd1ef1cf75ddbd57a2cb89f8f1d65e8bb6ac4af439d79cffc9c74",
        )


class ToolBoundaryTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        class DB:
            def add_audit(self, **kwargs):
                return 1

        self.g = BrowserGateway(
            base_url="http://steel:3000",
            cdp_url="ws://steel:3000",
            allow_hosts=("example.com",),
        )
        self.p = Principal(
            subject="owner",
            issuer="https://idp.test",
            client_id="app",
            auth_kind="oauth2",
            scopes=(READ_SCOPE, STANDARD_SCOPE),
        )
        self.s = ToolService(DB(), None, 300, browser=self.g)
        self.owner = (self.p.issuer, self.p.subject, self.p.client_id)
        self.s._browser_conversation_leases[self.owner] = (
            self.s.live_activity.session_tag("chat-A")
        )
        self.g.sessions[self.owner] = OwnedSession("a" * 36)

    async def test_new_tools_use_existing_standard_scope(self):
        low = Principal(
            subject=self.p.subject,
            issuer=self.p.issuer,
            client_id=self.p.client_id,
            auth_kind="oauth2",
            scopes=(READ_SCOPE,),
        )
        definitions = {d["name"]: d for d in TOOL_DEFINITIONS}
        for name in [
            "browser.links",
            "browser.follow",
            "browser.back",
            "browser.forward",
        ]:
            self.assertEqual(
                definitions[name]["securitySchemes"],
                definitions["browser.open"]["securitySchemes"],
            )
            with self.assertRaises(ToolError) as caught:
                await self.s.call(low, name, {}, host_session="chat-A")
            self.assertEqual(caught.exception.code, "insufficient_scope")

    async def test_cross_conversation_and_missing_context_rejected_before_gateway(self):
        with patch.object(self.g, "call", new=AsyncMock()) as call:
            for name in [
                "browser.links",
                "browser.follow",
                "browser.back",
                "browser.forward",
            ]:
                for session in [None, "chat-B"]:
                    with self.assertRaises(ToolError) as caught:
                        await self.s.call(self.p, name, {}, host_session=session)
                    self.assertIn(
                        caught.exception.code,
                        {
                            "browser_conversation_required",
                            "browser_conversation_in_use",
                        },
                    )
            call.assert_not_awaited()

    async def test_same_conversation_delegates_to_gateway_and_private_pause_still_blocks(
        self,
    ):
        with patch.object(
            self.g,
            "_visible_links",
            new=AsyncMock(return_value={"links": [], "count": 0}),
        ) as read:
            result = await self.s.call(
                self.p, "browser.links", {}, host_session="chat-A"
            )
            self.assertEqual(result["count"], 0)
            read.assert_awaited_once()
        self.g.sessions[self.owner].paused_for_human = True
        for name in [
            "browser.links",
            "browser.follow",
            "browser.back",
            "browser.forward",
        ]:
            with self.assertRaisesRegex(ToolError, "paused for human"):
                await self.s.call(self.p, name, {}, host_session="chat-A")


if __name__ == "__main__":
    unittest.main()
