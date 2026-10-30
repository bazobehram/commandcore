"""Browser private-canary input guard: deny obvious AI form submissions."""

from __future__ import annotations

import unittest
import time
import secrets
from unittest.mock import AsyncMock, MagicMock, patch

from commandcore_server.browser_gateway import (
    BrowserError,
    BrowserGateway,
    OwnedSession,
)


class _Connection:
    async def __aenter__(self):
        return object()

    async def __aexit__(self, *args):
        return False


class ConsequentialActionGuardTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.gateway = BrowserGateway(
            base_url="http://steel:3000",
            cdp_url="ws://steel:3000",
            allow_hosts=("example.com",),
        )
        self.owner = ("https://idp.test", "owner", "test-app")
        self.entry = OwnedSession("f" * 36, target_id="c" * 36)
        self.cdp = MagicMock()
        self.cdp.attach_page = AsyncMock(return_value=("session", "c" * 36))
        self.cdp.send = AsyncMock(
            return_value={"result": {"type": "boolean", "value": False}}
        )
        self.connection = _Connection()

    def _patches(self):
        return (
            patch.object(
                self.gateway,
                "_cdp_socket_uri",
                new=AsyncMock(return_value="ws://127.0.0.1"),
            ),
            patch(
                "commandcore_server.browser_gateway.websockets.connect",
                return_value=self.connection,
            ),
            patch("commandcore_server.browser_gateway.CDP", return_value=self.cdp),
            patch("commandcore_server.browser_gateway.asyncio.sleep", new=AsyncMock()),
        )

    async def test_human_reload_fetches_fresh_page_resources(self):
        """Explicit owner reload bypasses cached scripts but does not clear cookies."""
        with (
            self._patches()[0],
            self._patches()[1],
            self._patches()[2],
            self._patches()[3],
        ):
            await self.gateway._perform_action(
                self.owner, self.entry, "browser.reload", {}, human=True
            )
        self.cdp.send.assert_awaited_once()
        self.assertEqual(self.cdp.send.await_args.args[0], "Page.reload")
        self.assertEqual(self.cdp.send.await_args.args[1], {"ignoreCache": True})

    async def test_agent_cannot_reload_private_page(self):
        self.gateway.sessions[self.owner] = self.entry
        with self.assertRaisesRegex(BrowserError, "unknown browser tool"):
            await self.gateway.call(
                subject=self.owner[1],
                issuer=self.owner[0],
                client_id=self.owner[2],
                name="browser.reload",
                args={},
            )
        self.cdp.send.assert_not_awaited()

    async def test_agent_enter_denied_before_any_key_dispatch(self):
        with (
            self._patches()[0],
            self._patches()[1],
            self._patches()[2],
            self._patches()[3],
            self.assertRaisesRegex(BrowserError, "form"),
        ):
            await self.gateway._perform_action(
                self.owner, self.entry, "browser.keypress", {"key": "Enter"}
            )
        self.cdp.send.assert_not_awaited()

    async def test_human_enter_allowed_after_separate_handoff_verification(self):
        with (
            self._patches()[0],
            self._patches()[1],
            self._patches()[2],
            self._patches()[3],
        ):
            await self.gateway._perform_action(
                self.owner, self.entry, "browser.keypress", {"key": "Enter"}, human=True
            )
        self.assertEqual(
            [call.args[0] for call in self.cdp.send.await_args_list],
            ["Input.dispatchKeyEvent", "Input.dispatchKeyEvent"],
        )

    async def test_agent_click_denied_when_dom_reports_sensitive_control(self):
        with (
            self._patches()[0],
            self._patches()[1],
            self._patches()[2],
            self._patches()[3],
            self.assertRaisesRegex(BrowserError, "browser.handoff"),
        ):
            await self.gateway._perform_action(
                self.owner, self.entry, "browser.click", {"x": 330, "y": 400}
            )
        methods = [call.args[0] for call in self.cdp.send.await_args_list]
        self.assertEqual(methods, ["Input.dispatchMouseEvent", "Runtime.evaluate"])
        expression = self.cdp.send.await_args_list[-1].args[1]["expression"]
        self.assertIn("document.elementFromPoint(330,400)", expression)
        self.assertIn("input[type=submit]", expression)
        for sensitive in (
            "form",
            "button",
            "label",
            "select",
            "textarea",
            "[contenteditable]",
            "[role=menuitem]",
            "[download]",
            "iframe",
            "object",
        ):
            with self.subTest(sensitive=sensitive):
                self.assertIn(sensitive, expression)
        self.assertIn("u.protocol==='https:'", expression)
        self.assertIn("u.origin===location.origin", expression)
        self.assertIn("!u.search", expression)
        self.assertIn("!u.hash", expression)
        self.assertIn("link.target==='_self'", expression)

    async def test_agent_click_denied_when_dom_check_missing(self):
        self.cdp.send = AsyncMock(return_value={})
        with (
            self._patches()[0],
            self._patches()[1],
            self._patches()[2],
            self._patches()[3],
            self.assertRaisesRegex(BrowserError, "browser.handoff"),
        ):
            await self.gateway._perform_action(
                self.owner, self.entry, "browser.click", {"x": 12, "y": 22}
            )
        self.assertNotIn(
            "mousePressed",
            [c.args[1].get("type") for c in self.cdp.send.await_args_list],
        )

    async def test_agent_non_form_click_still_works_in_cautious_mode(self):
        async def response(name, *_args, **_kwargs):
            return (
                {"result": {"type": "boolean", "value": True}}
                if name == "Runtime.evaluate"
                else {}
            )

        self.cdp.send = AsyncMock(side_effect=response)
        with (
            self._patches()[0],
            self._patches()[1],
            self._patches()[2],
            self._patches()[3],
        ):
            await self.gateway._perform_action(
                self.owner, self.entry, "browser.click", {"x": 110, "y": 180}
            )
        self.assertEqual(
            [call.args[1].get("type") for call in self.cdp.send.await_args_list],
            ["mouseMoved", None, "mousePressed", "mouseReleased"],
        )

    async def test_human_click_does_not_require_agent_dom_check(self):
        with (
            self._patches()[0],
            self._patches()[1],
            self._patches()[2],
            self._patches()[3],
        ):
            await self.gateway._perform_action(
                self.owner,
                self.entry,
                "browser.click",
                {"x": 110, "y": 180},
                human=True,
            )
        self.assertEqual(
            [call.args[0] for call in self.cdp.send.await_args_list],
            ["Input.dispatchMouseEvent"] * 3,
        )

    async def test_blocked_click_can_be_approved_once_only_by_private_owner(self):
        self.entry.frame_url = "https://example.com/settings"
        self.cdp.send = AsyncMock(
            return_value={"result": {"type": "boolean", "value": False}}
        )
        with (
            self._patches()[0],
            self._patches()[1],
            self._patches()[2],
            self._patches()[3],
            self.assertRaisesRegex(BrowserError, "browser.handoff"),
        ):
            await self.gateway._perform_action(
                self.owner, self.entry, "browser.click", {"x": 110, "y": 180}
            )
        self.assertEqual(self.entry.pending_click["x"], 110)
        self.assertEqual(self.entry.pending_click["y"], 180)
        self.assertEqual(
            self.entry.pending_click["url"], "https://example.com/settings"
        )
        self.gateway.sessions[self.owner] = self.entry
        token = secrets.token_urlsafe(32)
        self.entry.handoff_token = token
        self.entry.paused_for_human = True
        self.entry.handoff_until = time.monotonic() + 600
        with self.assertRaisesRegex(BrowserError, "unknown browser tool"):
            await self.gateway.call(
                subject=self.owner[1],
                issuer=self.owner[0],
                client_id=self.owner[2],
                name="browser.approve_click",
                args={},
            )
        pending = await self.gateway.human_call(
            token, self.owner[1], "browser.pending", {}, issuer=self.owner[0]
        )
        self.assertEqual(pending, {"pending": {"x": 110, "y": 180}})
        with (
            patch.object(
                self.gateway,
                "_snapshot_private_frame",
                new=AsyncMock(return_value={"url": "https://example.com/settings"}),
            ),
            patch.object(self.gateway, "_perform_action", new=AsyncMock()) as act,
            patch.object(
                self.gateway,
                "_snapshot",
                new=AsyncMock(
                    return_value={
                        "url": "https://example.com/settings",
                        "screenshot_base64": "dummy",
                    }
                ),
            ),
            patch.object(self.gateway, "_publish_frame"),
        ):
            await self.gateway.human_call(
                token, self.owner[1], "browser.approve_click", {}, issuer=self.owner[0]
            )
            act.assert_awaited_once()
            self.assertEqual(act.await_args.args[2], "browser.click")
            self.assertEqual(act.await_args.args[3], {"x": 110, "y": 180})
            self.assertTrue(act.await_args.kwargs["human"])
            with self.assertRaisesRegex(BrowserError, "expired"):
                await self.gateway.human_call(
                    token,
                    self.owner[1],
                    "browser.approve_click",
                    {},
                    issuer=self.owner[0],
                )
        self.assertIsNone(self.entry.pending_click)

    async def test_approval_rejects_changed_page_and_clears_pending(self):
        self.gateway.sessions[self.owner] = self.entry
        token = secrets.token_urlsafe(32)
        self.entry.handoff_token = token
        self.entry.paused_for_human = True
        self.entry.handoff_until = time.monotonic() + 600
        self.entry.pending_click = {
            "x": 10,
            "y": 20,
            "url": "https://example.com/settings",
            "expires_at": time.monotonic() + 20,
        }
        with (
            patch.object(
                self.gateway,
                "_snapshot_private_frame",
                new=AsyncMock(return_value={"url": "https://example.com/different"}),
            ),
            patch.object(self.gateway, "_perform_action", new=AsyncMock()) as act,
            self.assertRaisesRegex(BrowserError, "page changed"),
        ):
            await self.gateway.human_call(
                token, self.owner[1], "browser.approve_click", {}, issuer=self.owner[0]
            )
        act.assert_not_awaited()
        self.assertIsNone(self.entry.pending_click)

    async def test_expired_click_is_not_offered(self):
        self.gateway.sessions[self.owner] = self.entry
        token = secrets.token_urlsafe(32)
        self.entry.handoff_token = token
        self.entry.paused_for_human = True
        self.entry.handoff_until = time.monotonic() + 600
        self.entry.pending_click = {
            "x": 10,
            "y": 20,
            "url": "https://example.com",
            "expires_at": time.monotonic() - 1,
        }
        self.assertEqual(
            await self.gateway.human_call(
                token, self.owner[1], "browser.pending", {}, issuer=self.owner[0]
            ),
            {"pending": None},
        )


if __name__ == "__main__":
    unittest.main()
