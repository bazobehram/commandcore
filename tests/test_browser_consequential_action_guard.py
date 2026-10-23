"""Browser private-canary input guard: deny obvious AI form submissions."""

from __future__ import annotations

import unittest
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


if __name__ == "__main__":
    unittest.main()
