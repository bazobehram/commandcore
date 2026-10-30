"""Owner-opted-in Browser UI scope stays narrow and fails closed."""

from __future__ import annotations

import secrets
import time
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from commandcore_server.browser_gateway import (
    BrowserError,
    BrowserGateway,
    OwnedSession,
)


class Connection:
    async def __aenter__(self):
        return object()

    async def __aexit__(self, *args):
        return False


class ScopedInputTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.gateway = BrowserGateway(
            base_url="http://steel:3000",
            cdp_url="ws://steel:3000",
            allow_hosts=("example.com", "other.example.com"),
        )
        self.owner = ("https://idp.test/", "owner", "oauth-app")
        self.token = secrets.token_urlsafe(32)
        self.entry = OwnedSession("f" * 36, target_id="c" * 36)
        self.entry.handoff_token = self.token
        self.entry.handoff_until = time.monotonic() + 600
        self.entry.paused_for_human = True
        self.gateway.sessions[self.owner] = self.entry
        self.cdp = MagicMock()
        self.cdp.attach_page = AsyncMock(return_value=("session", "c" * 36))
        self.cdp.send = AsyncMock()

    def _cdp_patches(self):
        return (
            patch.object(
                self.gateway,
                "_cdp_socket_uri",
                new=AsyncMock(return_value="ws://127.0.0.1"),
            ),
            patch(
                "commandcore_server.browser_gateway.websockets.connect",
                return_value=Connection(),
            ),
            patch("commandcore_server.browser_gateway.CDP", return_value=self.cdp),
            patch("commandcore_server.browser_gateway.asyncio.sleep", new=AsyncMock()),
        )

    async def test_resume_without_consent_never_grants_scope(self):
        result = await self.gateway.human_resume(
            self.token, self.owner[1], self.owner[0]
        )
        self.assertFalse(result["ai_interaction_granted"])
        self.assertIsNone(self.entry.ai_input_origin)
        self.assertEqual(self.entry.ai_input_until, 0.0)

    async def test_explicit_owner_consent_is_origin_bound_and_short_lived(self):
        with patch.object(
            self.gateway,
            "_snapshot_private_frame",
            new=AsyncMock(return_value={"url": "https://example.com/settings?foo=1"}),
        ):
            result = await self.gateway.human_resume(
                self.token, self.owner[1], self.owner[0], allow_ai_interaction=True
            )
        self.assertTrue(result["ai_interaction_granted"])
        self.assertEqual(self.entry.ai_input_origin, "https://example.com")
        self.assertGreater(self.entry.ai_input_until, time.monotonic() + 880)
        self.assertLess(self.entry.ai_input_until, time.monotonic() + 901)
        self.assertIsNone(self.entry.handoff_token)

    async def test_wrong_owner_cannot_grant_consent(self):
        with self.assertRaisesRegex(BrowserError, "handoff not found"):
            await self.gateway.human_resume(
                self.token, "different-owner", self.owner[0], allow_ai_interaction=True
            )
        self.assertIsNone(self.entry.ai_input_origin)

    async def test_outside_allowlist_consent_fails_closed(self):
        with (
            patch.object(
                self.gateway,
                "_snapshot_private_frame",
                new=AsyncMock(return_value={"url": "https://evil.test/"}),
            ),
            self.assertRaisesRegex(BrowserError, "allowed"),
        ):
            await self.gateway.human_resume(
                self.token, self.owner[1], self.owner[0], allow_ai_interaction=True
            )
        self.assertTrue(self.entry.paused_for_human)
        self.assertIsNone(self.entry.ai_input_origin)

    async def test_failed_resume_cannot_store_a_grant(self):
        with (
            patch.object(
                self.gateway,
                "_snapshot_private_frame",
                new=AsyncMock(return_value={"url": "https://example.com/"}),
            ),
            patch.object(
                self.gateway, "_save_session", side_effect=BrowserError("save failed")
            ),
            self.assertRaisesRegex(BrowserError, "save failed"),
        ):
            await self.gateway.human_resume(
                self.token, self.owner[1], self.owner[0], allow_ai_interaction=True
            )
        self.assertTrue(self.entry.paused_for_human)
        self.assertIsNone(self.entry.ai_input_origin)

    async def _click(self, origin="https://example.com", restricted=False):
        async def response(name, params=None, **kwargs):
            if name == "Runtime.evaluate":
                expr = params.get("expression", "")
                if expr == "location.origin":
                    return {"result": {"type": "string", "value": origin}}
                return {"result": {"type": "boolean", "value": not restricted}}
            return {}

        self.cdp.send = AsyncMock(side_effect=response)
        with (
            self._cdp_patches()[0],
            self._cdp_patches()[1],
            self._cdp_patches()[2],
            self._cdp_patches()[3],
        ):
            await self.gateway._perform_action(
                self.owner, self.entry, "browser.click", {"x": 110, "y": 180}
            )

    async def test_opted_in_owner_can_click_normal_control(self):
        self.entry.ai_input_origin = "https://example.com"
        self.entry.ai_input_until = time.monotonic() + 600
        await self._click()
        self.assertIn(
            "mousePressed",
            [
                x.args[1].get("type")
                for x in self.cdp.send.await_args_list
                if x.args[0] == "Input.dispatchMouseEvent"
            ],
        )

    async def test_cross_origin_does_not_inherit_consent(self):
        self.entry.ai_input_origin = "https://example.com"
        self.entry.ai_input_until = time.monotonic() + 600
        with self.assertRaisesRegex(BrowserError, "browser.handoff"):
            await self._click(origin="https://other.example.com", restricted=True)
        self.assertNotIn(
            "mousePressed",
            [
                x.args[1].get("type")
                for x in self.cdp.send.await_args_list
                if x.args[0] == "Input.dispatchMouseEvent"
            ],
        )

    async def test_expired_consent_does_not_allow_click(self):
        self.entry.ai_input_origin = "https://example.com"
        self.entry.ai_input_until = time.monotonic() - 1
        with self.assertRaisesRegex(BrowserError, "browser.handoff"):
            await self._click(restricted=True)
        self.assertNotIn(
            "mousePressed",
            [
                x.args[1].get("type")
                for x in self.cdp.send.await_args_list
                if x.args[0] == "Input.dispatchMouseEvent"
            ],
        )

    async def test_sensitive_control_stays_blocked_with_consent(self):
        self.entry.ai_input_origin = "https://example.com"
        self.entry.ai_input_until = time.monotonic() + 600
        with self.assertRaisesRegex(BrowserError, "Sensitive Browser control"):
            await self._click(restricted=True)
        self.assertNotIn(
            "mousePressed",
            [
                x.args[1].get("type")
                for x in self.cdp.send.await_args_list
                if x.args[0] == "Input.dispatchMouseEvent"
            ],
        )
        exprs = [
            x.args[1]["expression"]
            for x in self.cdp.send.await_args_list
            if x.args[0] == "Runtime.evaluate"
        ]
        self.assertTrue(
            any("password" in x and "revoke" in x and "payment" in x for x in exprs)
        )

    async def test_password_text_still_blocked_with_consent(self):
        self.entry.ai_input_origin = "https://example.com"
        self.entry.ai_input_until = time.monotonic() + 600
        self.cdp.send = AsyncMock(
            return_value={"result": {"type": "boolean", "value": True}}
        )
        with (
            self._cdp_patches()[0],
            self._cdp_patches()[1],
            self._cdp_patches()[2],
            self._cdp_patches()[3],
            self.assertRaisesRegex(BrowserError, "sign-in field"),
        ):
            await self.gateway._perform_action(
                self.owner, self.entry, "browser.type", {"text": "NEVER_SENT"}
            )
        self.assertNotIn(
            "Input.insertText", [x.args[0] for x in self.cdp.send.await_args_list]
        )


if __name__ == "__main__":
    unittest.main()
