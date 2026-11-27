"""Owner-only live frames: pointer/action updates and human-sensitive privacy."""

from __future__ import annotations

import asyncio
import unittest
from unittest.mock import AsyncMock, patch

import httpx
from commandcore_server.browser_gateway import (
    BrowserError,
    BrowserGateway,
    OwnedSession,
)


class BrowserLiveFrameTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.gateway = BrowserGateway(
            base_url="http://steel:3000",
            cdp_url="ws://steel:3000",
            allow_hosts=("example.com",),
            public_base_url="https://commandcore.test",
        )
        self.owner = ("https://idp.test", "owner", "test-app")
        self.entry = OwnedSession("a" * 36)
        self.gateway.sessions[self.owner] = self.entry
        self.fake_png = "iVBORw0KGgoAAAAAAA"

    async def send(self, name: str, args: dict | None = None):
        return await self.gateway.call(
            issuer=self.owner[0],
            subject=self.owner[1],
            client_id=self.owner[2],
            name=name,
            args=args or {},
        )

    def publish(self, name="browser.click", *, x=120, y=270):
        self.gateway._publish_frame(
            self.entry,
            {
                "screenshot_base64": self.fake_png,
                "url": "https://example.com/",
                "title": "Example",
            },
            name,
            {"x": x, "y": y},
            human=False,
        )

    async def test_owner_frame_sequence_deduplicates_png_without_cdp(self):
        self.publish()
        original = await self.send("browser.frame")
        assert original["changed"] and original["screenshot_base64"] == self.fake_png
        assert original["cursor"] == {"x": 120, "y": 270}
        unchanged = await self.send(
            "browser.frame", {"after_sequence": original["sequence"]}
        )
        assert not unchanged["changed"]
        assert "screenshot_base64" not in unchanged
        assert unchanged["action"] == "Click completed"

    async def test_typing_not_copied_into_live_frame_or_metadata(self):
        self.publish(name="browser.type")
        frame = await self.send("browser.frame")
        assert frame["action"] == "Text entered (content hidden)"
        assert "text" not in frame

    async def test_handoff_immediately_hides_frames_and_agent_actions(self):
        self.publish()
        handoff = await self.send("browser.handoff")
        token = handoff["handoff_url"].rsplit("/", 1)[-1]
        assert handoff["state"] == "paused_for_human"
        frame = await self.send("browser.frame")
        assert frame["state"] == "awaiting_human"
        assert "screenshot_base64" not in frame and "url" not in frame
        with self.assertRaisesRegex(BrowserError, "paused for human"):
            await self.send("browser.observe")
        with self.assertRaisesRegex(BrowserError, "cannot close"):
            await self.send("browser.close")
        self.entry.handoff_until = 0
        frame = await self.send("browser.frame")
        assert frame["state"] == "awaiting_human"
        with self.assertRaises(BrowserError):
            await self.gateway.human_resume(token, self.owner[1], self.owner[0])

    async def test_stale_stop_cannot_close_a_replacement_session(self):
        with self.assertRaisesRegex(BrowserError, "session changed"):
            await self.send("browser.close", {"expected_session_id": "old-session"})
        self.assertIs(self.gateway.sessions[self.owner], self.entry)
        for invalid in ("", 3, "x" * 129):
            with self.assertRaisesRegex(BrowserError, "invalid expected"):
                await self.send("browser.close", {"expected_session_id": invalid})
        self.assertIs(self.gateway.sessions[self.owner], self.entry)

    async def test_stop_retires_exact_missing_session_without_reassigning_worker(self):
        for status in (404, 410, 200):
            with self.subTest(status=status):
                self.gateway.sessions[self.owner] = self.entry
                self.gateway._bound_owner = self.owner
                response = httpx.Response(
                    status,
                    request=httpx.Request("POST", "http://steel:3000/release"),
                    json={"status": "released"} if status == 200 else {},
                )
                with patch(
                    "commandcore_server.browser_gateway.httpx.AsyncClient"
                ) as client:
                    post = client.return_value.__aenter__.return_value.post
                    post.return_value = response
                    result = await self.send(
                        "browser.close", {"expected_session_id": self.entry.id}
                    )
                    self.assertEqual(result, {"closed": True})
                    post.assert_awaited_once_with(
                        "http://steel:3000/v1/sessions/" + self.entry.id + "/release"
                    )
                self.assertNotIn(self.owner, self.gateway.sessions)
                self.assertEqual(self.gateway._bound_owner, self.owner)
                self.assertEqual(await self.send("browser.close"), {"closed": False})

    async def test_stop_preserves_session_when_release_not_confirmed(self):
        for status, body in (
            (403, {}),
            (500, {}),
            (200, {"status": "active"}),
            (200, []),
        ):
            with self.subTest(status=status, body=body):
                response = httpx.Response(
                    status,
                    request=httpx.Request("POST", "http://steel:3000/release"),
                    json=body,
                )
                with patch(
                    "commandcore_server.browser_gateway.httpx.AsyncClient"
                ) as client:
                    client.return_value.__aenter__.return_value.post.return_value = (
                        response
                    )
                    with self.assertRaises(BrowserError):
                        await self.send(
                            "browser.close", {"expected_session_id": self.entry.id}
                        )
                self.assertIs(self.gateway.sessions[self.owner], self.entry)

    async def test_queued_action_rejected_after_session_replacement(self):
        with patch.object(
            self.gateway, "_perform_action", new_callable=AsyncMock
        ) as perform:
            await self.entry.lock.acquire()
            task = asyncio.create_task(self.send("browser.click", {"x": 10, "y": 10}))
            try:
                await asyncio.sleep(0)
                self.assertFalse(task.done())
                self.gateway.sessions[self.owner] = OwnedSession("b" * 36)
            finally:
                self.entry.lock.release()
            with self.assertRaisesRegex(BrowserError, "session changed"):
                await task
            perform.assert_not_awaited()

    async def test_queued_handoff_rejected_after_session_replacement(self):
        await self.entry.lock.acquire()
        task = asyncio.create_task(self.send("browser.handoff"))
        replacement = OwnedSession("b" * 36)
        try:
            await asyncio.sleep(0)
            self.assertFalse(task.done())
            self.gateway.sessions[self.owner] = replacement
        finally:
            self.entry.lock.release()
        with self.assertRaisesRegex(BrowserError, "session changed"):
            await task
        self.assertFalse(replacement.paused_for_human)

    async def test_invalidation_during_snapshot_withholds_frame(self):
        async def snapshot(entry):
            self.gateway.sessions.pop(self.owner)
            return {"screenshot_base64": self.fake_png}

        with (
            patch.object(self.gateway, "_snapshot", side_effect=snapshot),
            self.assertRaisesRegex(BrowserError, "session changed"),
        ):
            await self.gateway.viewer_frame(
                self.owner[1], self.owner[0], self.owner[2], {}
            )
        self.assertIsNone(self.entry.frame_image)

    async def test_invalidation_during_release_cannot_delete_replacement(self):
        replacement = OwnedSession("b" * 36)

        async def post(url):
            self.gateway.sessions[self.owner] = replacement
            return httpx.Response(
                200, request=httpx.Request("POST", url), json={"status": "released"}
            )

        with patch("commandcore_server.browser_gateway.httpx.AsyncClient") as client:
            client.return_value.__aenter__.return_value.post.side_effect = post
            with self.assertRaisesRegex(BrowserError, "session changed"):
                await self.send("browser.close", {"expected_session_id": self.entry.id})
        self.assertIs(self.gateway.sessions[self.owner], replacement)

    async def test_expired_manual_handoff_requires_new_link_not_ai_resume(self):
        self.publish()
        first = await self.send("browser.handoff", {"reason": "approval"})
        self.assertEqual(first["reason"], "approval")
        first_token = first["handoff_url"].rsplit("/", 1)[-1]
        self.entry.handoff_until = 0  # fixture expiry, not a real 10-min wait
        state = await self.send("browser.frame")
        self.assertEqual(state["state"], "awaiting_human")
        self.assertEqual(state["reason"], "approval")
        self.assertTrue(state["can_renew"])
        self.assertNotIn("screenshot_base64", state)
        with self.assertRaisesRegex(BrowserError, "paused for human"):
            await self.send("browser.observe")
        second = await self.send("browser.handoff", {"reason": "verification"})
        self.assertEqual(second["reason"], "verification")
        second_token = second["handoff_url"].rsplit("/", 1)[-1]
        self.assertNotEqual(first_token, second_token)
        self.assertFalse((await self.send("browser.frame"))["can_renew"])
        with self.assertRaises(BrowserError):
            await self.gateway.human_resume(first_token, self.owner[1], self.owner[0])
        self.assertEqual(
            (
                await self.gateway.human_resume(
                    second_token, self.owner[1], self.owner[0]
                )
            )["state"],
            "resumed_for_agent",
        )

    async def test_private_hover_does_not_block_on_screenshot_capture(self):
        handoff = await self.send("browser.handoff")
        token = handoff["handoff_url"].rsplit("/", 1)[-1]
        with (
            patch.object(
                self.gateway, "_perform_action", new_callable=AsyncMock
            ) as perform,
            patch.object(self.gateway, "_snapshot", new_callable=AsyncMock) as snapshot,
        ):
            result = await self.gateway.human_call(
                token,
                self.owner[1],
                "browser.move",
                {"x": 140, "y": 180},
                issuer=self.owner[0],
            )
            self.assertEqual(result, {"status": "ok"})
            self.assertEqual(perform.await_count, 1)
            self.assertEqual(snapshot.await_count, 0)
        self.assertTrue(self.entry.paused_for_human)
        with self.assertRaisesRegex(BrowserError, "paused for human"):
            await self.send("browser.move", {"x": 2, "y": 2})

    async def test_invalid_handoff_reason_never_pauses_ai(self):
        self.publish()
        with self.assertRaisesRegex(BrowserError, "unsupported handoff"):
            await self.send("browser.handoff", {"reason": "admin"})
        self.assertFalse(self.entry.paused_for_human)

    async def test_explicit_resume_invalidates_last_viewer_frame(self):
        self.publish()
        handoff = await self.send("browser.handoff")
        token = handoff["handoff_url"].rsplit("/", 1)[-1]
        assert (await self.gateway.human_resume(token, self.owner[1], self.owner[0]))[
            "state"
        ] == "resumed_for_agent"
        frame = await self.send("browser.frame")
        assert frame["state"] == "agent"
        assert "screenshot_base64" not in frame
        self.publish(name="browser.observe")
        frame = await self.send("browser.frame")
        assert frame["changed"] and frame["screenshot_base64"] == self.fake_png

    async def test_frame_is_nonblocking_while_action_holds_lock(self):
        self.publish()
        await self.entry.lock.acquire()
        try:
            self.entry.action_running = True
            self.entry.last_action = "Clicking"
            frame = await self.send("browser.frame")
            assert frame["state"] == "running" and frame["busy"]
            assert frame["action"] == "Clicking"
        finally:
            self.entry.lock.release()

    async def test_other_owner_cannot_view_cached_frame(self):
        self.publish()
        with self.assertRaisesRegex(BrowserError, "no browser session"):
            await self.gateway.call(
                subject="intruder",
                issuer=self.owner[0],
                client_id=self.owner[2],
                name="browser.frame",
                args={},
            )

    async def test_invalid_sequence_rejected(self):
        self.publish()
        for invalid in (True, None, "1", -2, 9007199254740992):
            with self.subTest(invalid=invalid), self.assertRaises(BrowserError):
                await self.send("browser.frame", {"after_sequence": invalid})

    async def test_secret_console_human_frame_never_published(self):
        self.publish()
        before = self.entry.frame_sequence
        self.gateway._publish_frame(
            self.entry,
            {"screenshot_base64": "SENSITIVE", "url": "https://example.com/login"},
            "browser.type",
            {"text": "secret"},
            human=True,
        )
        assert self.entry.frame_sequence == before
        assert self.entry.frame_image == self.fake_png


if __name__ == "__main__":
    unittest.main()


class BrowserActionTrailTests(unittest.IsolatedAsyncioTestCase):
    async def test_only_sanitized_actions_and_coordinates_are_kept(self):
        gateway = BrowserGateway(
            base_url="http://steel:3000",
            cdp_url="ws://steel:3000",
            allow_hosts=("example.com",),
        )
        entry = OwnedSession("a" * 36)
        fixture = {
            "screenshot_base64": "iVBORw0KGgo=",
            "url": "https://example.com/",
            "title": "Demo",
        }
        for _ in range(25):
            gateway._publish_frame(
                entry, fixture, "browser.click", {"x": 50, "y": 75}, human=False
            )
        gateway._publish_frame(
            entry,
            fixture,
            "browser.type",
            {"text": "very private password"},
            human=False,
        )
        self.assertEqual(len(entry.recent_actions), 24)
        frame = gateway._frame(entry, {"after_sequence": 0})
        self.assertEqual(len(frame["recent_actions"]), 24)
        self.assertTrue(
            all(
                "text" not in event and "url" not in event
                for event in frame["recent_actions"]
            )
        )
        self.assertNotIn("very private", str(frame["recent_actions"]))
        self.assertEqual(
            frame["recent_actions"][-1]["action"], "Text entered (content hidden)"
        )
        self.assertEqual(
            gateway._frame(entry, {"after_sequence": frame["sequence"]})[
                "recent_actions"
            ],
            [],
        )
