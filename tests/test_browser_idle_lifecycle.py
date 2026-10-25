import asyncio
import time
from unittest.mock import AsyncMock

from commandcore_server.browser_gateway import BrowserGateway, OwnedSession


def test_idle_reaper_expiration_and_active_guards():
    async def run():
        worker = object.__new__(BrowserGateway)
        owner = ("issuer", "subject", "client")
        entry = OwnedSession("session-id")
        worker.sessions = {owner: entry}
        worker._release = AsyncMock(return_value={"closed": True})
        entry.last_meaningful_activity = time.monotonic() - 601
        assert await worker.reap_idle(600) == [owner]
        assert worker._release.await_args.kwargs["idle_seconds"] == 600
        worker._release.reset_mock()
        entry.last_meaningful_activity = time.monotonic()
        assert await worker.reap_idle(600) == []
        worker._release.assert_not_awaited()
        entry.last_meaningful_activity = time.monotonic() - 601
        entry.paused_for_human = True
        assert await worker.reap_idle(600) == []
        entry.paused_for_human = False
        entry.action_running = True
        assert await worker.reap_idle(600) == []

    asyncio.run(run())


def test_viewer_polling_does_not_keep_browser_alive():
    async def run():
        worker = BrowserGateway(
            base_url="http://steel:3000",
            cdp_url="ws://steel:3000",
            allow_hosts=("example.com",),
        )
        owner = ("issuer", "subject", "client")
        entry = OwnedSession("a" * 36)
        worker.sessions[owner] = entry
        entry.last_meaningful_activity = time.monotonic() - 601
        before = entry.last_meaningful_activity
        await worker.call(
            issuer=owner[0],
            subject=owner[1],
            client_id=owner[2],
            name="browser.frame",
            args={},
        )
        await worker.call(
            issuer=owner[0],
            subject=owner[1],
            client_id=owner[2],
            name="browser.watch",
            args={},
        )
        assert entry.last_meaningful_activity == before
        assert worker._frame(entry, {})["idle_remaining_seconds"] == 0

    asyncio.run(run())
