import asyncio
import time
from unittest.mock import AsyncMock

from commandcore_server.browser_gateway import BrowserGateway, OwnedSession


def gateway():
    return BrowserGateway(
        base_url="http://127.0.0.1:9999",
        cdp_url="ws://127.0.0.1:9999",
        allow_hosts=("example.com",),
    )


def test_idle_session_expires_only_when_safe():
    g = gateway()
    entry = OwnedSession("test")
    entry.last_interaction_mono = time.monotonic() - 601
    assert g._idle_expired(entry)
    entry.action_running = True
    assert not g._idle_expired(entry)
    entry.action_running = False
    entry.paused_for_human = True
    assert not g._idle_expired(entry)
    entry.paused_for_human = False
    entry.last_interaction_mono = time.monotonic()
    assert not g._idle_expired(entry)


def test_locked_session_never_expires():
    async def check():
        g = gateway()
        entry = OwnedSession("test")
        entry.last_interaction_mono = time.monotonic() - 1000
        async with entry.lock:
            assert not g._idle_expired(entry)
    asyncio.run(check())


def test_idle_cleanup_cannot_reassign_owner():
    g = gateway()
    owner = ("issuer", "subject", "client")
    entry = OwnedSession("test")
    entry.last_interaction_mono = time.monotonic() - 1000
    g.sessions[owner] = entry
    g._bound_owner = owner
    assert g._idle_expired(entry)
    assert g._bound_owner == owner


def test_idle_release_rechecks_after_activity():
    async def check():
        g = gateway()
        owner = ("issuer", "subject", "client")
        entry = OwnedSession("test")
        entry.last_interaction_mono = time.monotonic() - 1000
        g.sessions[owner] = entry
        # Activity resumes after the sweep initially considers it expired.
        entry.last_interaction_mono = time.monotonic()
        result = await g._release(owner, expected_session_id="test", require_idle=True)
        assert result["closed"] is False
        assert owner in g.sessions
        # An explicit close remains separately authorized, not altered by
        # the idle-sweeper's conditional release path.
    asyncio.run(check())


def test_handoff_cannot_be_closed_by_idle_sweeper():
    async def check():
        g = gateway()
        owner = ("issuer", "subject", "client")
        entry = OwnedSession("test")
        entry.last_interaction_mono = time.monotonic() - 1000
        entry.paused_for_human = True
        entry.handoff_token = "private"
        entry.handoff_until = time.monotonic() + 400
        g.sessions[owner] = entry
        result = await g._release(owner, expected_session_id="test", require_idle=True)
        assert result["closed"] is False
        assert owner in g.sessions
    asyncio.run(check())
