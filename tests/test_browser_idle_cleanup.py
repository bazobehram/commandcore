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


def test_idle_release_calls_worker_only_for_expired_owner(monkeypatch):
    from unittest.mock import patch

    class Reply:
        def raise_for_status(self):
            pass
        def json(self):
            return {"status": "released"}

    class FakeClient:
        def __init__(self, **kwargs):
            pass
        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            pass
        async def post(self, url):
            requests.append(url)
            return Reply()

    async def check():
        g = gateway()
        g.idle_timeout_seconds = 1
        owner = ("issuer", "user", "conversation-A")
        other = ("issuer", "user", "conversation-B")
        entry = OwnedSession("session-a")
        entry.last_interaction_mono = time.monotonic() - 3
        g.sessions[owner] = entry
        g._bound_owner = owner
        with patch("commandcore_server.browser_gateway.httpx.AsyncClient", FakeClient):
            closed = await g._release(owner, expected_session_id="session-a", require_idle=True)
            assert closed["closed"] is True
            assert owner not in g.sessions
            assert g._bound_owner == owner
            assert requests == ["http://127.0.0.1:9999/v1/sessions/session-a/release"]
            assert other not in g.sessions

    requests = []
    asyncio.run(check())


def test_idle_cleanup_never_closes_replaced_session():
    from commandcore_server.browser_gateway import BrowserError

    async def check():
        g = gateway()
        owner = ("issuer", "user", "conversation-A")
        replacement = OwnedSession("new")
        replacement.last_interaction_mono = time.monotonic() - 1200
        g.sessions[owner] = replacement
        try:
            await g._release(owner, expected_session_id="old", require_idle=True)
        except BrowserError as exc:
            assert "session changed" in str(exc)
        else:
            raise AssertionError("stale cleanup unexpectedly authorized")
        assert g.sessions[owner] is replacement

    asyncio.run(check())
