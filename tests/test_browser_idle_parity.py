"""Private idle behavior on shared source; no live worker or production data."""

import asyncio
import json
import time
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from commandcore_server.auth import READ_SCOPE, STANDARD_SCOPE
from commandcore_server.browser_gateway import (
    BrowserError,
    BrowserGateway,
    OwnedSession,
)
from commandcore_server.browser_session_store import (
    BrowserSessionStore,
    SessionStoreError,
)
from commandcore_server.browser_worker_binding import BrowserWorkerBinding
from commandcore_server.browser_worker_pool import OwnerBrowserWorkerPool
from commandcore_server.models import Principal
from commandcore_server.tools import ToolError, ToolService

OWNER = ("https://issuer.example/", "alice", "client")
OTHER = ("https://issuer.example/", "bob", "client")


def gateway():
    return BrowserGateway(
        base_url="http://steel:3000",
        cdp_url="ws://steel:3000",
        allow_hosts=("example.com",),
        public_base_url="https://commandcore.example",
    )


@pytest.fixture
def idle():
    worker = gateway()
    entry = OwnedSession("a" * 36)
    entry.last_activity_mono = time.monotonic() - 901
    worker.sessions[OWNER] = entry
    worker._bound_owner = OWNER
    return worker, entry


def release_response(status=200):
    return httpx.Response(
        status,
        request=httpx.Request("POST", "http://steel:3000/release"),
        json={"status": "released"} if status == 200 else {},
    )


async def send(worker, name, args=None):
    return await worker.call(
        issuer=OWNER[0],
        subject=OWNER[1],
        client_id=OWNER[2],
        name=name,
        args=args or {},
    )


@pytest.mark.asyncio
async def test_passive_frames_do_not_extend_idle_and_exact_session_is_retired(idle):
    worker, entry = idle
    original = entry.last_activity_mono
    await send(worker, "browser.frame")
    await send(worker, "browser.watch")
    assert entry.last_activity_mono == original
    with patch("commandcore_server.browser_gateway.httpx.AsyncClient") as client:
        post = client.return_value.__aenter__.return_value.post
        post.return_value = release_response()
        assert await worker.expire_idle_sessions() == 1
        post.assert_awaited_once_with(
            "http://steel:3000/v1/sessions/" + entry.id + "/release"
        )
    assert OWNER not in worker.sessions
    assert worker._bound_owner == OWNER
    with pytest.raises(BrowserError, match="permanently bound"):
        await worker._new_session(OTHER)


@pytest.mark.asyncio
async def test_recent_action_resets_timer(idle):
    worker, entry = idle
    with patch.object(worker, "_visible_links", new_callable=AsyncMock) as links:
        links.return_value = {"links": []}
        await send(worker, "browser.links")
    assert time.monotonic() - entry.last_activity_mono < 2
    with patch("commandcore_server.browser_gateway.httpx.AsyncClient") as client:
        assert await worker.expire_idle_sessions() == 0
        client.assert_not_called()


@pytest.mark.asyncio
async def test_busy_session_and_valid_handoff_are_not_closed(idle):
    worker, entry = idle
    with patch("commandcore_server.browser_gateway.httpx.AsyncClient") as client:
        async with entry.lock:
            assert await worker.expire_idle_sessions() == 0
        entry.paused_for_human = True
        entry.handoff_token = "x" * 43
        entry.handoff_until = time.monotonic() + 60
        assert await worker.expire_idle_sessions() == 0
        client.assert_not_called()
        assert entry.paused_for_human
        assert OWNER in worker.sessions


@pytest.mark.asyncio
async def test_expired_handoff_retires_without_restoring_ai_control(idle):
    worker, entry = idle
    entry.paused_for_human = True
    entry.handoff_token = "x" * 43
    entry.handoff_until = time.monotonic() - 1
    with pytest.raises(BrowserError, match="paused for human"):
        await send(worker, "browser.close")
    with patch("commandcore_server.browser_gateway.httpx.AsyncClient") as client:
        client.return_value.__aenter__.return_value.post.return_value = (
            release_response(404)
        )
        assert await worker.expire_idle_sessions() == 1
    assert entry.paused_for_human
    assert OWNER not in worker.sessions


@pytest.mark.asyncio
async def test_recheck_under_lock_protects_recent_action(idle):
    worker, entry = idle
    await worker._create_lock.acquire()
    task = asyncio.create_task(worker.expire_idle_sessions())
    with patch("commandcore_server.browser_gateway.httpx.AsyncClient") as client:
        try:
            await asyncio.sleep(0)
            assert not task.done()
            entry.last_activity_mono = time.monotonic()
        finally:
            worker._create_lock.release()
        assert await task == 0
        client.assert_not_called()


@pytest.mark.asyncio
async def test_release_failure_retains_conversation_lease(idle):
    worker, _entry = idle
    tools = ToolService(None, None, 60, browser=worker)
    tools._browser_conversation_leases[OWNER] = "tag"
    with patch("commandcore_server.browser_gateway.httpx.AsyncClient") as client:
        client.return_value.__aenter__.return_value.post.return_value = (
            release_response(500)
        )
        assert await tools.expire_idle_browser_sessions() == 0
    assert tools._browser_conversation_leases[OWNER] == "tag"
    assert OWNER in worker.sessions


@pytest.mark.asyncio
async def test_guard_excludes_inflight_and_clears_only_retired_owner_lease(idle):
    worker, _entry = idle
    tools = ToolService(None, None, 60, browser=worker)
    tools._browser_conversation_leases.update({OWNER: "old-chat", OTHER: "other-chat"})

    async def post(_url):
        with (
            pytest.raises(ToolError, match="cleanup in progress"),
            tools._browser_operation(OWNER),
        ):
            pytest.fail("same owner operation admitted")
        with tools._browser_operation(OTHER):
            assert tools._browser_inflight[OTHER] == 1
        return release_response()

    with patch("commandcore_server.browser_gateway.httpx.AsyncClient") as client:
        client.return_value.__aenter__.return_value.post.side_effect = post
        with tools._browser_operation(OWNER):
            assert await tools.expire_idle_browser_sessions() == 0
            client.assert_not_called()
        assert await tools.expire_idle_browser_sessions() == 1
    assert tools._browser_conversation_leases == {OTHER: "other-chat"}
    assert not tools._browser_expiring
    assert not tools._browser_inflight


@pytest.mark.asyncio
async def test_old_chat_cannot_adopt_session_and_new_chat_can_open_after_idle(idle):
    worker, _entry = idle
    tools = ToolService(None, None, 60, browser=worker)
    principal = Principal(
        subject=OWNER[1],
        issuer=OWNER[0],
        client_id=OWNER[2],
        auth_kind="oauth2",
        scopes=(READ_SCOPE, STANDARD_SCOPE),
    )
    tools._browser_conversation_leases[OWNER] = tools.live_activity.session_tag(
        "chat-A"
    )
    with pytest.raises(ToolError, match="Another conversation"):
        tools._browser_scope_args(principal, "browser.open", {}, "chat-B")
    with patch("commandcore_server.browser_gateway.httpx.AsyncClient") as client:
        client.return_value.__aenter__.return_value.post.return_value = (
            release_response()
        )
        assert await tools.expire_idle_browser_sessions() == 1
    assert tools._browser_scope_args(principal, "browser.open", {}, "chat-B") == {}
    with pytest.raises(ToolError, match="Another conversation"):
        tools._browser_scope_args(principal, "browser.frame", {}, "chat-A")


@pytest.mark.asyncio
async def test_lease_cleanup_error_preserves_old_chat_binding(idle):
    worker, _entry = idle
    tools = ToolService(None, None, 60, browser=worker)
    tools._browser_conversation_leases[OWNER] = "old-chat"
    with (
        patch("commandcore_server.browser_gateway.httpx.AsyncClient") as client,
        patch.object(
            tools, "_browser_lease_delete", side_effect=ToolError("cleanup failed")
        ),
    ):
        client.return_value.__aenter__.return_value.post.return_value = (
            release_response()
        )
        with pytest.raises(ToolError, match="cleanup failed"):
            await tools.expire_idle_browser_sessions()
    assert tools._browser_conversation_leases[OWNER] == "old-chat"
    assert OWNER not in tools._browser_expiring


@pytest.mark.asyncio
async def test_pool_requires_current_attested_route_before_release(idle):
    worker, _entry = idle
    pool = object.__new__(OwnerBrowserWorkerPool)
    pool.workers = (worker,)
    with (
        patch.object(pool, "_find_worker", side_effect=BrowserError("proof expired")),
        patch("commandcore_server.browser_gateway.httpx.AsyncClient") as client,
    ):
        assert await pool.expire_idle_sessions() == 0
        client.assert_not_called()
    with (
        patch.object(pool, "_find_worker", return_value=worker) as proof,
        patch("commandcore_server.browser_gateway.httpx.AsyncClient") as client,
    ):
        client.return_value.__aenter__.return_value.post.return_value = (
            release_response()
        )
        assert await pool.expire_idle_sessions() == 1
        assert proof.call_count == 2


def test_journal_preserves_same_boot_activity_and_grants_reboot_grace(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("COMMANDCORE_BROWSER_JOURNAL_DIR", str(tmp_path / "journal"))
    binding = BrowserWorkerBinding.provision(
        str(tmp_path / "binding.sqlite3"),
        "test-worker",
        "synthetic-fixture-key-" + "x" * 32,
    )
    binding.claim(OWNER)
    store = BrowserSessionStore(binding)
    entry = OwnedSession("a" * 36)
    entry.last_activity_mono = time.monotonic() - 901
    with patch.object(store, "boot_id", return_value="boot-a"):
        store.save(OWNER, entry)
        assert store.load()[1]["last_activity_mono"] == entry.last_activity_mono
        data = json.loads(store.cipher.decrypt(store.path.read_bytes()))
        data["last_activity_mono"] = float("nan")
        store.path.write_bytes(store.cipher.encrypt(json.dumps(data).encode()))
        with pytest.raises(SessionStoreError):
            store.load()
        del data["last_activity_mono"]
        store.path.write_bytes(store.cipher.encrypt(json.dumps(data).encode()))
        assert time.monotonic() - store.load()[1]["last_activity_mono"] < 2
        store.save(OWNER, entry)
    with patch.object(store, "boot_id", return_value="boot-b"):
        assert time.monotonic() - store.load()[1]["last_activity_mono"] < 2
    binding.close()
