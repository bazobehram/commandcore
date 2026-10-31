"""Offline, transport-only Chrome DevTools Protocol characterization tests.

No live Chromium, owner sessions, network, or production credentials are used.
"""
from __future__ import annotations

import json

import pytest

from commandcore_server.browser_cdp import CDP
from commandcore_server.browser_errors import BrowserError
from commandcore_server.browser_gateway import (
    BrowserError as GatewayBrowserError,
    BrowserManualStepRequired,
    CDP as GatewayCDP,
)


class Socket:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.sent = []

    async def send(self, raw):
        self.sent.append(json.loads(raw))

    async def recv(self):
        return next(self.responses)


def test_gateway_legacy_error_and_transport_imports_keep_identity():
    assert GatewayCDP is CDP
    assert GatewayBrowserError is BrowserError
    assert issubclass(BrowserManualStepRequired, BrowserError)


@pytest.mark.asyncio
async def test_send_skips_unrelated_cdp_notifications_and_pins_session():
    ws = Socket([
        {"method": "Page.loadEventFired", "params": {}},
        {"id": 100, "result": {"unrelated": True}},
        {"id": 1, "result": {"ok": True}},
        {"id": 2, "result": {"second": True}},
    ])
    cdp = CDP(ws)
    assert await cdp.send("Runtime.evaluate", {"expression": "2 + 2"}, "owned-session") == {"ok": True}
    assert await cdp.send("Page.enable") == {"second": True}
    assert ws.sent == [
        {"id": 1, "method": "Runtime.evaluate", "params": {"expression": "2 + 2"}, "sessionId": "owned-session"},
        {"id": 2, "method": "Page.enable", "params": {}},
    ]


@pytest.mark.asyncio
async def test_send_rejects_cdp_errors_without_forwarding_detail():
    ws = Socket([{"id": 1, "error": {"message": "secret host stack detail"}}])
    with pytest.raises(BrowserError, match="CDP operation failed: Runtime.evaluate") as exc:
        await CDP(ws).send("Runtime.evaluate", {"expression": "secret"})
    assert "secret host stack detail" not in str(exc.value)


@pytest.mark.asyncio
async def test_send_with_expired_socket_fails_with_bounded_error():
    class Expired(Socket):
        async def recv(self):
            raise TimeoutError("upstream transport timed out")

    with pytest.raises(BrowserError, match="CDP response timeout"):
        await CDP(Expired([])).send("Page.enable")


@pytest.mark.asyncio
async def test_attach_targets_explicit_existing_page_only():
    target = "owned-page-id"
    ws = Socket([
        {"id": 1, "result": {"targetInfos": [
            {"targetId": "another-page", "type": "page"},
            {"targetId": target, "type": "page"},
        ]}},
        {"id": 2, "result": {"sessionId": "owned-session"}},
        {"id": 3, "result": {}},
        {"id": 4, "result": {}},
    ])
    session, attached_target = await CDP(ws).attach_page(target)
    assert (session, attached_target) == ("owned-session", target)
    assert [message["method"] for message in ws.sent] == [
        "Target.getTargets", "Target.attachToTarget", "Page.enable", "Runtime.enable"
    ]
    assert ws.sent[1]["params"] == {"targetId": target, "flatten": True}
    assert ws.sent[2]["sessionId"] == ws.sent[3]["sessionId"] == "owned-session"


@pytest.mark.asyncio
async def test_attach_refuses_missing_or_nonpage_target():
    ws = Socket([{"id": 1, "result": {"targetInfos": [
        {"targetId": "target-1", "type": "service_worker"}
    ]}}])
    with pytest.raises(BrowserError, match="owned browser tab disappeared"):
        await CDP(ws).attach_page("target-1")
    assert [message["method"] for message in ws.sent] == ["Target.getTargets"]


@pytest.mark.asyncio
async def test_attach_without_target_creates_new_blank_page_not_first_page():
    ws = Socket([
        {"id": 1, "result": {"targetId": "new-owned-page"}},
        {"id": 2, "result": {"targetInfos": [
            {"targetId": "unrelated-page", "type": "page"},
            {"targetId": "new-owned-page", "type": "page"}
        ]}},
        {"id": 3, "result": {"sessionId": "owned-session"}},
        {"id": 4, "result": {}},
        {"id": 5, "result": {}},
    ])
    assert await CDP(ws).attach_page(None) == ("owned-session", "new-owned-page")
    assert ws.sent[0]["method"] == "Target.createTarget"
    assert ws.sent[0]["params"] == {"url": "about:blank"}
    assert ws.sent[2]["params"]["targetId"] == "new-owned-page"
