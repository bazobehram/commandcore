"""Optional, fail-closed visual browser bridge.

The Chromium process lives in a separate Steel container. This module only
holds short-lived CDP connections and owner-scoped session identifiers.
Experimental: do not use on sensitive authenticated sites until the browser
container has a tested outbound network isolation policy and handoff proxy.
"""

from __future__ import annotations

import asyncio
import base64
import ipaddress
import json
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

import httpx
import websockets


BROWSER_TOOL_NAMES = {
    "browser.open",
    "browser.observe",
    "browser.move",
    "browser.click",
    "browser.type",
    "browser.keypress",
    "browser.scroll",
    "browser.close",
}


class BrowserError(Exception):
    pass


def check_url(raw: str, allow_hosts: tuple[str, ...]) -> str:
    """Validate caller-supplied *initial* navigation. Not a network firewall."""
    if not allow_hosts:
        raise BrowserError("browser host allowlist is empty")
    if not isinstance(raw, str) or len(raw) > 2048:
        raise BrowserError("invalid URL")
    try:
        u = urlsplit(raw)
        host = (u.hostname or "").rstrip(".").lower()
        port = u.port
    except ValueError as exc:
        raise BrowserError("invalid URL") from exc
    if u.scheme != "https" or not host or port not in (None, 443):
        raise BrowserError("only HTTPS on port 443 is allowed")
    if u.username is not None or u.password is not None:
        raise BrowserError("credentials in URLs are forbidden")
    try:
        ipaddress.ip_address(host)
        raise BrowserError("IP literals are forbidden")
    except ValueError:
        pass
    if host == "localhost" or "." not in host or not re.fullmatch(r"[a-z0-9.-]+", host):
        raise BrowserError("invalid host")
    if not any(
        host == allowed
        or (
            allowed.startswith("*.")
            and host.endswith(allowed[1:])
            and host != allowed[2:]
        )
        for allowed in allow_hosts
    ):
        raise BrowserError("host is not in the browser allowlist")
    return raw


class CDP:
    def __init__(self, websocket: Any):
        self.ws = websocket
        self.counter = 0

    async def send(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        session: str | None = None,
    ) -> dict[str, Any]:
        self.counter += 1
        call_id = self.counter
        msg: dict[str, Any] = {"id": call_id, "method": method, "params": params or {}}
        if session:
            msg["sessionId"] = session
        await self.ws.send(json.dumps(msg))
        for _ in range(200):
            result = json.loads(await asyncio.wait_for(self.ws.recv(), timeout=12))
            if result.get("id") == call_id:
                if result.get("error"):
                    raise BrowserError(f"CDP operation failed: {method}")
                return result.get("result") or {}
        raise BrowserError("CDP response timeout")

    async def attach_page(self) -> str:
        info = await self.send("Target.getTargets")
        pages = [t for t in info.get("targetInfos", []) if t.get("type") == "page"]
        if not pages:
            raise BrowserError("no browser page available")
        result = await self.send(
            "Target.attachToTarget", {"targetId": pages[0]["targetId"], "flatten": True}
        )
        session = result["sessionId"]
        await self.send("Page.enable", session=session)
        await self.send("Runtime.enable", session=session)
        return session


@dataclass
class OwnedSession:
    id: str
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)


class BrowserGateway:
    def __init__(
        self,
        *,
        base_url: str,
        cdp_url: str,
        allow_hosts: tuple[str, ...],
        max_sessions: int = 1,
    ):
        if not base_url.startswith("http://") or not cdp_url.startswith("ws://"):
            raise ValueError("browser backend must use private HTTP/WS transport")
        # Current self-hosted Steel CDP endpoint multiplexes onto a single
        # active browser. Two API session IDs are NOT an isolation guarantee.
        if max_sessions != 1:
            raise ValueError("experimental browser supports one active owner only")
        self.base_url = base_url.rstrip("/")
        self.cdp_url = cdp_url.rstrip("/")
        self.allow_hosts = allow_hosts
        self.max_sessions = max_sessions
        self.sessions: dict[tuple[str, str, str], OwnedSession] = {}
        self._create_lock = asyncio.Lock()

    async def _new_session(self, owner: tuple[str, str, str]) -> OwnedSession:
        async with self._create_lock:
            existing = self.sessions.get(owner)
            if existing:
                return existing
            if len(self.sessions) >= self.max_sessions:
                raise BrowserError("maximum concurrent browser sessions reached")
            async with httpx.AsyncClient(timeout=15) as client:
                r = await client.post(
                    self.base_url + "/v1/sessions",
                    json={
                        "dimensions": {"width": 1280, "height": 800},
                        "solveCaptcha": False,
                    },
                )
                r.raise_for_status()
                session_id = r.json().get("id")
            if not isinstance(session_id, str) or not re.fullmatch(
                r"[0-9a-f-]{36}", session_id
            ):
                raise BrowserError("invalid Steel session response")
            entry = OwnedSession(session_id)
            self.sessions[owner] = entry
            return entry

    async def _release(self, owner: tuple[str, str, str]) -> dict[str, Any]:
        async with self._create_lock:
            entry = self.sessions.get(owner)
            if not entry:
                return {"closed": False}
            async with entry.lock:
                async with httpx.AsyncClient(timeout=12) as client:
                    r = await client.delete(self.base_url + "/v1/sessions/" + entry.id)
                    if r.status_code not in (200, 204, 404):
                        r.raise_for_status()
                self.sessions.pop(owner, None)
        return {"closed": True}

    async def call(
        self,
        *,
        subject: str,
        issuer: str,
        client_id: str,
        name: str,
        args: dict[str, Any],
    ) -> dict[str, Any]:
        if name not in BROWSER_TOOL_NAMES:
            raise BrowserError("unknown browser tool")
        owner = (issuer, subject, client_id)
        if name == "browser.close":
            return await self._release(owner)
        if name == "browser.open":
            check_url(args.get("url", ""), self.allow_hosts)
            entry = await self._new_session(owner)
        else:
            entry = self.sessions.get(owner)
            if not entry:
                raise BrowserError("no browser session: call browser.open first")

        async with entry.lock:
            uri = self.cdp_url + "/?sessionId=" + entry.id
            async with websockets.connect(
                uri, open_timeout=12, max_size=9_000_000, close_timeout=2
            ) as ws:
                cdp = CDP(ws)
                session = await cdp.attach_page()
                if name == "browser.open":
                    await cdp.send(
                        "Page.navigate", {"url": args["url"]}, session=session
                    )
                    await asyncio.sleep(1.5)
                elif name in {"browser.move", "browser.click"}:
                    x, y = args.get("x"), args.get("y")
                    if (
                        not isinstance(x, int)
                        or not isinstance(y, int)
                        or not (0 <= x <= 1280 and 0 <= y <= 800)
                    ):
                        raise BrowserError(
                            "coordinates must be integers inside the 1280x800 viewport"
                        )
                    await cdp.send(
                        "Input.dispatchMouseEvent",
                        {"type": "mouseMoved", "x": x, "y": y},
                        session=session,
                    )
                    if name == "browser.click":
                        await cdp.send(
                            "Input.dispatchMouseEvent",
                            {
                                "type": "mousePressed",
                                "x": x,
                                "y": y,
                                "button": "left",
                                "clickCount": 1,
                            },
                            session=session,
                        )
                        await cdp.send(
                            "Input.dispatchMouseEvent",
                            {
                                "type": "mouseReleased",
                                "x": x,
                                "y": y,
                                "button": "left",
                                "clickCount": 1,
                            },
                            session=session,
                        )
                elif name == "browser.type":
                    value = args.get("text")
                    if not isinstance(value, str) or not (1 <= len(value) <= 2000):
                        raise BrowserError("text length must be 1-2000")
                    await cdp.send("Input.insertText", {"text": value}, session=session)
                elif name == "browser.keypress":
                    key = args.get("key")
                    allowed = {
                        "Enter": 13,
                        "Tab": 9,
                        "Escape": 27,
                        "Backspace": 8,
                        "ArrowUp": 38,
                        "ArrowDown": 40,
                        "ArrowLeft": 37,
                        "ArrowRight": 39,
                    }
                    if key not in allowed:
                        raise BrowserError("unsupported key")
                    await cdp.send(
                        "Input.dispatchKeyEvent",
                        {
                            "type": "keyDown",
                            "key": key,
                            "windowsVirtualKeyCode": allowed[key],
                        },
                        session=session,
                    )
                    await cdp.send(
                        "Input.dispatchKeyEvent",
                        {
                            "type": "keyUp",
                            "key": key,
                            "windowsVirtualKeyCode": allowed[key],
                        },
                        session=session,
                    )
                elif name == "browser.scroll":
                    delta = args.get("delta_y")
                    if not isinstance(delta, int) or abs(delta) > 1000:
                        raise BrowserError(
                            "delta_y must be an integer between -1000 and 1000"
                        )
                    await cdp.send(
                        "Input.dispatchMouseEvent",
                        {
                            "type": "mouseWheel",
                            "x": 640,
                            "y": 400,
                            "deltaY": delta,
                            "deltaX": 0,
                        },
                        session=session,
                    )

                if name != "browser.observe":
                    await asyncio.sleep(0.4)
                # Structured page data is untrusted web content, never instructions.
                meta = await cdp.send(
                    "Runtime.evaluate",
                    {
                        "expression": "({title:document.title,url:location.href,text:(document.body?.innerText||'').slice(0,2400)})",
                        "returnByValue": True,
                        "awaitPromise": False,
                    },
                    session=session,
                )
                page = meta.get("result", {}).get("value", {})
                shot = await cdp.send(
                    "Page.captureScreenshot",
                    {"format": "png", "captureBeyondViewport": False},
                    session=session,
                )
                png = shot.get("data", "")
                if not isinstance(png, str) or len(png) > 6_000_000:
                    raise BrowserError("screenshot unavailable or exceeds limit")
                raw = base64.b64decode(png, validate=True)
                if not raw.startswith(b"\x89PNG\r\n\x1a\n"):
                    raise BrowserError("invalid PNG from browser")
                return {
                    "session_id": entry.id,
                    "title": str(page.get("title", ""))[:300],
                    "url": str(page.get("url", ""))[:2048],
                    "page_text": str(page.get("text", ""))[:2400],
                    "screenshot_base64": png,
                }
