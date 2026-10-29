"""Short-lived authenticated visual-browser human takeover (experimental).

Never proxies raw Steel debug/CDP endpoints. Cookies must belong to the same
CommandCore subject as the browser session. Human control revokes AI control
until explicit resume or token expiry.
"""

from __future__ import annotations

import asyncio
import base64
import json
import re
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
    Response,
    StreamingResponse,
)
from pydantic import BaseModel, Field

from .activity import argument_summary
from .browser_gateway import BrowserError, BrowserGateway
from .browser_worker_pool import OwnerBrowserWorkerPool
from .db import Database
from .models import Principal
from .permissions import risk_class

HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<meta name="color-scheme" content="dark light">
<title>Private Browser · CommandCore</title>
<link rel="icon" href="/commandcore-icon.png" type="image/png">
<link rel="stylesheet" href="/browser-console.css">
<script defer src="/browser-console.js"></script>
</head>
<body>
<header class="app-header">
  <div class="brand" aria-label="CommandCore">
    <img src="/commandcore-icon.png" width="40" height="40" alt="">
    <div><strong>CommandCore</strong><small>Remote execution workspace</small></div>
  </div>
  <div class="header-context"><span class="header-divider"></span> Browser <span class="crumb">/</span> Private control</div>
  <div class="session-badge"><span class="pulse" aria-hidden="true"></span><span>Human session</span></div>
</header>
<main class="workspace">
  <section class="introduction">
    <div>
      <p class="eyebrow">BROWSER WORKSPACE <span class="eyebrow-slash">/</span> SECURE TAKEOVER</p>
      <h1>You're in control<span class="period">.</span></h1>
      <p class="introduction-copy">A live view of your remote Chromium browser. Your AI is paused while you interact.</p>
    </div>
    <div class="session-limit"><span class="clock-icon" aria-hidden="true">◷</span>
      <div><strong>Private session</strong><small>Time-limited · up to 10 minutes</small></div>
    </div>
  </section>
  <div class="workspace-grid">
    <section class="remote-panel" aria-labelledby="remote-heading">
      <div class="browser-chrome">
        <div class="window-dots" aria-hidden="true"><i></i><i></i><i></i></div>
        <div class="browser-tab"><span class="tab-indicator" aria-hidden="true"></span><strong id="remote-heading">Remote Chromium</strong><span class="tab-tag">LIVE VIEW</span></div>
        <div class="browser-security"><span aria-hidden="true">◈</span> Owner-bound session</div>
      </div>
      <div class="browser-addressbar" aria-label="Current remote browser address">
        <span class="address-lock" aria-hidden="true">⌁</span>
        <div id="browser-address" class="address-value" role="status">Connecting to remote page…</div>
        <span class="address-readonly">ADDRESS ONLY</span>
      </div>
      <div id="viewport-stage" class="viewport-stage">
        <div id="viewport-empty" class="viewport-empty" role="status">
          <div class="loading-ring" aria-hidden="true"></div>
          <strong>Connecting to your browser</strong>
          <span>Loading an authenticated, private Chromium frame…</span>
        </div>
        <img id="viewport" alt="Live remote Chromium viewport. Click the image to interact with the page." draggable="false" hidden>
      </div>
      <div class="viewer-footer">
        <div class="viewer-live"><span class="live-indicator" aria-hidden="true"></span><span id="connection-status">Connecting</span></div>
        <div class="viewer-hint">Move · Click · Wheel to scroll</div>
        <div id="frame-updated" class="frame-updated" aria-live="off">Waiting for frame</div>
      </div>
    </section>
    <aside class="control-sidebar" aria-label="Human browser controls">
      <section class="sidebar-card current-control">
        <div class="card-eyebrow"><span class="human-indicator" aria-hidden="true"></span> PRIVATE CONTROL</div>
        <h2>Your browser. Your actions.</h2>
        <p id="status" class="status" role="status" aria-live="polite">Connecting to your browser…</p>
        <p class="security-note">AI actions and private screenshots stay blocked until you return control.</p>
      </section>
      <section class="sidebar-card" id="pending-approval" hidden>
        <div class="card-heading"><h2>AI requested a click</h2><span>YOUR APPROVAL</span></div>
        <p class="card-copy">Review the live page before approving. This permits exactly one click at the highlighted position, not future website actions.</p>
        <p id="pending-location" class="action-feedback">Waiting for request</p>
        <button id="approve-pending" class="accent-button" type="button">Approve this one click</button>
      </section>
      <section class="sidebar-card">
        <div class="card-heading"><h2>Navigate the page</h2><span>REMOTE INPUT</span></div>
        <p class="card-copy">Use your mouse on the viewport: hover, click and wheel scrolling work. Buttons remain available for touch devices.</p>
        <div class="button-grid">
          <button id="refresh" class="control-button wide-button" type="button"><span aria-hidden="true">↻</span> Refresh frame</button>
          <button id="scroll-up" class="control-button" type="button"><span aria-hidden="true">↑</span> Scroll up</button>
          <button id="scroll-down" class="control-button" type="button"><span aria-hidden="true">↓</span> Scroll down</button>
        </div>
        <div class="action-feedback" id="action-status" aria-live="polite">Awaiting your input</div>
      </section>
      <section class="sidebar-card">
        <div class="card-heading"><h2>Private keyboard</h2><span>NOT SHARED WITH AI</span></div>
        <label class="input-label" for="text">Send text to the focused field</label>
        <div class="private-input-row">
          <input id="text" type="password" placeholder="Type into the remote page" autocomplete="off" autocapitalize="off" spellcheck="false">
          <button id="send-text" class="accent-button" type="button">Type <span aria-hidden="true">↗</span></button>
        </div>
        <label class="reveal"><input id="visible-input" type="checkbox"> Show typing locally</label>
        <div class="key-buttons" aria-label="Remote keyboard keys">
          <button id="enter" class="control-button" type="button">Enter <span aria-hidden="true">↵</span></button>
          <button id="tab" class="control-button" type="button">Tab <span aria-hidden="true">⇥</span></button>
          <button id="escape" class="control-button" type="button">Esc</button>
        </div>
      </section>
      <section class="sidebar-card finish-card">
        <div class="card-heading"><h2>Finished?</h2><span>EXPLICIT HANDOFF</span></div>
        <p class="card-copy">Return control to your AI. This ends private interaction and allows it to continue.</p>
        <button id="resume" class="resume-button" type="button">Resume AI control <span aria-hidden="true">→</span></button>
        <p class="finish-note">Only you can resume this session.</p>
      </section>
    </aside>
  </div>
  <footer class="workspace-footer"><span>CommandCore · Private Browser</span><span>Protected remote interaction · No credentials shared with AI</span></footer>
</main>
</body></html>
"""


def _safe_page_address(value: object) -> str:
    """Display an owner-only address without URL credentials, query or fragment.

    Never reveal bearer/query parameters or make this value an HTML attribute.
    The result is only a read-only label for the authenticated human console.
    """
    if not isinstance(value, str) or len(value) > 4096:
        return ""
    try:
        parsed = urlsplit(value)
        if (
            parsed.scheme.lower() != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
        ):
            return ""
        hostname = parsed.hostname.encode("idna").decode("ascii").lower()
        if not re.fullmatch(r"[a-z0-9.-]{1,253}", hostname):
            return ""
        port = parsed.port
        suffix = f":{port}" if port and port != 443 else ""
        path = quote(parsed.path or "/", safe="/%:@-._~!$&'()*+,;=")
        # Avoid displaying URL-path secrets. The path is intentionally
        # abbreviated; query/fragment are always omitted completely.
        return f"https://{hostname}{suffix}{path[:180]}"
    except (ValueError, UnicodeError):
        return ""


async def _private_png_stream(
    browser: BrowserGateway | OwnerBrowserWorkerPool,
    token: str,
    subject: str,
    issuer: str,
    request: Request,
    *,
    min_frame_interval: float = 0.75,
    max_duration: float = 480.0,
    max_frames: int = 400,
):
    """Owner-only server-sent PNG frames; strictly bounded and cancellable.

    Each capture revalidates the handoff before AND after capture, so a
    concurrent explicit human resume or token expiry cannot expose frames
    after revocation. No screenshot is retained after yield, no frame is
    published to the model-facing AI viewer, and each yielded part waits for
    consumer backpressure before the next CDP capture.
    """
    deadline = time.monotonic() + max_duration
    failures = 0
    count = 0
    bytes_sent = 0
    max_total_bytes = 128 * 1024 * 1024
    while count < max_frames and time.monotonic() < deadline:
        if await request.is_disconnected():
            return
        started = time.monotonic()
        try:
            browser.handoff_owner(token, subject, issuer)
            # Frame-only CDP path avoids expensive page text/readiness work
            # from browser.observe and never publishes this human frame to AI.
            shot = await asyncio.wait_for(
                browser.private_stream_frame(token, subject, issuer),
                timeout=12.0,
            )
            # Recheck after the potentially slow CDP await, including after
            # any explicit resume concurrently executed on another request.
            browser.handoff_owner(token, subject, issuer)
            if await request.is_disconnected():
                return
            encoded = shot.get("screenshot_base64")
            if not isinstance(encoded, str):
                raise ValueError("no image")  # noqa: TRY004 - malformed frame payload
            frame = base64.b64decode(encoded, validate=True)
            if not frame.startswith(b"\x89PNG\r\n\x1a\n") or len(frame) > 4_500_000:
                raise ValueError("invalid frame")
        except BrowserError:
            return
        except (TimeoutError, ValueError, base64.binascii.Error):
            failures += 1
            if failures >= 3:
                return
            await asyncio.sleep(0.8)
            continue
        failures = 0
        if bytes_sent + len(frame) > max_total_bytes:
            return
        bytes_sent += len(frame)
        count += 1
        # SSE keeps exactly one long-lived authenticated HTTP response.
        # Never include URL/title, human input, OAuth data, or handoff
        # token in these events. The client keeps at most one frame in decode.
        payload = json.dumps(
            {
                "png": encoded,
                "address": _safe_page_address(shot.get("url")),
            },
            separators=(",", ":"),
        )
        yield b"event: frame\ndata: " + payload.encode("ascii") + b"\n\n"
        await asyncio.sleep(max(0.0, min_frame_interval - (time.monotonic() - started)))
    # Endpoint always terminates even when a client never disconnects.


class HumanAction(BaseModel):
    name: str
    args: dict[str, Any] = Field(default_factory=dict)


def install_browser_console(
    app: FastAPI,
    browser: BrowserGateway | OwnerBrowserWorkerPool | None,
    principal_dependency: Callable[..., Principal],
    same_origin: Callable[[Request], bool],
    db: Database,
) -> None:
    if browser is None:
        return

    # A single owner/session must not multiply expensive CDP captures by
    # opening several viewer tabs. Reservations live only for the request.
    active_streams: set[tuple[str, str, str]] = set()

    def authorize(token: str, principal: Principal) -> None:
        try:
            browser.handoff_owner(token, principal.subject, principal.issuer)
        except BrowserError as exc:
            raise HTTPException(404, "handoff not found or expired") from exc

    def private(response: Response) -> Response:
        response.headers["Cache-Control"] = "no-store"
        return response

    def audit(
        principal: Principal,
        name: str,
        args: dict[str, Any],
        status: str = "ok",
        duration_ms: int = 0,
    ) -> None:
        db.add_audit(
            user_id=principal.subject,
            client_id="human-browser-console",
            device_id=None,
            tool=name,
            args_summary=json.dumps(argument_summary(args), separators=(",", ":")),
            execution_id=None,
            status=status,
            duration_ms=duration_ms,
            exit_code=None,
            risk_class=risk_class(name),
        )

    @app.get("/browser-console.js", include_in_schema=False)
    async def browser_console_script() -> Response:
        script = Path(__file__).resolve().parents[2] / "web/browser-console.js"
        if not script.is_file():
            from .web_assets import web_asset

            script = web_asset("browser-console.js")
        return private(
            Response(script.read_bytes(), media_type="application/javascript")
        )

    @app.get("/browser-console.css", include_in_schema=False)
    async def browser_console_style() -> Response:
        style = Path(__file__).resolve().parents[2] / "web/browser-console.css"
        if not style.is_file():
            from .web_assets import web_asset

            style = web_asset("browser-console.css")
        return private(Response(style.read_bytes(), media_type="text/css"))

    @app.get("/browser/console/{token}/start", include_in_schema=False)
    async def browser_console_start(token: str) -> Response:
        """No credentials in links to IdP. Human must log in and be owner.

        This route does NOT authorize Browser control. Only a later verified
        OAuth panel cookie + matching handoff token can access the console.
        """
        if not re.fullmatch(r"[A-Za-z0-9_-]{43}", token):
            raise HTTPException(404, "handoff not found")
        redirect = RedirectResponse("/auth/login?return_to=browser", status_code=303)
        redirect.set_cookie(
            "commandcore_browser_handoff_destination",
            token,
            httponly=True,
            secure=True,
            samesite="lax",
            max_age=600,
            path="/auth",
        )
        redirect.headers["Referrer-Policy"] = "no-referrer"
        return private(redirect)

    @app.get("/browser/console/{token}", include_in_schema=False)
    async def browser_console_page(
        token: str, principal: Principal = Depends(principal_dependency)
    ) -> HTMLResponse:
        authorize(token, principal)
        return private(HTMLResponse(HTML))

    @app.get("/browser/console/{token}/stream", include_in_schema=False)
    async def browser_console_stream(
        token: str,
        request: Request,
        principal: Principal = Depends(principal_dependency),
    ) -> StreamingResponse:
        # Live images are exclusively for an authenticated OAuth owner with
        # an active, verifiable human takeover. No bootstrap credentials.
        if principal.auth_kind != "oauth2-panel" or not principal.issuer:
            raise HTTPException(403, "OAuth human console required")
        if request.headers.get("sec-fetch-site") not in {None, "none", "same-origin"}:
            raise HTTPException(403, "cross-origin stream denied")
        if request.headers.get("origin") and not same_origin(request):
            raise HTTPException(403, "cross-origin stream denied")
        authorize(token, principal)
        stream_owner = (principal.issuer, principal.subject, token)

        async def owned_frames():
            if stream_owner in active_streams:
                # The caller falls back to normal snapshots. One stream per
                # handoff prevents multiple tabs exhausting the worker.
                return
            active_streams.add(stream_owner)
            try:
                async for frame in _private_png_stream(
                    browser, token, principal.subject, principal.issuer, request
                ):
                    yield frame
            finally:
                active_streams.discard(stream_owner)

        return StreamingResponse(
            owned_frames(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "private, no-store, no-transform",
                "Vary": "Cookie, Authorization",
                "X-Content-Type-Options": "nosniff",
                "X-Accel-Buffering": "no",
                "Referrer-Policy": "no-referrer",
            },
        )

    @app.get("/browser/console/{token}/screenshot", include_in_schema=False)
    async def browser_console_screenshot(
        token: str, principal: Principal = Depends(principal_dependency)
    ) -> Response:
        authorize(token, principal)
        try:
            snapshot = await browser.human_call(
                token,
                principal.subject,
                "browser.observe",
                {},
                issuer=principal.issuer,
            )
            image = base64.b64decode(snapshot["screenshot_base64"], validate=True)
        except (BrowserError, ValueError) as exc:
            raise HTTPException(409, "browser unavailable") from exc
        audit(principal, "browser.observe", {})
        response = Response(image, media_type="image/png")
        address = _safe_page_address(snapshot.get("url"))
        if address:
            response.headers["X-CommandCore-Page-Address"] = address
        return private(response)

    @app.post("/browser/console/{token}/action", include_in_schema=False)
    async def browser_console_action(
        token: str,
        request: Request,
        action: HumanAction,
        principal: Principal = Depends(principal_dependency),
    ) -> Response:
        authorize(token, principal)
        # Cookies are same-site, but still require an explicit same-origin
        # browser request. Bearer authentication is not sufficient for takeover.
        origin = request.headers.get("origin")
        if not origin or not same_origin(request):
            raise HTTPException(403, "same-origin browser interaction required")
        started = time.monotonic()
        try:
            result = await browser.human_call(
                token,
                principal.subject,
                action.name,
                action.args,
                issuer=principal.issuer,
            )
        except BrowserError as exc:
            audit(principal, action.name, action.args, "error")
            raise HTTPException(422, "browser action rejected") from exc
        audit(
            principal,
            action.name,
            action.args,
            duration_ms=int((time.monotonic() - started) * 1000),
        )
        # The Browser action already captured a frame. A private human
        # console may explicitly request that same PNG in this response,
        # avoiding a second full Chromium/CDP capture immediately afterward.
        # Legacy callers still receive the unchanged metadata JSON contract.
        if request.headers.get("accept", "").split(",", 1)[0].strip() == "image/png":
            encoded = result.get("screenshot_base64")
            if not isinstance(encoded, str):
                raise HTTPException(409, "browser action image unavailable")
            try:
                png = base64.b64decode(encoded, validate=True)
            except (ValueError, base64.binascii.Error) as exc:
                raise HTTPException(409, "browser action image unavailable") from exc
            if not png.startswith(b"\x89PNG\r\n\x1a\n"):
                raise HTTPException(409, "browser action image unavailable")
            image_response = Response(png, media_type="image/png")
            address = _safe_page_address(result.get("url"))
            if address:
                image_response.headers["X-CommandCore-Page-Address"] = address
            return private(image_response)
        result.pop("screenshot_base64", None)
        return private(JSONResponse(result))

    @app.post("/browser/console/{token}/resume", include_in_schema=False)
    async def browser_console_resume(
        token: str,
        request: Request,
        principal: Principal = Depends(principal_dependency),
    ) -> JSONResponse:
        authorize(token, principal)
        origin = request.headers.get("origin")
        if not origin or not same_origin(request):
            raise HTTPException(403, "same-origin browser interaction required")
        try:
            result = await browser.human_resume(
                token, principal.subject, principal.issuer
            )
        except BrowserError as exc:
            raise HTTPException(409, "handoff not found or expired") from exc
        audit(principal, "browser.handoff.resume", {})
        return private(JSONResponse(result))
