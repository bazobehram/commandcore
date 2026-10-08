"""Short-lived authenticated visual-browser human takeover (experimental).

Never proxies raw Steel debug/CDP endpoints. Cookies must belong to the same
CommandCore subject as the browser session. Human control revokes AI control
until explicit resume or token expiry.
"""

from __future__ import annotations

import base64
import json
import time
from pathlib import Path
from typing import Any, Callable

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from pydantic import BaseModel, Field

from .browser_gateway import BrowserError, BrowserGateway
from .activity import argument_summary
from .db import Database
from .models import Principal
from .permissions import risk_class

HTML = """<!doctype html>
<html lang="en">
<head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>CommandCore — Browser Handoff</title>
<link rel="stylesheet" href="/browser-console.css">
<script defer src="/browser-console.js"></script>
</head>
<body>
<main>
<header><h1>CommandCore Browser</h1><p>Human control · 10-minute session</p></header>
<p id="status" role="status">Connecting to your browser…</p>
<img id="viewport" alt="Live browser screenshot: tap to click" draggable="false">
<div class="controls">
<button id="refresh" type="button">Refresh</button>
<button id="scroll-up" type="button">Scroll up</button>
<button id="scroll-down" type="button">Scroll down</button>
<input id="text" type="text" placeholder="Text to type" autocomplete="off">
<button id="send-text" type="button">Type</button>
<button id="enter" type="button">Enter</button>
<button id="tab" type="button">Tab</button>
<button id="escape" type="button">Escape</button>
<button id="resume" type="button">Resume AI control</button>
</div>
<p class="hint">Tap the screenshot to click. Log in or complete an account
verification yourself. AI control remains paused until you resume.</p>
</main>
</body></html>
"""


class HumanAction(BaseModel):
    name: str
    args: dict[str, Any] = Field(default_factory=dict)


def install_browser_console(
    app: FastAPI,
    browser: BrowserGateway | None,
    principal_dependency: Callable[..., Principal],
    same_origin: Callable[[Request], bool],
    db: Database,
) -> None:
    if browser is None:
        return

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

    @app.get("/browser/console/{token}", include_in_schema=False)
    async def browser_console_page(
        token: str, principal: Principal = Depends(principal_dependency)
    ) -> HTMLResponse:
        authorize(token, principal)
        return private(HTMLResponse(HTML))

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
        return private(Response(image, media_type="image/png"))

    @app.post("/browser/console/{token}/action", include_in_schema=False)
    async def browser_console_action(
        token: str,
        request: Request,
        action: HumanAction,
        principal: Principal = Depends(principal_dependency),
    ) -> JSONResponse:
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
