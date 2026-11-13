"""Authenticated first-party viewer; never enables/provisions Browser."""

from fastapi import Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response

from .web_assets import web_asset

from .auth import STANDARD_SCOPE, scope_allows
from .browser_gateway import BrowserError
from .browser_worker_pool import OwnerBrowserWorkerPool


def install_browser_viewer(app, browser, principal_dependency, same_origin, db):
    def authorize(principal):
        if (
            principal.auth_kind not in {"oauth2", "oauth2-panel"}
            or not principal.issuer
            or not principal.subject
            or not scope_allows(principal.scopes, STANDARD_SCOPE)
        ):
            raise HTTPException(403, "Authenticated STANDARD OAuth required")

    def private(data):
        return JSONResponse(
            data, headers={"Cache-Control": "no-store", "Vary": "Cookie, Authorization"}
        )

    def owner_client(principal, client_id):
        authorize(principal)
        if not isinstance(browser, OwnerBrowserWorkerPool):
            raise HTTPException(409, "Verified Browser worker pool unavailable")
        sessions = browser.viewer_sessions(principal.subject, principal.issuer)
        if not any(row["client_id"] == client_id for row in sessions):
            raise HTTPException(404, "Browser session unavailable")

    @app.get("/browser/live", include_in_schema=False)
    async def direct_browser_page():
        # No session data is embedded in this document. Authenticated APIs
        # supply owner-bound frames; mere GET never grants human takeover.
        return HTMLResponse(
            web_asset("browser-live.html").read_text(encoding="utf-8"),
            headers={
                "Cache-Control": "private, no-store",
                "Referrer-Policy": "no-referrer",
                "X-Content-Type-Options": "nosniff",
                "Content-Security-Policy": (
                    "default-src 'none'; script-src 'self'; style-src 'self'; "
                    "img-src 'self' data:; connect-src 'self'; "
                    "frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
                ),
            },
        )

    @app.get("/browser-live.js", include_in_schema=False)
    async def direct_browser_js():
        return Response(
            web_asset("browser-live.js").read_bytes(),
            media_type="application/javascript",
            headers={
                "Cache-Control": "private, no-store",
                "X-Content-Type-Options": "nosniff",
            },
        )

    @app.get("/browser-live.css", include_in_schema=False)
    async def direct_browser_css():
        return Response(
            web_asset("browser-live.css").read_bytes(),
            media_type="text/css",
            headers={
                "Cache-Control": "private, no-store",
                "X-Content-Type-Options": "nosniff",
            },
        )

    @app.get("/api/browser/sessions")
    async def sessions(principal=Depends(principal_dependency)):
        authorize(principal)
        if not isinstance(browser, OwnerBrowserWorkerPool):
            return private({"enabled": False, "sessions": []})
        try:
            return private(
                {
                    "enabled": True,
                    "sessions": browser.viewer_sessions(
                        principal.subject, principal.issuer
                    ),
                }
            )
        except BrowserError:
            raise HTTPException(409, "Browser worker verification unavailable")

    @app.get("/api/browser/frame")
    async def frame(
        client_id: str,
        after_sequence: int = -1,
        principal=Depends(principal_dependency),
    ):
        try:
            owner_client(principal, client_id)
            return private(
                await browser.viewer_frame(
                    principal.subject,
                    principal.issuer,
                    client_id,
                    {"after_sequence": after_sequence},
                )
            )
        except BrowserError:
            raise HTTPException(409, "Browser session verification unavailable")
        except TimeoutError:
            raise HTTPException(504, "Browser frame capture timed out")

    @app.post("/api/browser/handoff")
    async def handoff(request: Request, principal=Depends(principal_dependency)):
        if not request.headers.get("origin") or not same_origin(request):
            raise HTTPException(403, "Same-origin handoff required")
        data = await request.json()
        client_id = data.get("client_id") if isinstance(data, dict) else None
        try:
            owner_client(principal, client_id)
            result = await browser.call(
                subject=principal.subject,
                issuer=principal.issuer,
                client_id=client_id,
                name="browser.handoff",
                args={"reason": "approval"},
            )
        except BrowserError:
            raise HTTPException(409, "Browser handoff unavailable")
        db.add_audit(
            user_id=principal.subject,
            client_id=principal.client_id,
            device_id=None,
            tool="browser.handoff",
            args_summary="first-party manual takeover; contents omitted",
            execution_id=None,
            status="ok",
            duration_ms=0,
            exit_code=None,
            risk_class="standard",
        )
        return private(
            {
                "handoff_path": "/browser/console/"
                + result["handoff_url"].rsplit("/", 1)[-1],
                "state": result["state"],
            }
        )
