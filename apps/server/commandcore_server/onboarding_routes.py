from __future__ import annotations

import base64
import hashlib
import secrets
import time
from typing import Literal
from urllib.parse import urlencode

import httpx
import jwt
from fastapi import Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel, Field

from .auth import STANDARD_SCOPE, scope_allows
from .enrollment import EnrollmentService
from .security import issue_panel_session, token_hash
from .web_assets import web_page


class AgentBegin(BaseModel):
    display_name: str = Field(min_length=1, max_length=120)
    hostname: str = Field(min_length=1, max_length=255)
    platform: str = Field(min_length=1, max_length=80)
    architecture: str = Field(min_length=1, max_length=80)
    agent_version: str = Field(min_length=1, max_length=40)
    protocol_version: str = Field(min_length=1, max_length=20)
    public_key_b64: str = Field(min_length=40, max_length=48)
    capabilities: dict[str, bool | str | int | None] = Field(
        default_factory=dict, max_length=80
    )
    local_ceiling: Literal["READ_ONLY", "STANDARD"] = "STANDARD"
    device_id: str | None = Field(default=None, min_length=36, max_length=36)
    device_token_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    proof: str = Field(min_length=80, max_length=100)


class AgentPoll(BaseModel):
    poll_token: str = Field(min_length=40, max_length=100)
    proof: str = Field(min_length=80, max_length=100)


class Review(BaseModel):
    view_token: str = Field(min_length=40, max_length=100)


class DecisionFields(BaseModel):
    code: str = Field(min_length=9, max_length=9)
    approve: bool
    grant_to_me: bool = False


class Decision(Review, DecisionFields):
    pass


class ManagedRename(BaseModel):
    display_name: str = Field(min_length=1, max_length=120)


class ManagedGrant(BaseModel):
    subject: str = Field(min_length=1, max_length=255)
    profile: Literal["READ_ONLY", "STANDARD"] = "READ_ONLY"


def install_routes(
    app, db, settings, require_principal, same_origin, verifier, web_path, agents
):
    service = EnrollmentService(
        db, settings.bootstrap_subject, settings.enrollment_ttl_seconds
    )
    authenticated = Depends(require_principal)

    def limited(request: Request, bucket: str, limit: int = 20):
        peer = request.client.host if request.client else "unknown"
        try:
            service.rate_limit(peer, bucket, limit)
        except ValueError:
            raise HTTPException(429, "rate_limited", headers={"Retry-After": "60"})

    def mutation(request, principal):
        if principal.auth_kind in {"oauth2-panel", "panel-cookie"} and not same_origin(
            request
        ):
            raise HTTPException(403, "cross-origin mutation denied")
        if (
            principal.auth_kind in {"oauth2-panel", "panel-cookie"}
            and not request.headers.get("origin")
            and request.headers.get("sec-fetch-site") != "same-origin"
        ):
            raise HTTPException(403, "same-origin cookie mutation required")
        if principal.auth_kind != "bootstrap-bearer" and not scope_allows(
            principal.scopes, STANDARD_SCOPE
        ):
            raise HTTPException(403, "standard scope required")

    def failed(exc):
        raise HTTPException(400, str(exc)) from exc

    @app.post("/api/enrollment/start")
    async def begin(body: AgentBegin, request: Request):
        limited(request, "begin", 5)
        try:
            data = service.begin(
                body.model_dump(exclude={"proof"}, exclude_none=True), body.proof
            )
        except ValueError as exc:
            failed(exc)
        # Fragment keeps approval secret out of HTTP access logs and Referer.
        data["verification_uri"] = (
            settings.public_base_url.rstrip("/") + "/enroll/#" + data.pop("view_token")
        )
        return JSONResponse(data, headers={"Cache-Control": "no-store"})

    @app.post("/api/enrollment/poll")
    async def poll(body: AgentPoll, request: Request):
        limited(request, "poll", 60)
        try:
            return JSONResponse(
                service.claim(body.poll_token, body.proof),
                headers={"Cache-Control": "no-store"},
            )
        except ValueError as exc:
            failed(exc)

    @app.post("/api/enrollment/review")
    async def review(body: Review, request: Request, principal=authenticated):
        mutation(request, principal)
        limited(request, "review")
        try:
            return service.review(body.view_token, principal.subject)
        except ValueError as exc:
            failed(exc)

    @app.post("/api/enrollment/decision")
    async def decision(body: Decision, request: Request, principal=authenticated):
        mutation(request, principal)
        limited(request, "decision")
        try:
            return service.decide(
                body.view_token,
                principal.subject,
                body.code,
                body.approve,
                body.grant_to_me,
            )
        except ValueError as exc:
            failed(exc)

    @app.get("/api/enrollment/pending")
    async def pending(principal=authenticated):
        return {"enrollments": service.list_pending(principal.subject)}

    @app.post("/api/enrollment/pending/{enrollment_id}/decision")
    async def pending_decision(
        enrollment_id: str,
        body: DecisionFields,
        request: Request,
        principal=authenticated,
    ):
        mutation(request, principal)
        limited(request, "decision")
        try:
            return service.decide(
                enrollment_id,
                principal.subject,
                body.code,
                body.approve,
                body.grant_to_me,
                reviewed_id=True,
            )
        except ValueError as exc:
            failed(exc)

    @app.get("/enroll/")
    async def enroll_page():
        return HTMLResponse(
            web_page(web_path),
            headers={"Referrer-Policy": "no-referrer", "Cache-Control": "no-store"},
        )

    @app.get("/auth/config")
    async def auth_config():
        return {"oauth_available": bool(verifier and settings.panel_oauth_client_id)}

    @app.get("/auth/login")
    async def login(request: Request):
        if not verifier or not settings.panel_oauth_client_id:
            raise HTTPException(503, "panel OAuth client not configured")
        limited(request, "login", 10)
        state, pkce = secrets.token_urlsafe(32), secrets.token_urlsafe(48)
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(pkce.encode()).digest())
            .decode()
            .rstrip("=")
        )
        with db.lock, db.conn:
            db.conn.execute(
                "DELETE FROM panel_login_transactions WHERE expires_at<?",
                (time.time(),),
            )
            db.conn.execute(
                "INSERT INTO panel_login_transactions VALUES(?,?,?)",
                (token_hash(state), pkce, time.time() + 600),
            )
        callback = settings.public_base_url.rstrip("/") + "/auth/callback"
        url = (
            settings.oauth_issuer.rstrip("/")
            + "/authorize?"
            + urlencode(
                {
                    "client_id": settings.panel_oauth_client_id,
                    "response_type": "code",
                    "redirect_uri": callback,
                    "state": state,
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                    "scope": "commandcore:read commandcore:standard",
                    "resource": settings.oauth_audience,
                }
            )
        )
        response = RedirectResponse(url, 302)
        response.set_cookie(
            "commandcore_login_state",
            state,
            httponly=True,
            secure=settings.panel_cookie_secure,
            samesite="lax",
            max_age=600,
            path="/auth",
        )
        response.set_cookie(
            "commandcore_login_destination",
            "enroll"
            if request.query_params.get("return_to") == "enroll"
            else "devices",
            httponly=True,
            secure=settings.panel_cookie_secure,
            samesite="lax",
            max_age=600,
            path="/auth",
        )
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/auth/callback")
    async def callback(request: Request):
        # Consume state even on failed exchange. Never return provider error/code.
        state = request.query_params.get("state", "")
        cookie = request.cookies.get("commandcore_login_state", "")
        if not state or not cookie or not secrets.compare_digest(state, cookie):
            raise HTTPException(400, "invalid_login_state")
        if (
            request.query_params.get("iss", settings.oauth_issuer)
            != settings.oauth_issuer
        ):
            raise HTTPException(400, "invalid_login_issuer")
        with db.lock, db.conn:
            row = db.conn.execute(
                "SELECT * FROM panel_login_transactions WHERE state_hash=?",
                (token_hash(state),),
            ).fetchone()
            db.conn.execute(
                "DELETE FROM panel_login_transactions WHERE state_hash=?",
                (token_hash(state),),
            )
        if (
            not row
            or row["expires_at"] < time.time()
            or not request.query_params.get("code")
        ):
            raise HTTPException(400, "expired_or_failed_login")
        try:
            async with httpx.AsyncClient(timeout=20, follow_redirects=False) as client:
                exchanged = await client.post(
                    settings.oauth_issuer.rstrip("/") + "/oauth/token",
                    data={
                        "grant_type": "authorization_code",
                        "client_id": settings.panel_oauth_client_id,
                        "code": request.query_params["code"],
                        "code_verifier": row["verifier"],
                        "redirect_uri": settings.public_base_url.rstrip("/")
                        + "/auth/callback",
                        "resource": settings.oauth_audience,
                    },
                )
                exchanged.raise_for_status()
                token = exchanged.json()["access_token"]
            principal = verifier.verify(token)
        except (httpx.HTTPError, jwt.PyJWTError, KeyError, ValueError):
            raise HTTPException(400, "OAuth login failed") from None
        response = RedirectResponse(
            "/enroll/"
            if request.cookies.get("commandcore_login_destination") == "enroll"
            else "/",
            303,
        )
        session = issue_panel_session(
            secret=settings.session_secret,
            subject=principal.subject,
            ttl_seconds=min(
                settings.panel_session_ttl_seconds,
                int(exchanged.json().get("expires_in", 300)),
            ),
            scopes=principal.scopes,
            auth_kind="oauth2-panel",
        )
        response.set_cookie(
            settings.panel_cookie_name,
            session,
            httponly=True,
            secure=settings.panel_cookie_secure,
            samesite="strict",
            max_age=settings.panel_session_ttl_seconds,
            path="/",
        )
        response.delete_cookie("commandcore_login_state", path="/auth")
        response.delete_cookie("commandcore_login_destination", path="/auth")
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/api/managed-devices")
    async def managed(principal=authenticated):
        with db.lock:
            rows = db.conn.execute(
                "SELECT device_id FROM device_managers WHERE subject=?",
                (principal.subject,),
            ).fetchall()
        online = set(await agents.online_device_ids())
        devices = []
        for row in rows:
            device = db.get_device(row[0])
            if device:
                device["connected"] = device["id"] in online
                device["managed_by_me"] = True
                device["grants"] = db.list_device_grants(
                    settings.bootstrap_subject, device["id"]
                )
                devices.append(device)
        return {"devices": devices}

    def manager(principal, device_id):
        with db.lock:
            if not db.conn.execute(
                "SELECT 1 FROM device_managers WHERE subject=? AND device_id=?",
                (principal.subject, device_id),
            ).fetchone():
                raise HTTPException(404, "device not found")
        return db.get_device(device_id)

    @app.get("/api/managed-devices/{device_id}/audit")
    async def managed_audit(device_id: str, principal=authenticated):
        manager(principal, device_id)
        with db.lock:
            rows = db.conn.execute(
                "SELECT timestamp,tool,status,duration_ms,risk_class FROM audit_events WHERE device_id=? ORDER BY id DESC LIMIT 50",
                (device_id,),
            ).fetchall()
        return JSONResponse(
            {"events": [dict(row) for row in rows]},
            headers={"Cache-Control": "no-store"},
        )

    @app.patch("/api/managed-devices/{device_id}")
    async def rename_managed(
        device_id: str, body: ManagedRename, request: Request, principal=authenticated
    ):
        mutation(request, principal)
        device = manager(principal, device_id)
        if device["revoked_at"]:
            raise HTTPException(409, "device revoked")
        with db.lock, db.conn:
            db.conn.execute(
                "UPDATE devices SET display_name=? WHERE id=?",
                (body.display_name, device_id),
            )
            service._audit(
                principal.subject, "enrollment.device.rename", device_id, device_id
            )
        return {"ok": True}

    @app.put("/api/managed-devices/{device_id}/grants")
    async def grant_managed(
        device_id: str, body: ManagedGrant, request: Request, principal=authenticated
    ):
        mutation(request, principal)
        device = manager(principal, device_id)
        local = device["capabilities"].get("local_max_permission_profile", "READ_ONLY")
        if local == "READ_ONLY" and body.profile != "READ_ONLY":
            raise HTTPException(403, "grant exceeds local ceiling")
        if body.subject == settings.bootstrap_subject:
            raise HTTPException(400, "registry owner cannot receive a delegated grant")
        with db.lock, db.conn:
            if not db.conn.execute(
                "SELECT 1 FROM devices WHERE id=? AND revoked_at IS NULL", (device_id,)
            ).fetchone():
                raise HTTPException(409, "device revoked")
            db.conn.execute(
                "INSERT INTO device_grants(device_id,subject,max_permission_profile,created_at,created_by) VALUES(?,?,?,?,?) ON CONFLICT(device_id,subject) DO UPDATE SET max_permission_profile=excluded.max_permission_profile,created_at=excluded.created_at,created_by=excluded.created_by",
                (
                    device_id,
                    body.subject,
                    body.profile,
                    time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    principal.subject,
                ),
            )
            service._audit(
                principal.subject,
                "enrollment.device.grant",
                device_id,
                device_id,
                {"subject": body.subject, "profile": body.profile},
            )
        return {"ok": True}

    @app.delete("/api/managed-devices/{device_id}/grants")
    async def ungrant_managed(
        device_id: str, subject: str, request: Request, principal=authenticated
    ):
        mutation(request, principal)
        manager(principal, device_id)
        with db.lock, db.conn:
            db.conn.execute(
                "DELETE FROM device_grants WHERE device_id=? AND subject=?",
                (device_id, subject),
            )
            db.conn.execute(
                "DELETE FROM selections WHERE device_id=? AND owner_id=?",
                (device_id, subject),
            )
            service._audit(
                principal.subject,
                "enrollment.device.ungrant",
                device_id,
                device_id,
                {"subject": subject},
            )
        return {"ok": True}

    @app.post("/api/managed-devices/{device_id}/revoke")
    async def revoke_managed(device_id: str, request: Request, principal=authenticated):
        mutation(request, principal)
        manager(principal, device_id)
        if not db.revoke_device(settings.bootstrap_subject, device_id):
            raise HTTPException(409, "device already revoked")
        await agents.disconnect_device(device_id)
        with db.lock, db.conn:
            service._audit(
                principal.subject, "enrollment.device.revoke", device_id, device_id
            )
        return {"ok": True}

    return service
