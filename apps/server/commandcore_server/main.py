from __future__ import annotations

import asyncio
import hashlib
import os
import time
from contextlib import asynccontextmanager
from typing import Any
from urllib.parse import urlsplit

import uvicorn
from fastapi import (
    Depends,
    FastAPI,
    Header,
    HTTPException,
    Request,
    Response,
    WebSocket,
)
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field

from . import __version__
from .agent_gateway import AgentManager
from .web_assets import web_asset, web_page
from .auth import ALL_SCOPES, ADMIN_SCOPE, OAuthSettings, OAuthVerifier, scope_allows
from .config import Settings
from .db import Database
from .fleet import FleetRolloutService
from .mcp import MCPHandler
from .metrics import Metrics
from .models import Principal
from .security import (
    audit_summary,
    constant_time_token_equal,
    issue_panel_session,
    panel_session_claims,
)
from .tools import CORE_TOOL_DEFINITIONS, ToolError, ToolService

settings = Settings()
settings.validate()
db = Database(settings.db_path)
metrics = Metrics()
agents = AgentManager(db, metrics, settings.max_job_output_bytes)
tools = ToolService(db, agents, settings.selection_ttl_seconds)
fleet = FleetRolloutService(db, agents)
branding_icons = [
    {
        "src": settings.public_base_url.rstrip("/")
        + "/commandcore-icon.png?v="
        + hashlib.sha256(web_asset("commandcore-icon.png").read_bytes()).hexdigest()[
            :16
        ],
        "mimeType": "image/png",
        "sizes": ["1254x1254"],
    }
]
mcp = MCPHandler(
    tools,
    metrics,
    __version__,
    lambda scope: (
        _www_authenticate(
            scope,
            error="insufficient_scope",
            error_description="Additional authorization is required for this tool",
        )
        if settings.oauth_enabled
        else None
    ),
    icons=branding_icons,
)
oauth_verifier = (
    OAuthVerifier(
        OAuthSettings(
            issuer=settings.oauth_issuer,
            audience=settings.oauth_audience,
            jwks_url=settings.oauth_jwks_url,
            algorithms=settings.oauth_algorithms,
        )
    )
    if settings.oauth_enabled
    else None
)
core_mcp = MCPHandler(
    tools,
    metrics,
    __version__,
    mcp.scope_challenge,
    definitions=CORE_TOOL_DEFINITIONS,
    name="CommandCore Core",
    icons=branding_icons,
)


class EnrollmentRequest(BaseModel):
    token: str
    display_name: str = Field(min_length=1, max_length=120)
    hostname: str = Field(min_length=1, max_length=255)
    platform: str = Field(min_length=1, max_length=80)
    architecture: str = Field(min_length=1, max_length=80)
    agent_version: str = Field(min_length=1, max_length=40)
    protocol_version: str = Field(min_length=1, max_length=20)
    public_key_b64: str
    capabilities: dict[str, Any] = Field(default_factory=dict)


class PermissionRequest(BaseModel):
    profile: str


class PanelLoginRequest(BaseModel):
    token: str


class DeviceUpdateRequest(BaseModel):
    display_name: str | None = Field(default=None, min_length=1, max_length=120)
    tags: list[str] | None = None


class DeviceGrantRequest(BaseModel):
    subject: str = Field(min_length=1, max_length=255)
    max_permission_profile: str = Field(default="READ_ONLY")


class FleetRolloutRequest(BaseModel):
    target_version: str = Field(min_length=1, max_length=80)
    manifest_url: str = Field(min_length=8, max_length=2048)
    device_ids: list[str] = Field(min_length=1, max_length=500)
    canary_count: int = Field(default=1, ge=1, le=50)
    ring_size: int = Field(default=5, ge=1, le=100)
    stop_on_failure: bool = True


SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def _bearer(authorization: str | None) -> str | None:
    if not authorization or not authorization.startswith("Bearer "):
        return None
    return authorization[7:]


def _same_origin(request: Request) -> bool:
    fetch_site = (request.headers.get("sec-fetch-site") or "").lower()
    if fetch_site and fetch_site not in {"same-origin", "none"}:
        return False
    origin = request.headers.get("origin")
    if not origin:
        return fetch_site == "same-origin"
    try:
        parsed_origin = urlsplit(origin)
        expected_origin = urlsplit(settings.public_base_url)
        origin_host = parsed_origin.netloc.lower()
    except ValueError:
        return False
    return bool(
        origin_host
        and origin_host == expected_origin.netloc.lower()
        and parsed_origin.scheme == expected_origin.scheme
        and not parsed_origin.username
        and not parsed_origin.password
        and parsed_origin.path in {"", "/"}
        and not parsed_origin.query
        and not parsed_origin.fragment
    )


def _resource_metadata_url() -> str:
    parts = urlsplit(settings.mcp_base_url)
    if parts.scheme and parts.netloc:
        return f"{parts.scheme}://{parts.netloc}/.well-known/oauth-protected-resource"
    return (
        settings.public_base_url.rstrip("/") + "/.well-known/oauth-protected-resource"
    )


def _www_authenticate(
    scope: str = "commandcore:read",
    *,
    error: str | None = None,
    error_description: str | None = None,
) -> str:
    if settings.oauth_enabled:
        challenge = (
            f'Bearer resource_metadata="{_resource_metadata_url()}", scope="{scope}"'
        )
        if error:
            challenge += f', error="{error}"'
        if error_description:
            challenge += f', error_description="{error_description}"'
        return challenge
    return 'Bearer realm="CommandCore"'


def _authenticate_bearer(
    token: str | None, client_hint: str | None = None
) -> Principal | None:
    if token is None:
        return None
    if constant_time_token_equal(token, settings.api_token):
        if not settings.public_bootstrap_enabled:
            return None
        return Principal(
            settings.bootstrap_subject,
            client_hint or "http-api",
            "bootstrap-bearer",
            ALL_SCOPES,
        )
    if oauth_verifier is not None:
        try:
            return oauth_verifier.verify(token)
        except Exception:
            return None
    return None


def require_principal(
    request: Request,
    authorization: str | None = Header(default=None),
    x_commandcore_client: str | None = Header(default=None),
) -> Principal:
    principal = _authenticate_bearer(_bearer(authorization), x_commandcore_client)
    if principal is not None:
        return principal

    panel_cookie = request.cookies.get(settings.panel_cookie_name)
    if panel_cookie:
        claims = panel_session_claims(
            secret=settings.session_secret, token=panel_cookie
        )
        if claims:
            if request.method not in SAFE_METHODS and not _same_origin(request):
                raise HTTPException(403, "cross-origin panel mutation denied")
            kind = str(claims.get("auth_kind", "panel-cookie"))
            scopes = (
                tuple(claims.get("scopes") or ())
                if kind == "oauth2-panel"
                else ALL_SCOPES
            )
            if (
                kind == "oauth2-panel"
                and request.method not in SAFE_METHODS
                and not request.headers.get("origin")
                and request.headers.get("sec-fetch-site") != "same-origin"
            ):
                raise HTTPException(403, "panel origin required")
            return Principal(
                str(claims["sub"]),
                x_commandcore_client or "web-panel",
                kind,
                scopes,
                settings.oauth_issuer if kind == "oauth2-panel" else "",
            )

    invalid_token = _bearer(authorization) is not None
    raise HTTPException(
        status_code=401,
        detail="unauthorized",
        headers={
            "WWW-Authenticate": _www_authenticate(
                error="invalid_token" if invalid_token else None,
                error_description="The access token is invalid or expired"
                if invalid_token
                else None,
            )
        },
    )


def require_admin(principal: Principal = Depends(require_principal)) -> Principal:
    if principal.auth_kind in {"bootstrap-bearer", "panel-cookie"} or scope_allows(
        principal.scopes, ADMIN_SCOPE
    ):
        return principal
    raise HTTPException(status_code=403, detail="admin scope required")


def _owned_device(
    principal: Principal, device_id: str, *, allow_revoked: bool = True
) -> dict[str, Any]:
    device = db.get_device(device_id)
    if not device or device["owner_id"] != principal.subject:
        raise HTTPException(404, "device not found")
    if not allow_revoked and device["revoked_at"]:
        raise HTTPException(409, "device revoked")
    return device


def _accessible_device(
    principal: Principal, device_id: str, *, allow_revoked: bool = True
) -> dict[str, Any]:
    device = db.get_accessible_device(principal.subject, device_id)
    if not device:
        raise HTTPException(404, "device not found")
    if not allow_revoked and device["revoked_at"]:
        raise HTTPException(409, "device revoked")
    return device


def _audit_admin(
    principal: Principal,
    *,
    tool: str,
    device_id: str | None,
    arguments: dict[str, Any],
    status: str = "ok",
    risk: str = "medium",
) -> None:
    db.add_audit(
        user_id=principal.subject,
        client_id=principal.client_id,
        device_id=device_id,
        tool=tool,
        args_summary=audit_summary(arguments),
        execution_id=None,
        status=status,
        duration_ms=0,
        exit_code=None,
        risk_class=risk,
    )


async def heartbeat_monitor() -> None:
    while True:
        await asyncio.sleep(max(5, settings.heartbeat_timeout_seconds // 3))
        db.expire_stale_devices(time.time() - settings.heartbeat_timeout_seconds)


@asynccontextmanager
async def lifespan(app: FastAPI):
    task = asyncio.create_task(heartbeat_monitor())
    try:
        yield
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


app = FastAPI(title="CommandCore", version=__version__, lifespan=lifespan)


@app.middleware("http")
async def browser_security(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
    )
    if settings.public_base_url.startswith("https://"):
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
    if request.url.path.startswith(("/auth", "/enroll", "/api", "/mcp", "/recovery")):
        response.headers["Cache-Control"] = "no-store"
    return response


from .distribution import install_distribution_routes

install_distribution_routes(app, os.getenv("COMMANDCORE_DISTRIBUTION_DIR", ""))

from .onboarding_routes import install_routes

enrollment_service = install_routes(
    app,
    db,
    settings,
    require_principal,
    _same_origin,
    oauth_verifier,
    web_asset("onboarding.html"),
    agents,
)


@app.get("/.well-known/oauth-protected-resource")
@app.get("/.well-known/oauth-protected-resource/mcp")
@app.get("/.well-known/oauth-protected-resource/mcp/core")
async def oauth_protected_resource() -> JSONResponse:
    if not settings.oauth_enabled:
        return JSONResponse({"error": "oauth_not_configured"}, status_code=404)
    return JSONResponse(
        {
            "resource": settings.mcp_base_url,
            "authorization_servers": list(
                settings.oauth_authorization_servers or (settings.oauth_issuer,)
            ),
            "scopes_supported": list(ALL_SCOPES),
            "bearer_methods_supported": ["header"],
            "resource_name": "CommandCore MCP",
        }
    )


@app.get("/healthz")
async def healthz() -> dict[str, Any]:
    return {
        "status": "ok",
        "version": __version__,
        "agents_online": await agents.count(),
    }


@app.post("/api/session")
async def panel_login(req: PanelLoginRequest) -> JSONResponse:
    if not settings.public_bootstrap_enabled or not constant_time_token_equal(
        req.token, settings.api_token
    ):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    session = issue_panel_session(
        secret=settings.session_secret,
        subject=settings.bootstrap_subject,
        ttl_seconds=settings.panel_session_ttl_seconds,
    )
    response = JSONResponse(
        {
            "ok": True,
            "subject": settings.bootstrap_subject,
            "expires_in": settings.panel_session_ttl_seconds,
        }
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
    return response


@app.get("/api/session")
async def panel_session(
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    return {
        "authenticated": True,
        "subject": principal.subject,
        "client_id": principal.client_id,
        "auth_kind": principal.auth_kind,
        "scopes": list(principal.scopes),
        "version": __version__,
    }


@app.delete("/api/session")
async def panel_logout(request: Request) -> JSONResponse:
    if not _same_origin(request):
        return JSONResponse(
            {"error": "cross-origin panel mutation denied"}, status_code=403
        )
    response = JSONResponse({"ok": True})
    response.delete_cookie(settings.panel_cookie_name, path="/")
    return response


@app.get("/metrics")
async def prometheus_metrics(
    _: Principal = Depends(require_admin),
) -> PlainTextResponse:
    return PlainTextResponse(
        metrics.render(await agents.count()), media_type="text/plain; version=0.0.4"
    )


@app.get("/")
async def dashboard() -> HTMLResponse:
    web_path = web_asset("index.html")
    if web_path.exists():
        return HTMLResponse(web_page(web_path), headers={"Cache-Control": "no-store"})
    return HTMLResponse("<h1>CommandCore</h1><p>Web assets not found.</p>")


@app.get("/panel.css")
@app.get("/onboarding.css")
@app.get("/legacy-admin.css")
async def panel_styles(request: Request) -> Response:
    path = web_asset(request.url.path.lstrip("/"))
    return Response(
        path.read_text(encoding="utf-8"),
        media_type="text/css",
        headers={"Cache-Control": "no-cache"},
    )


@app.get("/commandcore-logo.webp")
@app.get("/commandcore-icon.png")
@app.get("/commandcore-wordmark.png")
async def commandcore_logo(request: Request) -> Response:
    path = web_asset(request.url.path.lstrip("/"))
    return Response(
        path.read_bytes(),
        media_type="image/png" if path.suffix == ".png" else "image/webp",
        headers={"Cache-Control": "public, max-age=86400"},
    )


@app.get("/panel.js")
@app.get("/onboarding.js")
@app.get("/legacy-admin.js")
async def panel_script(request: Request) -> Response:
    path = web_asset(request.url.path.lstrip("/"))
    return Response(
        path.read_text(encoding="utf-8"),
        media_type="application/javascript",
        headers={"Cache-Control": "no-cache"},
    )


@app.get("/admin")
async def recovery_dashboard(_: Principal = Depends(require_admin)) -> HTMLResponse:
    path = web_asset("legacy-admin.html")
    return HTMLResponse(web_page(path), headers={"Cache-Control": "no-store"})


@app.get("/api/overview")
async def api_overview(
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    snapshot = db.overview(principal.subject)
    visible_ids = {
        d["id"]
        for d in db.list_accessible_devices(principal.subject)
        if d["status"] != "revoked"
    }
    online_ids = [d for d in await agents.online_device_ids() if d in visible_ids]
    snapshot.update(
        {
            "version": __version__,
            "agent_protocol_version": "1",
            "connected_sockets": len(online_ids),
            "connected_device_ids": online_ids,
            "mcp_endpoint": settings.mcp_base_url,
            "agent_endpoint": settings.agent_base_url,
        }
    )
    return snapshot


@app.get("/api/devices")
async def api_devices(
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    connected = set(await agents.online_device_ids())
    devices = [
        d
        for d in db.list_accessible_devices(principal.subject)
        if d["status"] != "revoked"
    ]
    for device in devices:
        device["connected"] = device["id"] in connected
        device["recommended_agent_version"] = settings.recommended_agent_version
        device["agent_update_available"] = (
            device.get("agent_version") != settings.recommended_agent_version
        )
        device["agent_update_manifest_url"] = settings.agent_update_manifest_url or None
    return {
        "devices": devices,
        "recommended_agent_version": settings.recommended_agent_version,
        "agent_update_manifest_url": settings.agent_update_manifest_url or None,
    }


@app.get("/api/devices/{device_id}")
async def api_device(
    device_id: str, principal: Principal = Depends(require_principal)
) -> dict[str, Any]:
    device = _accessible_device(principal, device_id)
    device["connected"] = device_id in set(await agents.online_device_ids())
    device["active_jobs"] = db.list_jobs(
        principal.subject, active_only=True, device_id=device_id, limit=100
    )
    device["recommended_agent_version"] = settings.recommended_agent_version
    device["agent_update_available"] = (
        device.get("agent_version") != settings.recommended_agent_version
    )
    device["agent_update_manifest_url"] = settings.agent_update_manifest_url or None
    if device.get("is_owner"):
        device["grants"] = db.list_device_grants(principal.subject, device_id)
    return {"device": device}


@app.patch("/api/devices/{device_id}")
async def update_device(
    device_id: str,
    req: DeviceUpdateRequest,
    principal: Principal = Depends(require_admin),
) -> dict[str, Any]:
    _owned_device(principal, device_id, allow_revoked=False)
    try:
        ok = db.update_device_metadata(
            principal.subject, device_id, display_name=req.display_name, tags=req.tags
        )
    except ValueError as exc:
        _audit_admin(
            principal,
            tool="admin.device.update",
            device_id=device_id,
            arguments=req.model_dump(exclude_none=True),
            status="error",
        )
        raise HTTPException(400, str(exc)) from exc
    if not ok:
        raise HTTPException(404, "device not found")
    _audit_admin(
        principal,
        tool="admin.device.update",
        device_id=device_id,
        arguments=req.model_dump(exclude_none=True),
        risk="low",
    )
    return {"ok": True, "device": db.get_device(device_id)}


@app.get("/api/devices/{device_id}/grants")
async def list_grants(
    device_id: str, principal: Principal = Depends(require_admin)
) -> dict[str, Any]:
    _owned_device(principal, device_id)
    return {"grants": db.list_device_grants(principal.subject, device_id)}


@app.put("/api/devices/{device_id}/grants")
async def put_grant(
    device_id: str,
    req: DeviceGrantRequest,
    principal: Principal = Depends(require_admin),
) -> dict[str, Any]:
    _owned_device(principal, device_id, allow_revoked=False)
    try:
        ok = db.upsert_device_grant(
            principal.subject,
            device_id,
            req.subject,
            req.max_permission_profile,
            principal.subject,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    if not ok:
        raise HTTPException(404, "device not found")
    _audit_admin(
        principal,
        tool="admin.device.grant",
        device_id=device_id,
        arguments={
            "subject": req.subject,
            "max_permission_profile": req.max_permission_profile,
        },
        risk="high",
    )
    return {"ok": True, "grants": db.list_device_grants(principal.subject, device_id)}


@app.delete("/api/devices/{device_id}/grants")
async def delete_grant(
    device_id: str, subject: str, principal: Principal = Depends(require_admin)
) -> dict[str, Any]:
    _owned_device(principal, device_id)
    if not db.revoke_device_grant(principal.subject, device_id, subject):
        raise HTTPException(404, "grant not found")
    _audit_admin(
        principal,
        tool="admin.device.grant_revoke",
        device_id=device_id,
        arguments={"subject": subject},
        risk="high",
    )
    return {"ok": True}


@app.get("/api/fleet-rollouts")
async def list_fleet_rollouts(
    limit: int = 50, principal: Principal = Depends(require_admin)
) -> dict[str, Any]:
    return {
        "rollouts": db.list_fleet_rollouts(
            principal.subject, limit=max(1, min(limit, 200))
        )
    }


@app.post("/api/fleet-rollouts")
async def create_fleet_rollout(
    req: FleetRolloutRequest, principal: Principal = Depends(require_admin)
) -> dict[str, Any]:
    try:
        rollout = db.create_fleet_rollout(
            owner_id=principal.subject,
            created_by=principal.subject,
            target_version=req.target_version,
            manifest_url=req.manifest_url,
            device_ids=req.device_ids,
            canary_count=req.canary_count,
            ring_size=req.ring_size,
            stop_on_failure=req.stop_on_failure,
        )
    except KeyError as exc:
        raise HTTPException(404, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    _audit_admin(
        principal,
        tool="admin.fleet.create",
        device_id=None,
        arguments={
            "rollout_id": rollout["id"],
            "target_version": req.target_version,
            "device_count": len(req.device_ids),
        },
        risk="critical",
    )
    return {"rollout": rollout}


@app.get("/api/fleet-rollouts/{rollout_id}")
async def get_fleet_rollout(
    rollout_id: str, principal: Principal = Depends(require_admin)
) -> dict[str, Any]:
    try:
        rollout = fleet.reconcile(principal.subject, rollout_id)
    except KeyError as exc:
        raise HTTPException(404, str(exc)) from exc
    return {"rollout": rollout}


@app.post("/api/fleet-rollouts/{rollout_id}/advance")
async def advance_fleet_rollout(
    rollout_id: str, principal: Principal = Depends(require_admin)
) -> dict[str, Any]:
    try:
        result = await fleet.advance(principal.subject, rollout_id)
    except KeyError as exc:
        raise HTTPException(404, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    _audit_admin(
        principal,
        tool="admin.fleet.advance",
        device_id=result.get("device_id"),
        arguments={"rollout_id": rollout_id, "action": result.get("action")},
        risk="critical",
    )
    return result


@app.post("/api/fleet-rollouts/{rollout_id}/resume")
async def resume_fleet_rollout(
    rollout_id: str, principal: Principal = Depends(require_admin)
) -> dict[str, Any]:
    try:
        rollout = fleet.resume(principal.subject, rollout_id)
    except KeyError as exc:
        raise HTTPException(404, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    _audit_admin(
        principal,
        tool="admin.fleet.resume",
        device_id=None,
        arguments={"rollout_id": rollout_id},
        risk="critical",
    )
    return {"rollout": rollout}


@app.post("/api/fleet-rollouts/{rollout_id}/devices/{device_id}/skip")
async def skip_fleet_device(
    rollout_id: str, device_id: str, principal: Principal = Depends(require_admin)
) -> dict[str, Any]:
    rollout = db.get_fleet_rollout(principal.subject, rollout_id)
    if not rollout:
        raise HTTPException(404, "fleet rollout not found")
    member = next(
        (d for d in rollout["devices"] if str(d["device_id"]) == device_id), None
    )
    if not member:
        raise HTTPException(404, "rollout device not found")
    if str(member["state"]) in {"activating", "committed"}:
        raise HTTPException(409, "cannot skip an activating or committed device")
    db.set_fleet_device_state(
        principal.subject,
        rollout_id,
        device_id,
        "skipped",
        last_error="operator_skipped",
        event="device.skipped",
        detail={"by": principal.subject},
    )
    _audit_admin(
        principal,
        tool="admin.fleet.skip",
        device_id=device_id,
        arguments={"rollout_id": rollout_id},
        risk="high",
    )
    return {"rollout": fleet.reconcile(principal.subject, rollout_id)}


@app.delete("/api/fleet-rollouts/{rollout_id}")
async def cancel_fleet_rollout(
    rollout_id: str, principal: Principal = Depends(require_admin)
) -> dict[str, Any]:
    if not db.cancel_fleet_rollout(principal.subject, rollout_id):
        raise HTTPException(404, "active fleet rollout not found")
    _audit_admin(
        principal,
        tool="admin.fleet.cancel",
        device_id=None,
        arguments={"rollout_id": rollout_id},
        risk="critical",
    )
    return {"ok": True, "rollout": db.get_fleet_rollout(principal.subject, rollout_id)}


@app.get("/api/audit")
async def api_audit(
    limit: int = 100,
    device_id: str | None = None,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    if device_id:
        _owned_device(principal, device_id)
    return {
        "events": db.recent_audit(
            principal.subject, max(1, min(limit, 500)), device_id=device_id
        )
    }


@app.get("/api/jobs")
async def api_jobs(
    active: bool = False,
    device_id: str | None = None,
    limit: int = 100,
    principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    if device_id:
        _owned_device(principal, device_id)
    return {
        "jobs": db.list_jobs(
            principal.subject,
            active_only=active,
            device_id=device_id,
            limit=max(1, min(limit, 500)),
        )
    }


@app.get("/api/enrollment-tokens")
async def enrollment_tokens(
    principal: Principal = Depends(require_admin),
) -> dict[str, Any]:
    return {"tokens": db.list_enrollment_tokens(principal.subject)}


@app.post("/api/enrollment-tokens")
async def create_enrollment(
    principal: Principal = Depends(require_admin),
) -> dict[str, Any]:
    item = db.create_enrollment_token(
        principal.subject, settings.enrollment_ttl_seconds
    )
    _audit_admin(
        principal,
        tool="admin.enrollment.create",
        device_id=None,
        arguments={"token_id": item["id"], "expires_at": item["expires_at"]},
        risk="medium",
    )
    return {
        **item,
        "enroll_example": (
            f"commandcore-agent enroll {item['token']} --control-url {settings.public_base_url} "
            f"--agent-url {settings.agent_base_url}"
        ),
    }


@app.delete("/api/enrollment-tokens/{token_id}")
async def cancel_enrollment(
    token_id: str, principal: Principal = Depends(require_admin)
) -> dict[str, Any]:
    if not db.cancel_enrollment_token(principal.subject, token_id):
        _audit_admin(
            principal,
            tool="admin.enrollment.cancel",
            device_id=None,
            arguments={"token_id": token_id},
            status="error",
            risk="medium",
        )
        raise HTTPException(404, "active enrollment token not found")
    _audit_admin(
        principal,
        tool="admin.enrollment.cancel",
        device_id=None,
        arguments={"token_id": token_id},
        risk="medium",
    )
    return {"ok": True}


@app.post("/api/agent/enroll")
async def enroll(req: EnrollmentRequest) -> JSONResponse:
    if req.protocol_version != "1":
        return JSONResponse(
            {"error": "unsupported_agent_protocol", "supported": ["1"]}, status_code=400
        )
    owner = db.consume_enrollment_token(req.token)
    if not owner:
        return JSONResponse(
            {"error": "invalid_expired_or_used_enrollment_token"}, status_code=401
        )
    result = db.register_device(
        owner_id=owner,
        display_name=req.display_name,
        hostname=req.hostname,
        platform=req.platform,
        architecture=req.architecture,
        agent_version=req.agent_version,
        agent_protocol_version=req.protocol_version,
        public_key_b64=req.public_key_b64,
        capabilities=req.capabilities,
        auto_approve=settings.auto_approve_enrollment,
    )
    db.add_audit(
        user_id=owner,
        client_id="agent-enrollment",
        device_id=result["device_id"],
        tool="admin.device.enroll",
        args_summary=audit_summary(
            {
                "display_name": req.display_name,
                "hostname": req.hostname,
                "platform": req.platform,
                "architecture": req.architecture,
            }
        ),
        execution_id=None,
        status="ok",
        duration_ms=0,
        exit_code=None,
        risk_class="medium",
    )
    return JSONResponse(result, status_code=201)


@app.post("/api/devices/{device_id}/approve")
async def approve(
    device_id: str, principal: Principal = Depends(require_admin)
) -> dict[str, Any]:
    if not db.approve_device(principal.subject, device_id):
        _audit_admin(
            principal,
            tool="admin.device.approve",
            device_id=device_id,
            arguments={},
            status="error",
            risk="high",
        )
        raise HTTPException(404, "device not found, already approved, or revoked")
    _audit_admin(
        principal,
        tool="admin.device.approve",
        device_id=device_id,
        arguments={},
        risk="high",
    )
    return {"ok": True, "device": db.get_device(device_id)}


@app.post("/api/devices/{device_id}/revoke")
async def revoke(
    device_id: str, principal: Principal = Depends(require_admin)
) -> dict[str, Any]:
    if not db.revoke_device(principal.subject, device_id):
        _audit_admin(
            principal,
            tool="admin.device.revoke",
            device_id=device_id,
            arguments={},
            status="error",
            risk="critical",
        )
        raise HTTPException(404, "device not found or already revoked")
    await agents.disconnect_device(device_id)
    _audit_admin(
        principal,
        tool="admin.device.revoke",
        device_id=device_id,
        arguments={},
        risk="critical",
    )
    return {"ok": True}


@app.post("/api/devices/{device_id}/rotate-token")
async def rotate_token(
    device_id: str, principal: Principal = Depends(require_admin)
) -> dict[str, Any]:
    raw = db.rotate_device_token(principal.subject, device_id)
    if not raw:
        _audit_admin(
            principal,
            tool="admin.device.rotate_token",
            device_id=device_id,
            arguments={},
            status="error",
            risk="critical",
        )
        raise HTTPException(404, "device not found or revoked")
    await agents.disconnect_device(device_id)
    _audit_admin(
        principal,
        tool="admin.device.rotate_token",
        device_id=device_id,
        arguments={},
        risk="critical",
    )
    return {
        "device_id": device_id,
        "device_token": raw,
        "note": "Store this on the device with `commandcore-agent set-token` (hidden prompt) and restart the Agent. It is shown only once.",
    }


@app.post("/api/devices/{device_id}/permissions")
async def permissions(
    device_id: str,
    req: PermissionRequest,
    principal: Principal = Depends(require_admin),
) -> dict[str, Any]:
    before = _owned_device(principal, device_id, allow_revoked=False)[
        "permission_profile"
    ]
    try:
        ok = db.set_permission(principal.subject, device_id, req.profile)
    except ValueError as exc:
        _audit_admin(
            principal,
            tool="admin.device.permissions",
            device_id=device_id,
            arguments={"from": before, "to": req.profile},
            status="error",
            risk="high",
        )
        raise HTTPException(400, str(exc)) from exc
    except RuntimeError as exc:
        _audit_admin(
            principal,
            tool="admin.device.permissions",
            device_id=device_id,
            arguments={"from": before, "to": req.profile},
            status="error",
            risk="high",
        )
        raise HTTPException(409, str(exc)) from exc
    if not ok:
        raise HTTPException(404, "device not found")
    _audit_admin(
        principal,
        tool="admin.device.permissions",
        device_id=device_id,
        arguments={"from": before, "to": req.profile},
        risk="high",
    )
    return {"ok": True, "device": db.get_device(device_id)}


@app.post("/api/devices/{device_id}/inspect")
async def inspect_device(
    device_id: str, principal: Principal = Depends(require_principal)
) -> dict[str, Any]:
    device = _accessible_device(principal, device_id, allow_revoked=False)
    if device["status"] != "online":
        raise HTTPException(409, "device_offline")
    panel_principal = principal
    try:
        info = await tools.call(
            panel_principal, "system.info", {"device_id": device_id}
        )
        usage = await tools.call(
            panel_principal, "system.metrics", {"device_id": device_id}
        )
    except ToolError as exc:
        raise HTTPException(409, exc.message) from exc
    return {
        "device_id": device_id,
        "system_info": info.get("result"),
        "system_metrics": usage.get("result"),
    }


@app.websocket("/agent")
async def agent_socket(websocket: WebSocket) -> None:
    await agents.handle_websocket(websocket)


@app.post("/mcp")
@app.post("/mcp/core")
async def mcp_endpoint(request: Request) -> JSONResponse:
    token = _bearer(request.headers.get("authorization"))
    principal = _authenticate_bearer(token, request.headers.get("x-commandcore-client"))
    if principal is None:
        return JSONResponse(
            {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32001, "message": "Unauthorized"},
            },
            status_code=401,
            headers={
                "WWW-Authenticate": _www_authenticate(
                    error="invalid_token" if token is not None else None,
                    error_description="The access token is invalid or expired"
                    if token is not None
                    else None,
                )
            },
        )
    handler = core_mcp if request.url.path == "/mcp/core" else mcp
    return await handler.handle(request, principal)


@app.get("/api/devices/{device_id}/activity")
async def device_activity(
    device_id: str, principal: Principal = Depends(require_principal)
):
    _accessible_device(principal, device_id, allow_revoked=False)
    if not scope_allows(
        principal.scopes, "commandcore:read"
    ) and principal.auth_kind not in {"bootstrap-bearer", "panel-cookie"}:
        raise HTTPException(403, "read scope required")
    return {"events": db.list_activity(device_id)}


@app.post("/recovery/mcp", include_in_schema=False)
async def recovery_mcp(request: Request):
    import ipaddress

    try:
        local = bool(
            request.client and ipaddress.ip_address(request.client.host).is_loopback
        )
    except ValueError:
        local = False
    token = _bearer(request.headers.get("authorization"))
    forwarded = any(
        request.headers.get(h)
        for h in ("forwarded", "x-forwarded-for", "cf-connecting-ip")
    )
    if (
        not settings.recovery_enabled
        or not local
        or forwarded
        or not token
        or not constant_time_token_equal(token, settings.api_token)
    ):
        raise HTTPException(401, "recovery authentication denied")
    principal = Principal(
        settings.bootstrap_subject, "local-recovery", "bootstrap-bearer", ALL_SCOPES
    )
    return await mcp.handle(request, principal)


@app.get("/mcp")
@app.delete("/mcp")
async def mcp_non_post() -> JSONResponse:
    return JSONResponse(
        {
            "error": "MCP 2026 Streamable HTTP uses POST; GET/DELETE are not implemented."
        },
        status_code=405,
    )


def run() -> None:
    uvicorn.run(
        "commandcore_server.main:app",
        host=settings.host,
        port=settings.port,
        reload=False,
        access_log=False,
        proxy_headers=False,
    )


if __name__ == "__main__":
    run()
