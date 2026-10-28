"""Staged authenticated collaboration review: deny-only until trust and signing are provisioned.

Chat/API OAuth bearer credentials cannot attest a human clicking the private panel.
"""
from __future__ import annotations
from fastapi import Depends, HTTPException, Request
from time import time
from fastapi.responses import JSONResponse, HTMLResponse, Response
from html import escape
from urllib.parse import quote

from .collaboration_approval import AuthorizationDenied
from .collaboration_trusted_preview import preview_owned_request
from .collaboration_review_session import prepare_review_challenge


def install_collaboration_review_routes(app, tools_service, require_principal, same_origin):
    authenticated = Depends(require_principal)

    def trusted_panel(request: Request, principal, *, mutation: bool = False):
        if principal.auth_kind not in ("panel-cookie", "oauth2-panel"):
            raise HTTPException(403, "private_panel_login_required")
        if mutation:
            if not same_origin(request):
                raise HTTPException(403, "same_origin_required")
            # The existing panel enforces same-origin fetch metadata for changes.
            if not request.headers.get("origin") and request.headers.get("sec-fetch-site") != "same-origin":
                raise HTTPException(403, "explicit_same_origin_interaction_required")

    # Registration is opt-in and fail-closed. Never infer RP identity from
    # client-supplied Host, X-Forwarded-Host, or Origin headers.
    @app.post("/api/collaboration/webauthn/register/begin", include_in_schema=False)
    async def begin_webauthn_registration(request: Request, principal=authenticated):
        import os
        trusted_panel(request, principal, mutation=True)
        rp_id = os.environ.get("COMMANDCORE_WEBAUTHN_RP_ID", "")
        origin = os.environ.get("COMMANDCORE_WEBAUTHN_ORIGIN", "")
        if not rp_id or origin != "https://" + rp_id:
            raise HTTPException(503, "webauthn_registration_not_configured")
        try:
            result = tools_service._registration_ceremonies().begin(
                owner=principal.subject, rp_id=rp_id, origin=origin, now=int(time()))
        except AuthorizationDenied:
            raise HTTPException(409, "webauthn_registration_unavailable") from None
        return JSONResponse(result, headers={"Cache-Control":"no-store"})

    @app.post("/api/collaboration/webauthn/register/finish", include_in_schema=False)
    async def finish_webauthn_registration(request: Request, principal=authenticated):
        import os
        trusted_panel(request, principal, mutation=True)
        rp_id = os.environ.get("COMMANDCORE_WEBAUTHN_RP_ID", "")
        origin = os.environ.get("COMMANDCORE_WEBAUTHN_ORIGIN", "")
        if not rp_id or origin != "https://" + rp_id:
            raise HTTPException(503, "webauthn_registration_not_configured")
        try:
            declared_length = int(request.headers.get("content-length", "0") or 0)
        except ValueError:
            raise HTTPException(400, "invalid_content_length") from None
        if declared_length < 0:
            raise HTTPException(400, "invalid_content_length")
        if declared_length > 32768:
            raise HTTPException(413, "registration_response_too_large")
        raw = await request.body()
        if len(raw)>32768:
            raise HTTPException(413, "registration_response_too_large")
        try:
            import json
            payload=json.loads(raw)
            if not isinstance(payload, dict) or not isinstance(payload.get("challenge"),str) or not isinstance(payload.get("response"),dict):
                raise ValueError("invalid registration response")
            challenge=payload["challenge"]
            if len(challenge)>256:
                raise ValueError("invalid challenge")
        except (ValueError,UnicodeDecodeError):
            raise HTTPException(400, "invalid_registration_response") from None
        try:
            result=tools_service._registration_ceremonies().finish_and_enroll(
                registry=tools_service._webauthn_credentials(),
                owner=principal.subject,challenge=challenge,
                response=payload["response"],now=int(time()))
        except AuthorizationDenied:
            raise HTTPException(409, "webauthn_registration_rejected") from None
        return JSONResponse(result,headers={"Cache-Control":"no-store"})

    @app.get("/collaboration/webauthn-enroll.js", include_in_schema=False)
    async def registration_script(request: Request, principal=authenticated):
        trusted_panel(request, principal)
        source = r"""
const button = document.getElementById('enroll-passkey');
const status = document.getElementById('enrollment-status');
const decode = (str) => Uint8Array.from(atob(str.replace(/-/g,'+').replace(/_/g,'/') + '='.repeat((4-str.length%4)%4)), c=>c.charCodeAt(0));
const encode = (value) => {
  const bytes = new Uint8Array(value);
  let raw = '';
  for (const b of bytes) raw += String.fromCharCode(b);
  return btoa(raw).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
};
button?.addEventListener('click', async () => {
  button.disabled = true;
  status.textContent = 'Requesting passkey enrollment…';
  try {
    if (!window.PublicKeyCredential || !navigator.credentials?.create) throw new Error('WebAuthn unavailable');
    const start = await fetch('/api/collaboration/webauthn/register/begin', {method:'POST',headers:{'Content-Type':'application/json'},credentials:'same-origin'});
    if (!start.ok) throw new Error('Enrollment unavailable ('+start.status+')');
    const issued = await start.json();
    const options = issued.options.publicKey;
    options.challenge = decode(options.challenge);
    options.user.id = decode(options.user.id);
    if (options.excludeCredentials) for (const item of options.excludeCredentials) item.id = decode(item.id);
    const credential = await navigator.credentials.create({publicKey:options});
    if (!credential || credential.type !== 'public-key') throw new Error('No public-key credential');
    const response = {id:credential.id,rawId:encode(credential.rawId),type:credential.type,
      response:{clientDataJSON:encode(credential.response.clientDataJSON),
        attestationObject:encode(credential.response.attestationObject)}};
    const finish = await fetch('/api/collaboration/webauthn/register/finish', {
      method:'POST',headers:{'Content-Type':'application/json'},credentials:'same-origin',
      body:JSON.stringify({challenge:issued.challenge,response})});
    if (!finish.ok) throw new Error('Credential rejected ('+finish.status+')');
    status.textContent = 'Passkey enrolled. Message approval remains disabled.';
  } catch (error) {
    status.textContent = 'Enrollment failed: '+String(error.message || error);
  } finally { button.disabled = false; }
});
"""
        return Response(source, media_type="application/javascript", headers={
            "Cache-Control":"no-store","X-Content-Type-Options":"nosniff"})

    @app.get("/collaboration/webauthn-review.js", include_in_schema=False)
    async def review_verification_script(request: Request, principal=authenticated):
        trusted_panel(request, principal)
        source = r"""
const btn=document.getElementById('verify-review-passkey');
const status=document.getElementById('review-verification-status');
const b64=bytes=>{let s=''; for(const x of new Uint8Array(bytes))s+=String.fromCharCode(x);return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');};
btn?.addEventListener('click',async()=>{
 btn.disabled=true;
 try {
  if(!window.PublicKeyCredential||!navigator.credentials?.get)throw Error('WebAuthn unavailable');
  const base='/api/collaboration/approvals/'+encodeURIComponent(btn.dataset.requestId);
  const start=await fetch(base+'/review-challenge',{method:'POST',credentials:'same-origin'});
  if(!start.ok)throw Error('Challenge unavailable');
  const issued=await start.json();
  const assertion=await navigator.credentials.get({publicKey:{
   challenge:new TextEncoder().encode(issued.challenge),userVerification:'required',timeout:90000}});
  if(!assertion||assertion.type!=='public-key')throw Error('No public-key assertion');
  const response=await fetch(base+'/verify-webauthn',{method:'POST',credentials:'same-origin',
   headers:{'Content-Type':'application/json'},body:JSON.stringify({
    challenge:issued.challenge,credentialId:b64(assertion.rawId),
    authenticatorData:b64(assertion.response.authenticatorData),
    clientDataJSON:b64(assertion.response.clientDataJSON),
    signature:b64(assertion.response.signature)})});
  if(!response.ok)throw Error('Verification rejected');
  const result=await response.json();
  if(result.credential_verified!==true||result.delivery_authorized!==false)throw Error('Unexpected verification result');
  status.textContent='Identity verified; message delivery remains disabled.';
 }catch(e){status.textContent='Verification failed: '+String(e.message||e);}
 finally{btn.disabled=false;}
});
"""
        return Response(source,media_type="application/javascript",headers={
            "Cache-Control":"no-store","X-Content-Type-Options":"nosniff"})

    @app.get("/collaboration/review", include_in_schema=False)
    async def review_page(request: Request, principal=authenticated):
        trusted_panel(request, principal)
        pending = tools_service._approval_ledger().list_pending(
            owner_subject=principal.subject)
        items = "".join(
            "<li><strong>" + escape(r.expected_title) + "</strong> — "
            + escape(r.device_id) + " (expires " + str(r.expires_at) + ")"
            + ' <a href="/collaboration/review/'
            + escape(quote(r.request_id, safe=""), quote=True)
            + '">Review message</a>'
            + '<form method="post" action="/api/collaboration/approvals/'
            + escape(quote(r.request_id, safe=""), quote=True) + '/deny">'
            + '<button type="submit">Reject request</button></form></li>'
            for r in pending
        )
        body = (
            '<!doctype html><html><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            '<title>CommandCore — Collaboration review</title></head><body>'
            '<main><h1>Pending collaboration requests</h1>'
            '<p>No message can be approved or delivered from this page.</p>'
            '<section><h2>Register a passkey</h2>'
            '<p>Registration verifies identity only; it does not enable message delivery.</p>'
            '<button id="enroll-passkey" type="button">Enroll passkey</button>'
            '<p id="enrollment-status" role="status" aria-live="polite"></p>'
            '<script src="/collaboration/webauthn-enroll.js" defer></script>'
            '</section><ul>' + items + '</ul></main></body></html>'
        )
        return HTMLResponse(body, headers={
            "Cache-Control": "no-store",
            "Content-Security-Policy": "default-src 'none'; script-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
            "Referrer-Policy": "no-referrer",
        })

    @app.get("/collaboration/review/{request_id}", include_in_schema=False)
    async def review_message_page(request_id: str, request: Request, principal=authenticated):
        trusted_panel(request, principal)
        if not request_id or len(request_id) > 128:
            raise HTTPException(400, "invalid_request_id")
        ledger = tools_service._approval_ledger()
        record = ledger.get(owner_subject=principal.subject, request_id=request_id)
        if record is None:
            raise HTTPException(404, "request_not_found")
        device = tools_service.db.get_accessible_device(principal.subject, record.device_id)
        if device is None or device.get("owner_id") != principal.subject:
            raise HTTPException(403, "device_owner_required")
        try:
            result = await preview_owned_request(
                ledger=ledger, agents=tools_service.agents, device=device,
                owner_subject=principal.subject, request_id=request_id, now=int(time()))
        except AuthorizationDenied:
            raise HTTPException(409, "preview_unavailable") from None
        body = (
            '<!doctype html><html><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            '<title>CommandCore — Draft preview</title></head><body>'
            '<main><h1>Read-only draft preview</h1><p>Target: '
            + escape(result["window_title"]) + ' / ' + escape(result["device_id"])
            + '</p><pre style="white-space:pre-wrap;overflow-wrap:anywhere">'
            + escape(result["text"]) + '</pre>'
            + '<p>This page cannot authorize delivery.</p>'
            + '<button id="verify-review-passkey" type="button" data-request-id="'
            + escape(request_id, quote=True) + '">Verify identity with passkey</button>'
            + '<p id="review-verification-status" role="status" aria-live="polite"></p>'
            + '<script src="/collaboration/webauthn-review.js" defer></script>'
            + '<a href="/collaboration/review">Back to requests</a></main></body></html>'
        )
        return HTMLResponse(body, headers={
            "Cache-Control": "no-store",
            "Content-Security-Policy": "default-src 'none'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'",
            "Referrer-Policy": "no-referrer",
        })

    @app.post("/api/collaboration/approvals/{request_id}/review-challenge", include_in_schema=False)
    async def create_review_challenge(request_id: str, request: Request, principal=authenticated):
        trusted_panel(request, principal, mutation=True)
        if not request_id or len(request_id) > 128:
            raise HTTPException(400, "invalid_request_id")
        ledger = tools_service._approval_ledger()
        record = ledger.get(owner_subject=principal.subject, request_id=request_id)
        if record is None:
            raise HTTPException(404, "request_not_found")
        device = tools_service.db.get_accessible_device(principal.subject, record.device_id)
        if device is None or device.get("owner_id") != principal.subject:
            raise HTTPException(403, "device_owner_required")
        try:
            result = await prepare_review_challenge(
                ledger=ledger, challenges=tools_service._review_challenges(),
                agents=tools_service.agents, device=device,
                owner_subject=principal.subject, request_id=request_id, now=int(time()))
        except AuthorizationDenied:
            raise HTTPException(409, "review_challenge_unavailable") from None
        return JSONResponse(result, headers={"Cache-Control": "no-store"})

    @app.post("/api/collaboration/approvals/{request_id}/verify-webauthn", include_in_schema=False)
    async def verify_review_webauthn(request_id: str, request: Request, principal=authenticated):
        # Verification only: never call decide(), issuer, dispatch or deliver.
        import base64
        import binascii
        import json
        import os
        trusted_panel(request, principal, mutation=True)
        rp_id=os.environ.get("COMMANDCORE_WEBAUTHN_RP_ID","")
        origin=os.environ.get("COMMANDCORE_WEBAUTHN_ORIGIN","")
        if not rp_id or origin != "https://" + rp_id:
            raise HTTPException(503, "webauthn_review_not_configured")
        if not request_id or len(request_id)>128:
            raise HTTPException(400, "invalid_request_id")
        try:
            declared_length=int(request.headers.get("content-length","0") or 0)
        except ValueError:
            raise HTTPException(400,"invalid_content_length") from None
        if declared_length<0:
            raise HTTPException(400,"invalid_content_length")
        if declared_length>16384:
            raise HTTPException(413,"assertion_too_large")
        body=await request.body()
        if len(body)>16384:
            raise HTTPException(413,"assertion_too_large")
        try:
            payload=json.loads(body)
            if not isinstance(payload,dict):
                raise ValueError("invalid payload")
            token=payload["challenge"]
            credential_id=payload["credentialId"]
            if not isinstance(token,str) or not isinstance(credential_id,str) or len(credential_id)>2048:
                raise ValueError("invalid challenge or credential")
            def decode(value):
                if not isinstance(value,str) or len(value)>16384:
                    raise ValueError("invalid encoding")
                decoded=base64.b64decode(value+"="*((-len(value))%4),altchars=b"-_",validate=True)
                if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != value:
                    raise ValueError("noncanonical base64url")
                return decoded
            if not credential_id or not decode(credential_id):
                raise ValueError("invalid credential identifier")
            auth_data=decode(payload["authenticatorData"])
            client_data=decode(payload["clientDataJSON"])
            signature=decode(payload["signature"])
        except (KeyError,ValueError,TypeError,binascii.Error):
            raise HTTPException(400,"invalid_webauthn_assertion") from None
        ledger=tools_service._approval_ledger()
        record=ledger.get(owner_subject=principal.subject,request_id=request_id)
        if record is None:
            raise HTTPException(404,"request_not_found")
        device=tools_service.db.get_accessible_device(principal.subject,record.device_id)
        if device is None or device.get("owner_id") != principal.subject:
            raise HTTPException(403,"device_owner_required")
        try:
            from .collaboration_webauthn_review import verify_review_assertion
        except ImportError:
            raise HTTPException(503,"webauthn_verifier_unavailable") from None
        try:
            result=await verify_review_assertion(
                ledger=ledger,challenges=tools_service._review_challenges(),
                registry=tools_service._webauthn_credentials(),agents=tools_service.agents,
                device=device,owner_subject=principal.subject,request_id=request_id,
                review_challenge=token,credential_id=credential_id,
                authenticator_data=auth_data,client_data_json=client_data,
                signature=signature,expected_origin=origin,expected_rp_id=rp_id,
                now=int(time()))
        except AuthorizationDenied:
            raise HTTPException(409,"webauthn_review_rejected") from None
        return JSONResponse(result,headers={"Cache-Control":"no-store"})

    @app.get("/api/collaboration/approvals/{request_id}/preview", include_in_schema=False)
    async def owner_preview(request_id: str, request: Request, principal=authenticated):
        trusted_panel(request, principal)
        if not request_id or len(request_id) > 128:
            raise HTTPException(400, "invalid_request_id")
        ledger = tools_service._approval_ledger()
        record = ledger.get(owner_subject=principal.subject, request_id=request_id)
        if record is None:
            raise HTTPException(404, "request_not_found")
        device = tools_service.db.get_accessible_device(principal.subject, record.device_id)
        if device is None or device.get("owner_id") != principal.subject:
            raise HTTPException(403, "device_owner_required")
        try:
            result = await preview_owned_request(
                ledger=ledger, agents=tools_service.agents, device=device,
                owner_subject=principal.subject, request_id=request_id, now=int(time()))
        except AuthorizationDenied:
            raise HTTPException(409, "preview_unavailable") from None
        return JSONResponse(result, headers={"Cache-Control": "no-store"})

    @app.get("/api/collaboration/approvals", include_in_schema=False)
    async def list_requests(request: Request, principal=authenticated):
        trusted_panel(request, principal)
        requests = tools_service._approval_ledger().list_pending(owner_subject=principal.subject)
        return JSONResponse({
            "requests": [{
                "request_id": r.request_id,
                "device_id": r.device_id,
                "window_id": r.window_id,
                "window_title": r.expected_title,
                "expires_at": r.expires_at,
                "status": r.status,
                # Hashes allow exact-action matching without showing private text.
                # A hash alone is NOT sufficient evidence for positive approval.
                "draft_sha256": r.draft_sha256,
                "action_sha256": r.action_digest,
                "approval_ready": False,
                "delivery_authorized": False,
            } for r in requests],
        }, headers={"Cache-Control": "no-store"})

    @app.post("/api/collaboration/approvals/{request_id}/deny", include_in_schema=False)
    async def deny_request(request_id: str, request: Request, principal=authenticated):
        trusted_panel(request, principal, mutation=True)
        if not request_id or len(request_id) > 128:
            raise HTTPException(400, "invalid_request_id")
        try:
            result = tools_service._approval_ledger().decide(
                request_id=request_id, owner_subject=principal.subject,
                actor_subject=principal.subject, actor_attested=True,
                decision="deny", now=int(time()),
            )
        except AuthorizationDenied:
            raise HTTPException(400, "approval_not_pending_or_not_owned") from None
        return JSONResponse(
            {"request_id":result.request_id,"status":result.status,"delivery_authorized":False},
            headers={"Cache-Control":"no-store"},
        )
