"""Owner-scoped device draft readback for a trusted review UI.

This is intentionally not an MCP or public HTTP endpoint.
"""
from __future__ import annotations

from hashlib import sha256
from hmac import compare_digest

from .collaboration_approval import ApprovalLedger, AuthorizationDenied, action_digest


async def preview_owned_request(*, ledger: ApprovalLedger, agents, device: dict,
                                owner_subject: str, request_id: str, now: int):
    request = ledger.get(owner_subject=owner_subject, request_id=request_id)
    if request is None or request.status != "pending":
        raise AuthorizationDenied("approval_not_pending_or_not_owned")
    if now < request.created_at or now >= request.expires_at:
        raise AuthorizationDenied("approval_expired")
    if request.device_id != str(device.get("id", "")):
        raise AuthorizationDenied("device_or_owner_mismatch")
    connections = getattr(agents, "connections", None)
    if not isinstance(connections, dict) or connections.get(request.device_id) is None:
        raise AuthorizationDenied("device_offline")
    response = await agents.dispatch(
        owner_id=owner_subject, device=device, tool="agents.preview",
        arguments={"draft_id": request.draft_id}, timeout_ms=15000)
    if getattr(response, "status", None) != "ok" or not isinstance(getattr(response, "result", None), dict):
        raise AuthorizationDenied("draft_preview_unavailable")
    data = response.result
    text = data.get("text")
    if not isinstance(text, str) or not text or len(text.encode("utf-8")) > 4096:
        raise AuthorizationDenied("draft_preview_invalid")
    digest = sha256(text.encode("utf-8")).hexdigest()
    if not compare_digest(digest, request.draft_sha256):
        raise AuthorizationDenied("draft_preview_hash_mismatch")
    fields = {
        "draft_id": request.draft_id, "window_id": request.window_id,
        "title": request.expected_title, "pid": request.process_id,
        "process_start": request.process_start,
    }
    if any(data.get(k) != v for k, v in fields.items()):
        raise AuthorizationDenied("draft_preview_target_mismatch")
    if data.get("preview_only") is not True or data.get("delivery_authorized") is not False:
        raise AuthorizationDenied("draft_preview_not_read_only")
    try:
        coords_ok = (type(data.get("input_x")) is int and type(data.get("input_y")) is int)
        send_key = data.get("send_key")
        if not coords_ok or send_key not in ("Return", "ctrl+Return"):
            raise AuthorizationDenied("draft_preview_action_invalid")
        verified_action = action_digest(
            device_id=request.device_id, window_id=request.window_id,
            title=request.expected_title, process_id=request.process_id,
            process_start=request.process_start, draft_id=request.draft_id,
            draft_sha256=digest, input_x=data["input_x"],
            input_y=data["input_y"], send_key=send_key)
    except (ValueError, TypeError, KeyError):
        raise AuthorizationDenied("draft_preview_action_invalid") from None
    if not compare_digest(verified_action, request.action_digest):
        raise AuthorizationDenied("draft_preview_action_mismatch")
    return {"request_id": request_id, "device_id": request.device_id,
            "window_title": request.expected_title, "text": text,
            "draft_sha256": digest, "action_sha256": request.action_digest,
            "preview_only": True, "delivery_authorized": False}
