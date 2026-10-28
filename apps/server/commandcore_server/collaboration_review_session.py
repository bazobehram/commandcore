"""Trusted review-session adapter: validates a fresh preview before minting a token.

Tokens are *not* approval. The caller must independently authenticate and attest
an explicit user decision before consuming them and requesting delivery.
"""
from __future__ import annotations
from .collaboration_trusted_preview import preview_owned_request

async def prepare_review_challenge(*, ledger, challenges, agents, device,
                                   owner_subject, request_id, now):
    preview = await preview_owned_request(
        ledger=ledger, agents=agents, device=device,
        owner_subject=owner_subject, request_id=request_id, now=now)
    request = ledger.get(owner_subject=owner_subject, request_id=request_id)
    if request is None or request.status != "pending" or request.expires_at <= now:
        from .collaboration_approval import AuthorizationDenied
        raise AuthorizationDenied("approval_not_pending_or_not_owned")
    token = challenges.issue(
        owner=owner_subject, request_id=request_id,
        action_digest=preview["action_sha256"], now=now,
        max_expires_at=request.expires_at)
    return {"challenge": token, "expires_at": min(now+90,request.expires_at),
            "request_id": request_id, "action_sha256": preview["action_sha256"],
            "delivery_authorized": False}
