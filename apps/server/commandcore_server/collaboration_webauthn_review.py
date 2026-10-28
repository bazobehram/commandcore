"""Verify a WebAuthn assertion for a single review, without approving delivery.

The reviewed action is re-read from the device. A successful credential check
only consumes the review challenge; it does NOT sign permits or mark approvals.
This remains staging-only until enrollment and browser ceremony are validated.
"""
from __future__ import annotations
from .collaboration_approval import AuthorizationDenied
from .collaboration_trusted_preview import preview_owned_request

async def verify_review_assertion(*, ledger, challenges, registry, agents, device,
                                  owner_subject, request_id, review_challenge,
                                  credential_id, authenticator_data,
                                  client_data_json, signature, expected_origin,
                                  expected_rp_id, now):
    fresh = await preview_owned_request(
        ledger=ledger, agents=agents, device=device,
        owner_subject=owner_subject, request_id=request_id, now=now)
    # A WebAuthn challenge is the unpredictable server-stored review token.
    # The verified signature covers this challenge, not a client-selected action.
    if not isinstance(review_challenge, str):
        raise AuthorizationDenied("review_challenge_invalid")
    try:
        challenge_bytes=review_challenge.encode("ascii")
    except UnicodeEncodeError:
        raise AuthorizationDenied("review_challenge_invalid") from None
    if len(challenge_bytes)<32 or len(challenge_bytes)>256:
        raise AuthorizationDenied("review_challenge_invalid")
    # Credential counter and review challenge are committed together.
    # Require a shared SQLite database; different files fail closed.
    counter=registry.verify_and_consume(
        challenges=challenges, owner=owner_subject, request_id=request_id,
        action_digest=fresh["action_sha256"], token=review_challenge, now=now,
        credential_id=credential_id, authenticator_data=authenticator_data,
        client_data_json=client_data_json, signature=signature,
        expected_challenge=challenge_bytes, expected_origin=expected_origin,
        expected_rp_id=expected_rp_id)
    return {"request_id": request_id, "credential_verified": True,
            "counter": counter, "delivery_authorized": False}
