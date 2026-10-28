"""Validate a credential-bound, user-verified assertion before delivery.

This validates signatures and intent binding; the trusted authenticator must
independently enforce authenticator user verification and credential enrollment.
Not an HTTP/MCP endpoint and not an implementation of WebAuthn itself.
"""
from __future__ import annotations
import base64
import json
from dataclasses import dataclass
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from .collaboration_approval import AuthorizationDenied

@dataclass(frozen=True)
class HumanAssertion:
    owner: str
    request_id: str
    action_digest: str
    challenge: str
    expires_at: int
    credential_id: str
    user_verified: bool
    signature_b64: str

def assertion_bytes(a: HumanAssertion) -> bytes:
    return json.dumps({
        "owner":a.owner, "request_id":a.request_id,
        "action_digest":a.action_digest, "challenge":a.challenge,
        "expires_at":a.expires_at, "credential_id":a.credential_id,
        "user_verified":a.user_verified
    },sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()

def verify_human_assertion(*, assertion: HumanAssertion, public_key: Ed25519PublicKey,
                           expected_owner: str, expected_request: str,
                           expected_action: str, expected_challenge: str,
                           expected_credential: str, now: int) -> None:
    if not isinstance(assertion,HumanAssertion) or assertion.user_verified is not True:
        raise AuthorizationDenied("user_verification_required")
    # Bound all untrusted assertion fields before decoding or canonicalizing.
    if (not isinstance(assertion.signature_b64, str)
            or len(assertion.signature_b64) > 128
            or not isinstance(assertion.challenge, str)
            or len(assertion.challenge) > 256
            or not isinstance(assertion.expires_at, int)
            or isinstance(assertion.expires_at, bool)
            or not isinstance(now, int) or isinstance(now, bool)):
        raise AuthorizationDenied("human_assertion_invalid")
    if (assertion.owner!=expected_owner or assertion.request_id!=expected_request
            or assertion.action_digest!=expected_action
            or assertion.challenge!=expected_challenge
            or assertion.credential_id!=expected_credential
            or now>=assertion.expires_at or assertion.expires_at>now+90):
        raise AuthorizationDenied("human_assertion_binding_invalid")
    try:
        signature=base64.b64decode(assertion.signature_b64,validate=True)
        if len(signature) != 64:
            raise AuthorizationDenied("human_assertion_signature_invalid")
        public_key.verify(signature,assertion_bytes(assertion))
    except (ValueError,InvalidSignature):
        raise AuthorizationDenied("human_assertion_signature_invalid") from None
