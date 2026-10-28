"""Offline permit issuance after an independently attested owner decision.

No MCP entrypoint, HTTP decision route, or implicit delivery is defined here.
A trusted UI must separately authenticate and approve the exact ledger request.
"""
from __future__ import annotations

import base64
import json
import secrets
import time
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .collaboration_approval import ApprovalLedger, AuthorizationDenied

DOMAIN = b"commandcore:collaboration:delivery:v1\n"


@dataclass(frozen=True)
class Issuer:
    issuer: str
    owner_subject: str
    private_key: Ed25519PrivateKey

    def issue(self, ledger: ApprovalLedger, *, request_id: str, now: int | None = None) -> dict:
        if now is None:
            now = int(time.time())
        # Load only from the owner's durable ledger; never trust MCP-provided action fields.
        request = ledger.get(owner_subject=self.owner_subject, request_id=request_id)
        if request is None or request.status != "approved" or request.decision_actor != self.owner_subject:
            raise AuthorizationDenied("attested_approval_required")
        if not self.issuer or not self.owner_subject:
            raise AuthorizationDenied("issuer_configuration_required")
        if now < request.created_at or now >= request.expires_at:
            raise AuthorizationDenied("approval_expired")
        if len(request.action_digest) != 64 or not all(c in "0123456789abcdef" for c in request.action_digest):
            raise AuthorizationDenied("invalid_action_digest")
        expires = min(now + 120, request.expires_at)
        if expires <= now:
            raise AuthorizationDenied("permit_expired")
        permit = {
            "version": 1,
            "issuer": self.issuer,
            "owner_subject": self.owner_subject,
            "device_id": request.device_id,
            "window_id": request.window_id,
            "process_id": request.process_id,
            "process_start": request.process_start,
            "draft_id": request.draft_id,
            "action_sha256": request.action_digest,
            "nonce": secrets.token_urlsafe(32),
            "issued_at": now,
            "expires_at": expires,
        }
        canonical = json.dumps(permit, separators=(",", ":"), ensure_ascii=False).encode()
        signature = base64.b64encode(self.private_key.sign(DOMAIN + canonical)).decode()
        # The ledger consume is transactional and one-use. Never release the signed
        # envelope unless consume succeeded; concurrent issuers cannot both return.
        ledger.consume(request_id=request_id, owner_subject=self.owner_subject,
                       action_digest_value=request.action_digest, now=now)
        return {"permit": permit, "signature_b64": signature}
