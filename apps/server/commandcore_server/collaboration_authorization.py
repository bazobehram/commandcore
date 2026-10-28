"""Trusted-service boundary for collaboration approval and permit issuance.

Not registered as HTTP/MCP endpoint. The caller must independently verify
the owner's interactive approval before setting actor_attested=True.
"""
from __future__ import annotations

import time
from dataclasses import dataclass

from .collaboration_approval import ApprovalLedger, AuthorizationDenied
from .collaboration_permit_issuer import Issuer


@dataclass(frozen=True)
class TrustedAuthorization:
    ledger: ApprovalLedger
    issuer: Issuer

    def authorize_and_issue(
        self, *, request_id: str, owner_subject: str,
        actor_attested: bool, now: int | None = None,
    ) -> dict:
        # NO signed permit until an enrolled, independently verified human
        # authenticator is wired into this boundary. A caller boolean cannot
        # establish authorization, even if supplied by an internal service.
        raise AuthorizationDenied("human_authenticator_not_configured")
