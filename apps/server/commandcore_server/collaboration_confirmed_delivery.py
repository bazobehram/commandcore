"""Fail-closed collaboration confirmation gate.

Positive authorization is deliberately unavailable until a trusted credential
enrollment and user-verification service exists. No HTTP or MCP caller may set
a boolean to enable delivery. Do not restore the previous unreachable code.
"""
from __future__ import annotations
from .collaboration_approval import AuthorizationDenied

async def confirm_review_and_dispatch(
    *, authority, challenges, agents, device, request_id: str,
    owner_subject: str, challenge: str, human_attested: bool,
    now: int | None = None,
):
    raise AuthorizationDenied("human_authenticator_not_configured")
