"""Internal-only transport for a permit minted from trusted owner approval.

Not an MCP tool or HTTP route. The UI trust boundary must call this only
after independently verifying a human interaction and device permissions.
"""
from __future__ import annotations

from .collaboration_approval import AuthorizationDenied
from .collaboration_authorization import TrustedAuthorization


async def authorize_and_dispatch(
    *,
    authority: TrustedAuthorization,
    agents,
    device: dict,
    request_id: str,
    owner_subject: str,
    actor_attested: bool,
    now: int | None = None,
):
    # Do not dispatch anything before the credential-backed approval
    # implementation is enrolled and acceptance-tested.
    raise AuthorizationDenied("human_authenticator_not_configured")
