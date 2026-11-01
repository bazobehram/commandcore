"""Optional single-owner restriction for private CommandCore instances.

Disabled by default, so public/self-hosted multi-user deployments are unchanged.
An exact OAuth subject ID is an identifier, not a secret or login credential.
"""

from __future__ import annotations

import hmac


def owner_allowed(configured_subject: str, verified_subject: str) -> bool:
    """Return whether a *verified* OAuth/panel principal may use this private host."""
    if not configured_subject:
        return True
    return bool(verified_subject) and hmac.compare_digest(
        configured_subject.encode("utf-8"), verified_subject.encode("utf-8")
    )
