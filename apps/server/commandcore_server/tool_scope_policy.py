"""Shared OAuth scope classification for MCP metadata and server execution.

Client tool annotations are UX hints, never security grants. Execution must
also enforce authenticated identity, current device grant and local ceilings.
"""

from __future__ import annotations

from collections.abc import Collection

from .auth import FULL_SCOPE, READ_SCOPE, STANDARD_SCOPE

_FULL_SCOPE_TOOLS = frozenset(
    {
        "services.manage",
        "package.install",
        "system.reboot",
        "system.shutdown",
        "docker.ps",
        "docker.inspect",
        "docker.logs",
        "docker.exec",
        "docker.run",
        "agent.update.stage",
        "agent.update.activate",
        "agent.update.rollback",
        "agents.deliver",
    }
)


def required_oauth_scope(name: str, read_only_hints: Collection[str]) -> str:
    """Match prior scope rules; unknown tools still fail at registry lookup."""
    if name in _FULL_SCOPE_TOOLS:
        return FULL_SCOPE
    if name in read_only_hints or name == "devices.select":
        return READ_SCOPE
    return STANDARD_SCOPE
