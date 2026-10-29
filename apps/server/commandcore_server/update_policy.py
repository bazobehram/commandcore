"""Explicit, fail-closed manual Agent update eligibility for the public beta.

A version notification is not permission to dispatch a remote update.
The Agent independently verifies a trusted signed release before activation.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

_VERSION = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-rc(0|[1-9][0-9]*))?$"
)


def release_key(raw: str | None) -> tuple[int, ...] | None:
    match = _VERSION.fullmatch(str(raw or ""))
    if not match:
        return None
    major, minor, patch = (int(x) for x in match.group(1, 2, 3))
    rc = match.group(4)
    return (major, minor, patch, 1 if rc is None else 0, int(rc or 0))


def trusted_manifest_url(url: str | None) -> bool:
    if not isinstance(url, str) or not url or len(url) > 2048:
        return False
    try:
        parsed = urlsplit(url)
    except ValueError:
        return False
    return (
        parsed.scheme == "https"
        and bool(parsed.hostname)
        and not parsed.username
        and not parsed.password
        and not parsed.fragment
        and not any(ord(char) < 33 for char in url)
    )


def manual_update_info(
    device: dict,
    *,
    target_version: str,
    manifest_url: str,
    connected: bool,
    operator_full: bool,
) -> dict:
    current_version = str(device.get("agent_version") or "")
    current, target = release_key(current_version), release_key(target_version)
    if not current or not target:
        state = "unknown"
    elif current == target:
        state = "up_to_date"
    elif current > target:
        state = "ahead"
    else:
        state = "available"

    caps = device.get("capabilities") or {}
    blocks: list[str] = []
    if state != "available":
        blocks.append("no_newer_recommended_release")
    if not connected:
        blocks.append("device_offline")
    if not trusted_manifest_url(manifest_url):
        blocks.append("signed_release_feed_not_configured")
    if not operator_full:
        blocks.append("operator_full_scope_required")
    if device.get("permission_profile") != "FULL_CONTROL":
        blocks.append("server_full_control_required")
    if device.get("access_max_permission_profile") != "FULL_CONTROL":
        blocks.append("account_full_grant_required")
    if caps.get("local_max_permission_profile") != "FULL_CONTROL":
        blocks.append("local_full_control_required")
    if caps.get("agent_update") is not True:
        blocks.append("agent_update_not_supported")
    if caps.get("agent_update_trust_configured") is not True:
        blocks.append("signed_update_trust_not_configured")

    return {
        "state": state,
        "installed_version": current_version or None,
        "recommended_version": target_version or None,
        "available": state == "available",
        "can_start": not blocks,
        "blockers": blocks,
        "automatic_updates": False,
        "component": "agent",
    }
