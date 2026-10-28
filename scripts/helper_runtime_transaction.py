"""Safe helper-only runtime staging; no root activation or network Agent changes.

Intended for a *trusted root-only staging directory* after signed verification.
The caller must perform service approval and activation separately.
"""

from __future__ import annotations

import os
from pathlib import Path


def validate_root(root: Path) -> None:
    if root.is_symlink() or not root.is_dir():
        raise ValueError("untrusted helper staging root")
    info = root.stat()
    if info.st_uid != 0 or info.st_mode & 0o022:
        raise PermissionError(
            "helper staging must be root-owned and non-writable by others"
        )


def stage_layout(root: Path, release_name: str) -> dict:
    """Read-only plan: refuse collisions and escapes before any root installation."""
    import re

    validate_root(root)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}", release_name):
        raise ValueError("invalid helper release identifier")
    release = root / "releases" / release_name
    current = root / "current"
    if (root / "releases").is_symlink() or release.exists() or release.is_symlink():
        raise FileExistsError("unsafe release destination or collision")
    if current.exists() and not current.is_symlink():
        raise ValueError("current helper pointer is not a symlink")
    if current.is_symlink():
        target = os.readlink(current)
        try:
            rollback_target({"previous": target})
        except ValueError as exc:
            raise ValueError(
                "current helper pointer escapes release directory"
            ) from exc
    return {
        "release": str(release),
        "current": str(current),
        "previous": os.readlink(current) if current.is_symlink() else None,
        "network_agent_mutation": False,
        "root_activation": False,
    }


def rollback_target(plan: dict) -> str | None:
    """Return only a prevalidated previous helper target, never an Agent path."""
    old = plan.get("previous")
    import re

    if old is not None and (
        not isinstance(old, str)
        or re.fullmatch(r"releases/[A-Za-z0-9][A-Za-z0-9._-]{0,79}", old) is None
        or old[9:] in (".", "..")
    ):
        raise ValueError("unsafe previous helper target")
    return old
