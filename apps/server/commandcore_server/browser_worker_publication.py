"""Explicit group-readable, operator-owned Browser publication boundary."""

from __future__ import annotations

import os
import stat
from pathlib import Path


def check_publication_file(
    path: Path, info: os.stat_result, uid: int, gid: int
) -> bool:
    """Only dedicated read-only consumer group may read a published file."""
    if uid <= 0 or gid <= 0 or gid not in (os.getegid(), *os.getgroups()):
        return False
    try:
        parent = path.parent.lstat()
        return (
            path.is_absolute()
            and path.resolve() == path
            and stat.S_ISDIR(parent.st_mode)
            and stat.S_IMODE(parent.st_mode) == 0o750
            and (parent.st_uid, parent.st_gid) == (uid, gid)
            and stat.S_ISREG(info.st_mode)
            and stat.S_IMODE(info.st_mode) == 0o640
            and (info.st_uid, info.st_gid) == (uid, gid)
            and info.st_nlink == 1
        )
    except OSError:
        return False
