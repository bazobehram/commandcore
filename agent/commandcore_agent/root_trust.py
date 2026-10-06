"""Root helper configuration must not be replaceable by the network Agent."""

from __future__ import annotations

import os
import stat
from pathlib import Path


def check_root_directory(path: str | Path) -> None:
    target = Path(path).absolute()
    for parent in (target, *target.parents):
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0:
            raise PermissionError(
                "helper configuration requires root-owned directories"
            )
        if info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX:
            raise PermissionError(
                "helper configuration directory is writable by another user"
            )


def read_root_file(path: str | Path, *, secret: bool = False) -> bytes:
    target = Path(path).absolute()
    check_root_directory(target.parent)
    descriptor = os.open(target, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise PermissionError(
                "helper configuration requires a root-owned protected file"
            )
        if secret and info.st_mode & 0o007:
            raise PermissionError("helper secret must not be accessible to other users")
        if info.st_size > 1048576:
            raise ValueError("helper configuration is too large")
        return os.read(descriptor, 1048577)
    finally:
        os.close(descriptor)
