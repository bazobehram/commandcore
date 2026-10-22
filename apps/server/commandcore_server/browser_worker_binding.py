"""Durable, fail-closed browser-worker owner pin across API restarts.

This is *not* a substitute for per-owner containers or browser-profile isolation.
The operator provisions a binding file before starting a fresh worker. A web
request can claim that pre-provisioned worker only once; it can never reassign
it to another principal, even after an ordinary session release or API restart.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import sqlite3
import stat
from contextlib import closing
from pathlib import Path
from typing import TypeAlias

Owner: TypeAlias = tuple[str, str, str]


class WorkerOwnershipError(Exception):
    """No worker assignment, unsafe storage, or a different owner."""


class BrowserWorkerBinding:
    def __init__(
        self,
        path: str,
        worker_id: str,
        secret: str,
        *,
        require_claimed: bool = False,
    ):
        if not worker_id or not re.fullmatch(r"[a-zA-Z0-9_-]{8,100}", worker_id):
            raise ValueError(
                "worker ID must be a stable opaque 8-100 character identifier"
            )
        if len(secret) < 32:
            raise ValueError(
                "browser worker binding secret must contain at least 32 characters"
            )
        self.path = Path(path)
        if not self.path.is_absolute():
            raise ValueError("browser worker binding path must be absolute")
        self.worker_id = worker_id
        self._require_claimed = require_claimed
        self._key = secret.encode("utf-8")
        self._storage_identity: tuple[int, int] | None = None
        self._verify_storage()
        # Retain the original inode while this binding is live. Otherwise an
        # unlink/recreate can reuse its inode number and evade replacement
        # detection on some filesystems. The file object closes with the owner.
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        try:
            fd = os.open(self.path, flags)
            self._storage_file = os.fdopen(fd, "rb")
            opened = os.fstat(self._storage_file.fileno())
            if (opened.st_dev, opened.st_ino) != self._storage_identity:
                self._storage_file.close()
                raise WorkerOwnershipError("browser worker binding storage replaced")
        except OSError as exc:
            raise WorkerOwnershipError(
                "browser worker binding storage unavailable"
            ) from exc
        with closing(self._connection()) as db:
            row = db.execute(
                "SELECT worker_id,owner_mac FROM worker_binding WHERE singleton=1"
            ).fetchone()
        if row is None or row[0] != worker_id:
            raise WorkerOwnershipError(
                "browser worker binding has a different worker ID"
            )
        if require_claimed and not row[1]:
            raise WorkerOwnershipError(
                "OAuth browser worker requires explicit operator owner preassignment"
            )

    def close(self) -> None:
        stream = getattr(self, "_storage_file", None)
        if stream is not None:
            stream.close()

    def __del__(self):
        self.close()

    @classmethod
    def provision(cls, path: str, worker_id: str, secret: str) -> BrowserWorkerBinding:
        """Operator-only one-time provisioning. Refuses to overwrite prior owner."""
        p = Path(path)
        if not p.is_absolute() or not p.parent.is_dir() or p.is_symlink():
            raise WorkerOwnershipError("unsafe browser worker binding path")
        mode = p.parent.stat().st_mode
        if mode & 0o022:
            raise WorkerOwnershipError(
                "browser worker directory must not be writable by others"
            )
        # O_EXCL protects against replacing or resetting an existing owner's file.
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(str(p), flags, 0o600)
        os.close(fd)
        try:
            with closing(sqlite3.connect(str(p))) as db, db:
                db.execute(
                    "CREATE TABLE worker_binding (singleton INTEGER PRIMARY KEY"
                    " CHECK(singleton=1), worker_id TEXT NOT NULL,"
                    " owner_mac TEXT, claimed_at TEXT)"
                )
                db.execute(
                    "INSERT INTO worker_binding (singleton, worker_id) VALUES (1, ?)",
                    (worker_id,),
                )
            return cls(str(p), worker_id, secret)
        except BaseException:
            # Provisioning has not assigned an owner yet; delete only our own
            # newly created file, not an existing owner's binding.
            p.unlink(missing_ok=True)
            raise

    def _verify_storage(self) -> None:
        try:
            parent = self.path.parent.stat()
            file = self.path.lstat()
        except (OSError, ValueError) as exc:
            raise WorkerOwnershipError(
                "browser worker binding storage missing"
            ) from exc
        if not stat.S_ISDIR(parent.st_mode) or parent.st_mode & 0o022:
            raise WorkerOwnershipError("browser worker binding directory is unsafe")
        if not stat.S_ISREG(file.st_mode) or file.st_mode & 0o077:
            raise WorkerOwnershipError("browser worker binding file is unsafe")
        identity = (file.st_dev, file.st_ino)
        if self._storage_identity is None:
            self._storage_identity = identity
        elif self._storage_identity != identity:
            raise WorkerOwnershipError("browser worker binding storage replaced")

    def _connection(self) -> sqlite3.Connection:
        self._verify_storage()
        # URI mode=rw prevents silent creation if the binding file is removed.
        from urllib.parse import quote

        mode = "ro" if self._require_claimed else "rw"
        uri = "file:" + quote(str(self.path), safe="/") + "?mode=" + mode
        return sqlite3.connect(uri, uri=True, timeout=5, isolation_level=None)

    def _mac(self, owner: Owner) -> str:
        if (
            len(owner) != 3
            or not all(isinstance(x, str) and x.strip() for x in owner)
            or owner[2] in {"unknown", "oauth-client"}
        ):
            raise WorkerOwnershipError("verified OAuth identity required")
        return hmac.new(
            self._key,
            json.dumps(owner, ensure_ascii=False, separators=(",", ":")).encode(
                "utf-8"
            ),
            hashlib.sha256,
        ).hexdigest()

    def matches(self, owner: Owner) -> bool:
        """Read-only owner lookup for a pre-provisioned worker pool."""
        fingerprint = self._mac(owner)
        try:
            with closing(self._connection()) as db:
                row = db.execute(
                    "SELECT worker_id,owner_mac FROM worker_binding WHERE singleton=1"
                ).fetchone()
        except (sqlite3.Error, OSError) as exc:
            raise WorkerOwnershipError(
                "browser owner binding storage unavailable"
            ) from exc
        if row is None or row[0] != self.worker_id or not row[1]:
            raise WorkerOwnershipError("browser worker binding not initialized")
        return hmac.compare_digest(row[1], fingerprint)

    def claim(self, owner: Owner) -> None:
        """Atomically bind a fresh worker, or verify its immutable owner."""
        if self._require_claimed:
            # A production API verifies operator-preassigned ownership. It must
            # work with a read-only mount and never acquire a SQLite write lock.
            if not self.matches(owner):
                raise WorkerOwnershipError(
                    "worker permanently belongs to another OAuth user"
                )
            return
        fingerprint = self._mac(owner)
        try:
            db = self._connection()
            try:
                db.execute("BEGIN IMMEDIATE")
                row = db.execute(
                    "SELECT worker_id,owner_mac FROM worker_binding WHERE singleton=1"
                ).fetchone()
                if row is None or row[0] != self.worker_id:
                    raise WorkerOwnershipError("worker identity mismatch")
                if row[1] is None:
                    db.execute(
                        "UPDATE worker_binding SET owner_mac=?, claimed_at=datetime('now')"
                        " WHERE singleton=1 AND owner_mac IS NULL",
                        (fingerprint,),
                    )
                elif not hmac.compare_digest(row[1], fingerprint):
                    raise WorkerOwnershipError(
                        "worker permanently belongs to another OAuth user"
                    )
                db.execute("COMMIT")
            except BaseException:
                db.execute("ROLLBACK")
                raise
            finally:
                db.close()
        except (sqlite3.Error, OSError) as exc:
            raise WorkerOwnershipError(
                "browser owner binding storage unavailable"
            ) from exc
