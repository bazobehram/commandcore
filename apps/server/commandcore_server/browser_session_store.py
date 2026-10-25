"""Encrypted, owner-bound Browser recovery journal.

Persist only browser session routing metadata, not screenshots, DOM, typed data,
cookies or observations. A recovered private handoff stays paused; only the
same authenticated owner may explicitly resume it while the token is valid.
"""

from __future__ import annotations
import base64
import hashlib
import json
import os
import re
import stat
import time
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from .browser_worker_binding import BrowserWorkerBinding, WorkerOwnershipError

_BOOT = Path("/proc/sys/kernel/random/boot_id")


class SessionStoreError(RuntimeError):
    pass


class BrowserSessionStore:
    def __init__(self, binding: BrowserWorkerBinding):
        self.binding = binding
        # Immutable owner binding stays on the read-only /browser-owner volume.
        # Recovery metadata belongs on the separate persistent writable /data volume.
        journal_root = Path(
            os.environ.get("COMMANDCORE_BROWSER_JOURNAL_DIR", "/data/browser-sessions")
        )
        if not journal_root.is_absolute():
            raise SessionStoreError("browser session journal path must be absolute")
        journal_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.path = journal_root / (binding.worker_id + ".session.enc")
        # Domain-separated key. The worker binding secret never appears on disk.
        key = hashlib.sha256(
            b"commandcore-browser-session-journal-v1\0" + binding._key
        ).digest()
        self.cipher = Fernet(base64.urlsafe_b64encode(key))
        mode = journal_root.stat().st_mode
        if mode & 0o077:
            raise SessionStoreError("session journal directory must be private")

    @staticmethod
    def boot_id() -> str:
        try:
            return _BOOT.read_text().strip()
        except OSError:
            return ""

    def save(self, owner: tuple[str, str, str], entry) -> None:
        if len(owner) != 3 or not all(
            isinstance(x, str) and 0 < len(x) <= 2048 for x in owner
        ):
            raise SessionStoreError("invalid owner for browser journal")
        try:
            self.binding.claim(owner)
        except WorkerOwnershipError as exc:
            raise SessionStoreError("session owner not bound to worker") from exc
        state = {
            "v": 1,
            "worker": self.binding.worker_id,
            "owner": list(owner),
            "id": entry.id,
            "target_id": entry.target_id,
            "paused": entry.paused_for_human,
            "reason": entry.handoff_reason,
            "token": entry.handoff_token,
            "until_mono": entry.handoff_until,
            "boot": self.boot_id(),
        }
        raw = json.dumps(state, separators=(",", ":"), ensure_ascii=False).encode()
        data = self.cipher.encrypt(raw)
        name = self.path.with_name(self.path.name + "." + os.urandom(6).hex() + ".tmp")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(name, flags, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(name, self.path)
            dirfd = os.open(
                self.path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            )
            try:
                os.fsync(dirfd)
            finally:
                os.close(dirfd)
        except (OSError, ValueError) as exc:
            raise SessionStoreError("browser journal unavailable") from exc
        finally:
            name.unlink(missing_ok=True)

    def load(self):
        try:
            st = self.path.lstat()
        except FileNotFoundError:
            return None
        if not stat.S_ISREG(st.st_mode) or st.st_mode & 0o077:
            raise SessionStoreError("unsafe browser journal file")
        try:
            raw = self.cipher.decrypt(self.path.read_bytes())
            data = json.loads(raw)
            if (
                type(data) is not dict
                or data.get("v") != 1
                or data.get("worker") != self.binding.worker_id
            ):
                raise ValueError("wrong journal version or worker")
            owner = data.get("owner")
            if (
                not isinstance(owner, list)
                or len(owner) != 3
                or not all(isinstance(x, str) and 0 < len(x) <= 2048 for x in owner)
            ):
                raise ValueError("invalid owner")
            owner = tuple(owner)
            self.binding.claim(owner)
            sid = data.get("id")
            if not isinstance(sid, str) or not re.fullmatch(r"[0-9a-f-]{36}", sid):
                raise ValueError("invalid session identifier")
            target = data.get("target_id")
            if target is not None and (
                not isinstance(target, str) or len(target) > 256
            ):
                raise ValueError("invalid target")
            paused = data.get("paused")
            if type(paused) is not bool:
                raise ValueError("invalid pause state")
            token = data.get("token")
            until = data.get("until_mono")
            reason = data.get("reason")
            if reason not in {
                "sign_in",
                "verification",
                "approval",
                "login_or_approval",
            }:
                raise ValueError("invalid handoff reason")
            if token is not None and (
                not isinstance(token, str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{43}", token)
            ):
                raise ValueError("invalid handoff token")
            if type(until) not in (int, float) or until < 0:
                raise ValueError("invalid handoff deadline")
            if not paused:
                token = None
                until = 0.0
            # No persistent token survives a boot change or its time limit.
            if (
                not self.boot_id()
                or data.get("boot") != self.boot_id()
                or time.monotonic() >= until
            ):
                token = None
                until = 0.0
            return owner, {
                "id": sid,
                "target_id": target,
                "paused": paused,
                "reason": reason,
                "token": token,
                "until_mono": until,
            }
        except (
            InvalidToken,
            ValueError,
            TypeError,
            KeyError,
            UnicodeError,
            WorkerOwnershipError,
            OSError,
        ) as exc:
            raise SessionStoreError("browser journal verification failed") from exc

    def delete(self):
        try:
            self.path.unlink(missing_ok=True)
        except OSError as exc:
            raise SessionStoreError("could not remove browser journal") from exc
