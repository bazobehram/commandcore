"""Opt-in, JWT-verified API entrypoint for remote Browser operator allocation.

This NEVER grants API Docker or operator Ed25519 signing-key access. It only
issues a short-lived, authenticated user intent to the separately privileged
operator's peer-credential-checked Unix socket. A transport acknowledgement is
NOT physical worker readiness.
"""

from __future__ import annotations

import asyncio
import os
import stat
import time
from pathlib import Path

from .browser_gateway import BrowserError
from .browser_provision_intent import (
    BrowserProvisionIntentDenied,
    issue_provision_intent,
)
from .browser_provision_ipc import (
    BrowserProvisionTransportDenied,
    send_provision_intent,
)
from .browser_worker_dynamic import RefreshingOwnerBrowserWorkerPool
from .models import Principal

_PENDING_SECONDS = 600
_MAX_PENDING_OWNERS = 256
_MAX_SECRET_FILE = 4096


def read_api_provision_key(path: str) -> bytes:
    """Dedicated API-only provisioning MAC key, distinct from operator signer."""
    target = Path(path)
    if not target.is_absolute() or target.is_symlink():
        raise BrowserProvisionIntentDenied("provisioning credential path invalid")
    try:
        directory = target.parent.stat()
        if not stat.S_ISDIR(directory.st_mode) or directory.st_mode & 0o022:
            raise BrowserProvisionIntentDenied(
                "provisioning credential directory unsafe"
            )
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        fd = os.open(target, flags)
        try:
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_mode & 0o077
                or info.st_uid not in {0, os.geteuid()}
                or not 32 <= info.st_size <= _MAX_SECRET_FILE
            ):
                raise BrowserProvisionIntentDenied("provisioning credential unsafe")
            content = os.read(fd, _MAX_SECRET_FILE + 1)
            if len(content) != info.st_size:
                raise BrowserProvisionIntentDenied("provisioning credential changed")
            return content
        finally:
            os.close(fd)
    except OSError as exc:
        raise BrowserProvisionIntentDenied(
            "provisioning credential unavailable"
        ) from exc


def require_private_browser_journal() -> Path:
    """Fail before provisioning if persistent encrypted conversation storage is absent."""
    path = Path(
        os.environ.get("COMMANDCORE_BROWSER_JOURNAL_DIR", "/data/browser-sessions")
    )
    if not path.is_absolute() or path.is_symlink():
        raise BrowserProvisionIntentDenied(
            "private Browser conversation journal required"
        )
    try:
        info = path.stat()
    except OSError as exc:
        raise BrowserProvisionIntentDenied(
            "Browser conversation journal unavailable"
        ) from exc
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_mode & 0o077
        or info.st_uid != os.geteuid()
    ):
        raise BrowserProvisionIntentDenied(
            "Browser conversation journal permissions unsafe"
        )
    return path


class BrowserOAuthProvisioner:
    """Serial, no-auto-retry allocation; production requires operator quotas/jobs."""

    def __init__(
        self,
        *,
        worker_pool: RefreshingOwnerBrowserWorkerPool,
        provision_secret_path: str,
        socket_path: str,
        operator_uid: int,
        operator_gid: int,
    ) -> None:
        if (
            not isinstance(worker_pool, RefreshingOwnerBrowserWorkerPool)
            or not provision_secret_path
            or not socket_path
            or operator_uid <= 0
            or operator_gid <= 0
        ):
            raise BrowserProvisionIntentDenied(
                "public Browser provisioning configuration incomplete"
            )
        self.worker_pool = worker_pool
        self.secret_path = provision_secret_path
        self.socket_path = socket_path
        self.operator_uid = operator_uid
        self.operator_gid = operator_gid
        self._lock = asyncio.Lock()
        self._pending: dict[tuple[str, str, str], float] = {}

    async def ensure_owner(self, principal: Principal) -> None:
        """Call only after actual OAuth JWT and browser.open scope authorization."""
        # Issue a valid/authorized intent before even checking owner existence.
        # Caller cannot supply issuer/subject/client ID in tool arguments.
        require_private_browser_journal()
        signing_key = read_api_provision_key(self.secret_path)
        intent = issue_provision_intent(principal, signing_key)
        owner = (principal.issuer, principal.subject, principal.client_id)
        async with self._lock:
            try:
                self.worker_pool.refresh()
                if self.worker_pool.has_owner_binding(owner):
                    self._pending.pop(owner, None)
                    return
            except BrowserError as exc:
                raise BrowserProvisionTransportDenied(
                    "owner manifest unavailable"
                ) from exc
            now = time.monotonic()
            self._pending = {k: v for k, v in self._pending.items() if v > now}
            if owner not in self._pending and len(self._pending) >= _MAX_PENDING_OWNERS:
                raise BrowserProvisionTransportDenied(
                    "provisioning admission capacity reached"
                )
            if self._pending.get(owner, 0) > now:
                raise BrowserProvisionTransportDenied(
                    "provisioning request already pending or uncertain"
                )
            # Before sending any request, reserve the owner for a local cooldown.
            # Timeout is ambiguous; DO NOT automatically replay or allocate again.
            self._pending[owner] = now + _PENDING_SECONDS
            try:
                await asyncio.to_thread(
                    send_provision_intent,
                    intent,
                    self.socket_path,
                    operator_uid=self.operator_uid,
                    operator_gid=self.operator_gid,
                )
            except (BrowserProvisionTransportDenied, OSError):
                # Keep pending: operator may have created a worker before IPC broke.
                raise BrowserProvisionTransportDenied(
                    "operator allocation outcome unavailable"
                ) from None
            # An ACK is not readiness. BrowserGateway will still verify owner,
            # physical attestation and the actual per-tenant relay before action.
            try:
                self.worker_pool.refresh()
            except BrowserError as exc:
                raise BrowserProvisionTransportDenied(
                    "worker manifest not yet available"
                ) from exc
