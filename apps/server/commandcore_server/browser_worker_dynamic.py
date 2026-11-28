"""Fail-closed, read-only reconciliation of operator-owned public worker manifests.

This module never provisions Docker or reads an operator's private signing seed.
It only observes a protected routing manifest and pinned owner ledgers; each
worker action still requires an independent fresh physical attestation.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import threading
from pathlib import Path
from typing import Any

from .browser_gateway import BrowserError, BrowserGateway
from .browser_worker_binding import WorkerOwnershipError
from .browser_worker_pool import Owner, OwnerBrowserWorkerPool, ProofVerifier
from .browser_worker_publication import check_publication_file
from .browser_worker_uds_client import WorkerUnixClient

_MAX_MANIFEST_BYTES = 65536


class RefreshingOwnerBrowserWorkerPool(OwnerBrowserWorkerPool):
    """Add/retire workers without restarting the API; never adopt old sessions."""

    def __init__(
        self,
        manifest_path: str,
        binding_secret: str,
        allow_hosts: tuple[str, ...],
        public_base_url: str,
        *,
        attestation: ProofVerifier,
        relay_root: str = "",
        relay_operator_uid: int = -1,
        relay_operator_gid: int = -1,
        publication_identity: tuple[int, int] | None = None,
    ) -> None:
        if attestation is None or len(binding_secret) < 32:
            raise ValueError("dynamic public Browser requires proof and owner key")
        self.manifest_path = Path(manifest_path)
        self.binding_secret = binding_secret
        self.allow_hosts = allow_hosts
        self.public_base_url = public_base_url
        self.attestation = attestation
        if relay_root and (relay_operator_uid < 0 or relay_operator_gid < 0):
            raise ValueError(
                "public worker relay identity must be explicitly configured"
            )
        self.publication_identity = publication_identity
        self.relay_root = relay_root
        self.relay_operator_uid = relay_operator_uid
        self.relay_operator_gid = relay_operator_gid
        self.workers: tuple[BrowserGateway, ...] = ()
        self._worker_starts: dict[str, str] = {}
        self._manifest_digest: bytes | None = None
        self._refresh_lock = threading.RLock()
        self.refresh()

    def _read_manifest(self) -> tuple[bytes, int]:
        path = self.manifest_path
        if not path.is_absolute() or path.is_symlink():
            raise BrowserError("dynamic browser worker manifest path unsafe")
        try:
            parent = path.parent.stat()
            if not stat.S_ISDIR(parent.st_mode) or parent.st_mode & 0o022:
                raise BrowserError("dynamic browser worker manifest directory unsafe")
            flags = (
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
            )
            fd = os.open(path, flags)
            try:
                info = os.fstat(fd)
                if (
                    not stat.S_ISREG(info.st_mode)
                    or (
                        not check_publication_file(
                            path, info, *self.publication_identity
                        )
                        if self.publication_identity is not None
                        else bool(info.st_mode & 0o077)
                    )
                    or info.st_size > _MAX_MANIFEST_BYTES
                ):
                    raise BrowserError(
                        "dynamic browser worker manifest permissions unsafe"
                    )
                body = os.read(fd, _MAX_MANIFEST_BYTES + 1)
                after = os.fstat(fd)
                if (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) != (
                    after.st_dev,
                    after.st_ino,
                    after.st_size,
                    after.st_mtime_ns,
                ) or len(body) != info.st_size:
                    raise BrowserError(
                        "dynamic browser worker manifest changed while reading"
                    )
                return body, info.st_ino
            finally:
                os.close(fd)
        except OSError as exc:
            raise BrowserError("dynamic browser worker manifest unavailable") from exc

    def _discard(self) -> None:
        for gateway in self.workers:
            gateway.sessions.clear()
            if gateway.worker_binding is not None:
                gateway.worker_binding.close()
        self.workers = ()
        self._worker_starts.clear()
        self._manifest_digest = None

    @staticmethod
    def _same_route(a: BrowserGateway, b: BrowserGateway) -> bool:
        left, right = a.worker_binding, b.worker_binding
        assert left is not None and right is not None
        return (
            left.worker_id == right.worker_id
            and left.path == right.path
            and left._storage_identity == right._storage_identity
            and a.base_url == b.base_url
            and a.cdp_url == b.cdp_url
            and a.egress_proxy_url == b.egress_proxy_url
            and a.egress_policy_url == b.egress_policy_url
            and a.allow_hosts == b.allow_hosts
            and a.public_base_url == b.public_base_url
            and (
                (
                    str(a.control_relay.root),
                    a.control_relay.worker_id,
                    a.control_relay.operator_uid,
                    a.control_relay.operator_gid,
                )
                if a.control_relay
                else None
            )
            == (
                (
                    str(b.control_relay.root),
                    b.control_relay.worker_id,
                    b.control_relay.operator_uid,
                    b.control_relay.operator_gid,
                )
                if b.control_relay
                else None
            )
        )

    def refresh(self) -> None:
        """Read operator snapshot and atomically reconcile, otherwise deny all."""
        with self._refresh_lock:
            try:
                body, inode = self._read_manifest()
                digest = hashlib.sha256(body).digest()
                if digest == self._manifest_digest:
                    return
                manifest = json.loads(body)
                if (
                    not isinstance(manifest, dict)
                    or set(manifest) != {"workers"}
                    or not isinstance(manifest["workers"], list)
                    or len(manifest["workers"]) > 16
                ):
                    raise BrowserError("invalid dynamic browser worker manifest")
                if manifest["workers"]:
                    candidate = OwnerBrowserWorkerPool.from_manifest(
                        str(self.manifest_path),
                        self.binding_secret,
                        self.allow_hosts,
                        self.public_base_url,
                        self.attestation,
                        publication_identity=self.publication_identity,
                    )
                    incoming = tuple(candidate.workers)
                    if self.relay_root:
                        for gateway in incoming:
                            binding = gateway.worker_binding
                            assert binding is not None
                            gateway.control_relay = WorkerUnixClient(
                                self.relay_root,
                                binding.worker_id,
                                operator_uid=self.relay_operator_uid,
                                operator_gid=self.relay_operator_gid,
                            )
                else:
                    incoming = ()
                # Check against in-place edits or atomic rename between reads.
                final_body, final_inode = self._read_manifest()
                if final_inode != inode or final_body != body:
                    for worker in incoming:
                        if worker.worker_binding is not None:
                            worker.worker_binding.close()
                    raise BrowserError(
                        "dynamic worker manifest changed during reconciliation"
                    )
                old = {
                    w.worker_binding.worker_id: w
                    for w in self.workers
                    if w.worker_binding
                }
                keep = []
                for fresh in incoming:
                    binding = fresh.worker_binding
                    assert binding is not None
                    previous = old.get(binding.worker_id)
                    if previous is not None and self._same_route(previous, fresh):
                        # The same immutable owner ledger and route: keep in-memory
                        # session ownership only for this exact process incarnation.
                        binding.close()
                        keep.append(previous)
                    else:
                        keep.append(fresh)
                kept_ids = {id(worker) for worker in keep}
                for previous in self.workers:
                    if id(previous) not in kept_ids:
                        previous.sessions.clear()
                        if previous.worker_binding is not None:
                            previous.worker_binding.close()
                self.workers = tuple(keep)
                valid_ids = {
                    w.worker_binding.worker_id for w in self.workers if w.worker_binding
                }
                self._worker_starts = {
                    k: v for k, v in self._worker_starts.items() if k in valid_ids
                }
                self._manifest_digest = digest
            except (
                OSError,
                ValueError,
                TypeError,
                KeyError,
                BrowserError,
                WorkerOwnershipError,
            ) as exc:
                self._discard()
                raise BrowserError(
                    "dynamic browser worker manifest unavailable or invalid"
                ) from exc

    def has_owner_binding(self, owner: Owner) -> bool:
        """Owner ledger lookup only; a proof outage is NOT a missing assignment."""
        self.refresh()
        found = False
        for worker in self.workers:
            binding = worker.worker_binding
            if binding is None:
                raise BrowserError("unbound worker route")
            try:
                if binding.matches(owner):
                    if found:
                        raise BrowserError("ambiguous owner assignment")
                    found = True
            except WorkerOwnershipError as exc:
                raise BrowserError("owner binding ledger unavailable") from exc
        return found

    def _find_worker(self, owner: Owner) -> BrowserGateway:
        self.refresh()
        return super()._find_worker(owner)

    def viewer_sessions(self, subject: str, issuer: str) -> list[dict[str, str]]:
        self.refresh()
        return super().viewer_sessions(subject, issuer)

    def handoff_owner(self, token: str, subject: str, issuer: str = "") -> Owner:
        self.refresh()
        return super().handoff_owner(token, subject, issuer)

    def _after_action(self, worker: BrowserGateway, owner: Owner) -> None:
        self.refresh()
        try:
            current = self._find_worker(owner)
        except BrowserError as exc:
            worker.sessions.clear()
            raise BrowserError(
                "browser worker changed during action; result withheld"
            ) from exc
        if current is not worker:
            worker.sessions.clear()
            raise BrowserError("browser worker changed during action; result withheld")

    async def call(
        self,
        *,
        subject: str,
        issuer: str,
        client_id: str,
        name: str,
        args: dict[str, Any],
        human: bool = False,
        human_token: str | None = None,
    ) -> dict[str, Any]:
        owner = (issuer, subject, client_id)
        worker = self._find_worker(owner)
        result = await super().call(
            subject=subject,
            issuer=issuer,
            client_id=client_id,
            name=name,
            args=args,
            human=human,
            human_token=human_token,
        )
        self._after_action(worker, owner)
        return result

    async def viewer_frame(
        self, subject: str, issuer: str, client_id: str, args: dict[str, Any]
    ) -> dict[str, Any]:
        owner = (issuer, subject, client_id)
        worker = self._find_worker(owner)
        result = await super().viewer_frame(subject, issuer, client_id, args)
        self._after_action(worker, owner)
        return result

    async def human_call(
        self,
        token: str,
        subject: str,
        name: str,
        args: dict[str, Any],
        issuer: str = "",
    ) -> dict[str, Any]:
        owner = self.handoff_owner(token, subject, issuer)
        worker = self._find_worker(owner)
        result = await super().human_call(token, subject, name, args, issuer=issuer)
        self._after_action(worker, owner)
        return result

    async def private_stream_frame(
        self, token: str, subject: str, issuer: str = ""
    ) -> dict[str, Any]:
        owner = self.handoff_owner(token, subject, issuer)
        worker = self._find_worker(owner)
        result = await super().private_stream_frame(token, subject, issuer)
        self._after_action(worker, owner)
        return result

    async def human_resume(
        self,
        token: str,
        subject: str,
        issuer: str = "",
        *,
        allow_ai_interaction: bool = False,
    ) -> dict[str, Any]:
        owner = self.handoff_owner(token, subject, issuer)
        worker = self._find_worker(owner)
        result = await super().human_resume(
            token, subject, issuer, allow_ai_interaction=allow_ai_interaction
        )
        self._after_action(worker, owner)
        return result
