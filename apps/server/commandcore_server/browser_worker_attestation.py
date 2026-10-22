"""Short-lived, HMAC-authenticated operator proof for Browser worker identity.

The separate operator process alone can access Docker. CommandCore only reads
a private signed snapshot, and denies browser operations when proof is stale,
missing, invalid, or does not include the exact preassigned worker identity.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import stat
import tempfile
import time
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .browser_worker_orchestrator import PhysicalWorker

ATTESTATION_VERSION = 1
MAX_ATTESTATION_AGE_SECONDS = 12
CLOCK_SKEW_SECONDS = 2
BINDING_FIELDS = (
    "worker_id",
    "generation",
    "steel_name",
    "boundary_name",
    "steel_container_id",
    "boundary_container_id",
    "isolated_network",
    "control_network",
    "outbound_network",
    "isolated_network_id",
    "control_network_id",
    "outbound_network_id",
    "steel_image_id",
    "boundary_image_id",
)
RUNTIME_FIELD = "steel_started_at"


class BrowserAttestationError(Exception):
    """Physical browser process identity could not be confirmed."""


def _canonical(data: dict[str, Any]) -> bytes:
    return json.dumps(
        data, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _require_private_path(path: Path, *, existing: bool = True) -> None:
    if not path.is_absolute():
        raise BrowserAttestationError("attestation path must be absolute")
    try:
        parent = path.parent.stat()
        if not stat.S_ISDIR(parent.st_mode) or parent.st_mode & 0o022:
            raise BrowserAttestationError("attestation directory is insecure")
        if existing:
            item = path.lstat()
            # Public-to-API proof may be 0640 for a dedicated proof-only
            # group. Never permit group write/execute or ANY other access.
            # Unix DAC still requires the API service to be in that group.
            if not stat.S_ISREG(item.st_mode) or item.st_mode & 0o037:
                raise BrowserAttestationError("attestation file is insecure")
            if item.st_mode & 0o040 and item.st_gid not in (
                os.getegid(),
                *os.getgroups(),
            ):
                raise BrowserAttestationError("attestation proof group untrusted")
    except OSError as exc:
        raise BrowserAttestationError("attestation file unavailable") from exc


def _worker_record(worker: PhysicalWorker) -> dict[str, str]:
    return {key: getattr(worker, key) for key in BINDING_FIELDS}


def write_operator_attestation(
    path: str,
    secret: str,
    verified_workers: Iterable[PhysicalWorker],
    *,
    now: int | None = None,
    started_at_by_worker: dict[str, str] | None = None,
    proof_gid: int | None = None,
) -> None:
    """Operator only: publish validated workers after Docker inspect.

    Caller must verify each worker first. Never call this in API/MCP code.
    """
    if len(secret) < 32:
        raise BrowserAttestationError("attestation signing key missing")
    destination = Path(path)
    _require_private_path(destination, existing=False)
    workers = sorted(
        (
            {
                **_worker_record(worker),
                RUNTIME_FIELD: (started_at_by_worker or {}).get(worker.worker_id, ""),
            }
            for worker in verified_workers
        ),
        key=lambda row: row["worker_id"],
    )
    if len({row["worker_id"] for row in workers}) != len(workers):
        raise BrowserAttestationError("duplicate attested worker")
    payload = {
        "version": ATTESTATION_VERSION,
        "issued_at": int(time.time()) if now is None else now,
        "workers": workers,
    }
    envelope = {
        **payload,
        "hmac_sha256": hmac.new(
            secret.encode(), _canonical(payload), hashlib.sha256
        ).hexdigest(),
    }
    tmp = None
    try:
        fd, tmp = tempfile.mkstemp(prefix=".ccbw-attest-", dir=destination.parent)
        try:
            if proof_gid is not None:
                if type(proof_gid) is not int or proof_gid < 0:
                    raise BrowserAttestationError("invalid shared proof group")
                os.fchown(fd, -1, proof_gid)
            os.fchmod(fd, 0o640 if proof_gid is not None else 0o600)
        except BaseException:
            # Repeated operator reconciliation must never leak an open fd on
            # bad group configuration, filesystem errors or failed chown.
            os.close(fd)
            raise
        with os.fdopen(fd, "wb") as writer:
            writer.write(_canonical(envelope))
            writer.flush()
            os.fsync(writer.fileno())
        os.replace(tmp, destination)
        tmp = None
        dirfd = os.open(str(destination.parent), os.O_DIRECTORY)
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
    finally:
        if tmp is not None:
            Path(tmp).unlink(missing_ok=True)


class WorkerAttestationVerifier:
    def __init__(
        self, path: str, secret: str, *, max_age: int = MAX_ATTESTATION_AGE_SECONDS
    ):
        if len(secret) < 32:
            raise ValueError("attestation key must contain at least 32 characters")
        if not 2 <= max_age <= 30:
            raise ValueError("attestation lifetime must be 2-30 seconds")
        self.path = Path(path)
        self.key = secret.encode()
        self.max_age = max_age

    def _read(self, *, now: int | None = None) -> list[dict[str, str]]:
        _require_private_path(self.path)
        try:
            # Small bounded metadata file; cannot turn into arbitrary file-read.
            with self.path.open("rb") as stream:
                raw = stream.read(1_000_001)
            if len(raw) > 1_000_000:
                raise BrowserAttestationError("oversized worker attestation")
            data = json.loads(raw)
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise BrowserAttestationError("invalid worker attestation") from exc
        if not isinstance(data, dict) or set(data) != {
            "version",
            "issued_at",
            "workers",
            "hmac_sha256",
        }:
            raise BrowserAttestationError("malformed worker attestation")
        mac = data.pop("hmac_sha256")
        if not isinstance(mac, str) or not hmac.compare_digest(
            hmac.new(self.key, _canonical(data), hashlib.sha256).hexdigest(),
            mac,
        ):
            raise BrowserAttestationError("worker attestation signature invalid")
        issued = data["issued_at"]
        timestamp = int(time.time()) if now is None else now
        if (
            data["version"] != ATTESTATION_VERSION
            or type(issued) is not int
            or not -CLOCK_SKEW_SECONDS <= timestamp - issued <= self.max_age
        ):
            raise BrowserAttestationError("worker attestation expired")
        workers = data["workers"]
        if (
            not isinstance(workers, list)
            or len(workers) > 16
            or any(
                not isinstance(row, dict)
                or set(row) != set(BINDING_FIELDS) | {RUNTIME_FIELD}
                or any(not isinstance(value, str) for value in row.values())
                for row in workers
            )
        ):
            raise BrowserAttestationError("invalid worker attestation records")
        if len({row["worker_id"] for row in workers}) != len(workers):
            raise BrowserAttestationError("duplicate attested worker")
        return workers

    def verify(self, worker_id: str, *, now: int | None = None) -> dict[str, str]:
        for record in self._read(now=now):
            if record["worker_id"] == worker_id:
                return record
        raise BrowserAttestationError(
            "physical browser worker is not currently verified"
        )
