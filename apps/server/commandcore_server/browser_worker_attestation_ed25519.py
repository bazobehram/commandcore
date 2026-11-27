"""Operator-only Ed25519 signing; public-key-only Browser attestation verifier.

No raw private key or HMAC signing secret is required in the internet-facing API.
Legacy HMAC support is retained for disposable test configurations only.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
import tempfile
import time
from collections.abc import Iterable
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .browser_worker_attestation import (
    ATTESTATION_VERSION,
    BINDING_FIELDS,
    CLOCK_SKEW_SECONDS,
    MAX_ATTESTATION_AGE_SECONDS,
    RUNTIME_FIELD,
    BrowserAttestationError,
    _canonical,
    _require_private_path,
    _worker_record,
)
from .browser_worker_orchestrator import PhysicalWorker

_ALGORITHM = "Ed25519"
_SIGNATURE_FIELD = "signature_ed25519"
_MAX_FILE_BYTES = 1_000_000

RELAY_ATTESTATION_VERSION = 2
RELAY_FIELDS = frozenset(
    {
        "relay_container_id",
        "relay_image_id",
        "relay_started_at",
        "relay_steel_dev",
        "relay_steel_ino",
        "relay_policy_dev",
        "relay_policy_ino",
    }
)


def _validate_relay_fields(row: dict[str, str]) -> None:
    if (
        not re.fullmatch(r"[0-9a-f]{64}", row["relay_container_id"])
        or row["relay_container_id"]
        in (row["steel_container_id"], row["boundary_container_id"])
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", row["relay_image_id"])
        or not re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z",
            row["relay_started_at"],
        )
        or row["relay_started_at"].startswith("0001-")
        or any(
            not re.fullmatch(r"[0-9]{1,20}", row[field])
            for field in RELAY_FIELDS
            if field.endswith(("_dev", "_ino"))
        )
        or any(
            int(row[field]) == 0 for field in ("relay_steel_ino", "relay_policy_ino")
        )
        or (row["relay_steel_dev"], row["relay_steel_ino"])
        == (row["relay_policy_dev"], row["relay_policy_ino"])
    ):
        raise BrowserAttestationError("invalid signed relay identity")


def _decode_key(raw: str) -> bytes:
    if not isinstance(raw, str):
        raise BrowserAttestationError("invalid attestation key encoding")
    try:
        key = base64.b64decode(raw, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise BrowserAttestationError("invalid attestation key encoding") from exc
    if len(key) != 32:
        raise BrowserAttestationError("attestation key must contain 32 raw bytes")
    return key


def public_key_for_private_seed(private_seed_base64: str) -> str:
    """Operator-only: export the verification key for a public-config variable."""
    key = Ed25519PrivateKey.from_private_bytes(_decode_key(private_seed_base64))
    raw = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return base64.b64encode(raw).decode("ascii")


def write_operator_ed25519_attestation(
    path: str,
    private_seed_base64: str,
    verified_workers: Iterable[PhysicalWorker],
    *,
    now: int | None = None,
    started_at_by_worker: dict[str, str] | None = None,
    proof_gid: int | None = None,
    verified_relays: dict[str, dict[str, str]] | None = None,
) -> None:
    """Operator only: publish short-lived signed physical worker status.

    Version 2 requires fresh evidence from verify_physical_relay for every
    worker. Never accept relay evidence supplied by the API or a user.
    """
    secret = Ed25519PrivateKey.from_private_bytes(_decode_key(private_seed_base64))
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
        key=lambda x: x["worker_id"],
    )
    if len(workers) > 16 or len({x["worker_id"] for x in workers}) != len(workers):
        raise BrowserAttestationError("invalid attested worker count")
    version = ATTESTATION_VERSION
    if verified_relays is not None:
        version = RELAY_ATTESTATION_VERSION
        if set(verified_relays) != {row["worker_id"] for row in workers}:
            raise BrowserAttestationError("relay evidence must cover every worker")
        for row in workers:
            proof = verified_relays[row["worker_id"]]
            if (
                not isinstance(proof, dict)
                or set(proof) != RELAY_FIELDS | {"worker_id", "generation"}
                or any(not isinstance(value, str) for value in proof.values())
                or proof["worker_id"] != row["worker_id"]
                or proof["generation"] != row["generation"]
            ):
                raise BrowserAttestationError("relay evidence worker mismatch")
            row.update({field: proof[field] for field in RELAY_FIELDS})
            _validate_relay_fields(row)
        if len({row["relay_container_id"] for row in workers}) != len(workers):
            raise BrowserAttestationError("duplicate signed relay identity")
    payload = {
        "version": version,
        "issued_at": int(time.time()) if now is None else now,
        "workers": workers,
        "algorithm": _ALGORITHM,
    }
    signed = {
        **payload,
        _SIGNATURE_FIELD: base64.b64encode(secret.sign(_canonical(payload))).decode(
            "ascii"
        ),
    }
    tmp = None
    try:
        fd, tmp = tempfile.mkstemp(prefix=".ccbw-ed25519-", dir=destination.parent)
        try:
            if proof_gid is not None:
                if type(proof_gid) is not int or proof_gid < 0:
                    raise BrowserAttestationError("invalid proof group")
                os.fchown(fd, -1, proof_gid)
            os.fchmod(fd, 0o640 if proof_gid is not None else 0o600)
        except BaseException:
            os.close(fd)
            raise
        with os.fdopen(fd, "wb") as writer:
            writer.write(_canonical(signed))
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


class Ed25519WorkerAttestationVerifier:
    """API-only verifier with an Ed25519 public key; cannot sign forged proofs."""

    def __init__(
        self,
        path: str,
        public_key_base64: str,
        *,
        max_age: int = MAX_ATTESTATION_AGE_SECONDS,
    ) -> None:
        if not 2 <= max_age <= 30:
            raise ValueError("attestation lifetime must be 2-30 seconds")
        self.path = Path(path)
        self.key = Ed25519PublicKey.from_public_bytes(_decode_key(public_key_base64))
        self.max_age = max_age

    def _read(self, *, now: int | None = None) -> list[dict[str, str]]:
        _require_private_path(self.path)
        try:
            with self.path.open("rb") as stream:
                raw = stream.read(_MAX_FILE_BYTES + 1)
            if len(raw) > _MAX_FILE_BYTES:
                raise BrowserAttestationError("oversized worker attestation")
            data = json.loads(raw)
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise BrowserAttestationError("invalid worker attestation") from exc
        expected = {"version", "issued_at", "workers", "algorithm", _SIGNATURE_FIELD}
        if not isinstance(data, dict) or set(data) != expected:
            raise BrowserAttestationError("malformed Ed25519 attestation")
        signature = data.pop(_SIGNATURE_FIELD)
        if data.get("algorithm") != _ALGORITHM:
            raise BrowserAttestationError("unsupported attestation algorithm")
        try:
            encoded = base64.b64decode(signature, validate=True)
            if len(encoded) != 64:
                raise BrowserAttestationError("invalid Ed25519 signature length")
            self.key.verify(encoded, _canonical(data))
        except (TypeError, ValueError, binascii.Error, InvalidSignature) as exc:
            raise BrowserAttestationError(
                "worker attestation signature invalid"
            ) from exc
        issued = data["issued_at"]
        stamp = int(time.time()) if now is None else now
        if (
            type(data["version"]) is not int
            or data["version"] not in (ATTESTATION_VERSION, RELAY_ATTESTATION_VERSION)
            or type(issued) is not int
            or not -CLOCK_SKEW_SECONDS <= stamp - issued <= self.max_age
        ):
            raise BrowserAttestationError("worker attestation expired")
        workers = data["workers"]
        fields = set(BINDING_FIELDS) | {RUNTIME_FIELD}
        if data["version"] == RELAY_ATTESTATION_VERSION:
            fields |= RELAY_FIELDS
        if (
            not isinstance(workers, list)
            or len(workers) > 16
            or any(
                not isinstance(row, dict)
                or set(row) != fields
                or any(not isinstance(value, str) for value in row.values())
                for row in workers
            )
            or len({row["worker_id"] for row in workers}) != len(workers)
        ):
            raise BrowserAttestationError("invalid worker attestation records")
        if data["version"] == RELAY_ATTESTATION_VERSION:
            for row in workers:
                _validate_relay_fields(row)
            if len({row["relay_container_id"] for row in workers}) != len(workers):
                raise BrowserAttestationError("duplicate signed relay identity")
        return workers

    def verify(self, worker_id: str, *, now: int | None = None) -> dict[str, str]:
        for row in self._read(now=now):
            if row["worker_id"] == worker_id:
                return row
        raise BrowserAttestationError(
            "physical browser worker is not currently verified"
        )
