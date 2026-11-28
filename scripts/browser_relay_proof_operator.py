#!/usr/bin/env python3
"""Publish short-lived v2 relay proof from the operator's private registry.

This is a separate, read-only Docker inspector. It never grants ownership,
starts workers, or accepts a proof supplied by the public API.
"""

from __future__ import annotations

import argparse
import os
import re
import stat
import time
from pathlib import Path

from browser_worker_lifecycle import exclusive_state
from commandcore_server.browser_worker_attestation import (
    MAX_ATTESTATION_AGE_SECONDS,
    BrowserAttestationError,
)
from commandcore_server.browser_worker_attestation_ed25519 import (
    write_operator_ed25519_attestation,
)
from commandcore_server.browser_worker_orchestrator import (
    DockerCli,
    PhysicalWorker,
    WorkerQuarantined,
    is_trusted_systemd_credential,
    verify_physical_worker,
)
from commandcore_server.browser_worker_relay_identity import (
    EMPTY_DATA_TMPFS,
    verify_physical_relay,
)

_STAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z")


def read_seed(path: Path) -> str:
    if not path.is_absolute() or path.is_symlink():
        raise BrowserAttestationError("unsafe operator signing credential")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid not in (0, os.geteuid())
            or not (
                stat.S_IMODE(info.st_mode) in (0o400, 0o600)
                or (
                    stat.S_IMODE(info.st_mode) == 0o440
                    and info.st_uid == 0
                    and is_trusted_systemd_credential(path)
                )
            )
            or not 1 <= info.st_size <= 128
        ):
            raise BrowserAttestationError("unsafe operator signing credential")
        data = os.read(fd, 129)
        if len(data) != info.st_size:
            raise BrowserAttestationError("operator signing credential changed")
        return data.decode("ascii").strip()
    finally:
        os.close(fd)


def _steel_stamp(worker: PhysicalWorker, docker: DockerCli) -> str:
    record = docker.inspect(worker.steel_name)
    state = record.get("State") or {}
    stamp = state.get("StartedAt")
    if (
        record.get("Id") != worker.steel_container_id
        or state.get("Running") is not True
        or not isinstance(stamp, str)
        or not _STAMP.fullmatch(stamp)
        or stamp.startswith("0001-")
    ):
        raise WorkerQuarantined("unverified Steel incarnation")
    return stamp


def _check_network_members(worker: PhysicalWorker, docker: DockerCli) -> None:
    for name, identity, members in (
        (
            worker.isolated_network,
            worker.isolated_network_id,
            {worker.steel_container_id, worker.boundary_container_id},
        ),
        (
            worker.outbound_network,
            worker.outbound_network_id,
            {worker.boundary_container_id},
        ),
    ):
        info = docker.inspect_network(name)
        if info.get("Id") != identity or set(info.get("Containers") or {}) != members:
            raise WorkerQuarantined("unexpected worker network member")


def reconcile_once(
    root: Path,
    destination: Path,
    seed: str,
    *,
    proof_gid: int | None,
    docker: DockerCli,
) -> int:
    """Publish only a fresh registry-consistent set, otherwise an empty proof."""
    try:
        if not root.is_absolute() or root.resolve() != root:
            raise WorkerQuarantined("unsafe operator registry")
        with exclusive_state(root) as entries:
            started = time.monotonic()
            issued = int(time.time())
            workers = []
            stamps = {}
            relays = {}
            identities = set()
            for entry in entries:
                if entry.get("state") != "active":
                    continue
                worker = PhysicalWorker.from_dict(entry["physical"])
                if entry.get("worker_id") != worker.worker_id:
                    raise WorkerQuarantined("registry worker identity mismatch")
                relay = dict(entry["relay"])
                resources = (
                    worker.worker_id,
                    worker.steel_container_id,
                    worker.boundary_container_id,
                    worker.isolated_network_id,
                    worker.control_network_id,
                    worker.outbound_network_id,
                    relay["container_id"],
                )
                if len(set(resources)) != len(resources) or identities.intersection(
                    resources
                ):
                    raise WorkerQuarantined("duplicate worker resource identity")
                identities.update(resources)
                stamp = _steel_stamp(worker, docker)
                verify_physical_worker(worker, docker)
                _check_network_members(worker, docker)
                boundary = docker.inspect(worker.boundary_name)
                if (
                    boundary.get("Id") != worker.boundary_container_id
                    or boundary.get("Mounts")
                    or ((boundary.get("HostConfig") or {}).get("Tmpfs") or {}).get(
                        "/data"
                    )
                    != EMPTY_DATA_TMPFS
                ):
                    raise WorkerQuarantined(
                        "public boundary has unexpected persistent storage"
                    )

                relay["socket_root"] = Path(relay["socket_root"])
                evidence = verify_physical_relay(worker, docker, **relay)
                if _steel_stamp(worker, docker) != stamp:
                    raise WorkerQuarantined("Steel restarted during verification")
                workers.append(worker)
                stamps[worker.worker_id] = stamp
                relays[worker.worker_id] = evidence
            # The oldest inspection must not acquire a fresh timestamp simply
            # because subsequent Docker calls were slow.
            if time.monotonic() - started >= MAX_ATTESTATION_AGE_SECONDS / 2:
                raise WorkerQuarantined("operator inspection exceeded freshness budget")
            write_operator_ed25519_attestation(
                str(destination),
                seed,
                workers,
                now=issued,
                started_at_by_worker=stamps,
                proof_gid=proof_gid,
                verified_relays=relays,
            )
            return len(workers)
    except (
        WorkerQuarantined,
        BrowserAttestationError,
        OSError,
        ValueError,
        KeyError,
        TypeError,
    ):
        # Never preserve a previously usable proof after an observed failure.
        write_operator_ed25519_attestation(
            str(destination),
            seed,
            [],
            proof_gid=proof_gid,
            verified_relays={},
        )
        return 0


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--attestation", type=Path, required=True)
    parser.add_argument("--signing-key-file", type=Path, required=True)
    parser.add_argument("--proof-gid", type=int, required=True)
    parser.add_argument("--interval", type=float, default=3)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.interval <= 3 or args.proof_gid <= 0:
        parser.error("invalid proof publication settings")
    try:
        seed = read_seed(args.signing_key_file)
        while True:
            reconcile_once(
                args.state_dir,
                args.attestation,
                seed,
                proof_gid=args.proof_gid,
                docker=DockerCli(),
            )
            if args.once:
                break
            time.sleep(args.interval)
    except (BrowserAttestationError, OSError, ValueError):
        parser.exit(2, "Browser relay proof publication unavailable\n")


if __name__ == "__main__":
    main()
