#!/usr/bin/env python3
"""Operator-only, fail-closed CommandCore Browser worker provisioning prototype.

Not an MCP tool. Docker privileges remain outside the CommandCore server.
Only create disposable/new worker IDs; never migrate an existing Chromium
profile/owner. Published manifests contain no OAuth identity.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import secrets
import shlex
import stat
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from commandcore_server.browser_egress import _normalize_hosts
from commandcore_server.browser_worker_binding import (
    BrowserWorkerBinding,
    WorkerOwnershipError,
)
from commandcore_server.browser_worker_orchestrator import (
    DockerCli,
    PhysicalWorker,
    WorkerQuarantined,
    verify_physical_worker,
)

MAX_WORKERS = 16
SECCOMP_SOURCE_SHA256 = (
    "a48b434d0ed34bdd1020fd5f73af8f2060c680fafabfa2e278d3866b6d9a2476"
)
SECCOMP_PROFILE = (
    Path(__file__).resolve().parent / "vendor/chromium-sandbox-seccomp-probe.json"
)
MARK = "org.commandcore.browser"
FILE_MODE = 0o600
DIR_MODE = 0o700


def command(*args: str) -> str:
    result = subprocess.run(
        ["docker", *args], capture_output=True, text=True, check=False, timeout=30
    )
    if result.returncode:
        raise WorkerQuarantined("Docker provisioning command failed")
    return result.stdout.strip()


def inspect_image(name: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_.:/@-]{1,200}", name):
        raise WorkerQuarantined("unsafe image reference")
    digest = command("image", "inspect", name, "--format", "{{.Id}}")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise WorkerQuarantined("image was not pinned to an immutable ID")
    return digest


def private_dir(path: Path) -> None:
    st = path.stat()
    if not stat.S_ISDIR(st.st_mode) or st.st_mode & 0o077:
        raise WorkerQuarantined("operator state directory must be private")
    if st.st_mode & 0o022:
        raise WorkerQuarantined("operator state directory writable by others")


def private_json(path: Path) -> Any:
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_mode & 0o077:
        raise WorkerQuarantined("operator data file permissions unsafe")
    return json.loads(path.read_text())


def atomic_json(path: Path, data: Any) -> None:
    private_dir(path.parent)
    file = None
    try:
        fd, file = tempfile.mkstemp(dir=path.parent, prefix=".ccbw-")
        os.fchmod(fd, FILE_MODE)
        # Administrator lifecycle actions must retain the dedicated operator's
        # state ownership, including after shutdown/retirement.
        if os.geteuid() == 0:
            parent = path.parent.stat()
            os.fchown(fd, parent.st_uid, parent.st_gid)
        with os.fdopen(fd, "w") as output:
            json.dump(data, output, separators=(",", ":"), sort_keys=True)
            output.flush()
            os.fsync(output.fileno())
        os.replace(file, path)
        file = None
        dirfd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
    finally:
        if file:
            Path(file).unlink(missing_ok=True)


def snapshots(root: Path, entries: list[dict]) -> None:
    active = [e for e in entries if e["state"] == "active"]
    # Reconciler sees physical snapshot before API sees routing snapshot.
    # On transition, HMAC attestation is always separately required.
    atomic_json(
        root / "physical-workers.json", {"workers": [e["physical"] for e in active]}
    )
    atomic_json(
        root / "browser-workers.json", {"workers": [e["route"] for e in active]}
    )


@contextmanager
def exclusive_state(root: Path):
    private_dir(root)
    flag = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flag |= os.O_NOFOLLOW
    lock = os.open(root / ".operator.lock", flag, FILE_MODE)
    try:
        if not stat.S_ISREG(os.fstat(lock).st_mode) or os.fstat(lock).st_mode & 0o077:
            raise WorkerQuarantined("operator lock permissions unsafe")
        fcntl.flock(lock, fcntl.LOCK_EX)
        file = root / "registry.json"
        entries = private_json(file)["workers"] if file.exists() else []
        if not isinstance(entries, list) or len(entries) > MAX_WORKERS:
            raise WorkerQuarantined("invalid browser worker registry")
        yield entries
    finally:
        fcntl.flock(lock, fcntl.LOCK_UN)
        os.close(lock)


def stored(root: Path, entries: list[dict]) -> None:
    atomic_json(root / "registry.json", {"workers": entries})
    snapshots(root, entries)


def _assert_owner(data: dict) -> tuple[str, str, str]:
    if not isinstance(data, dict) or set(data) != {"issuer", "subject", "client_id"}:
        raise WorkerQuarantined(
            "private owner assignment requires issuer, subject, client_id"
        )
    owner = (data["issuer"], data["subject"], data["client_id"])
    if any(not isinstance(item, str) or not item.strip() for item in owner):
        raise WorkerQuarantined("invalid private owner assignment")
    if not owner[0].startswith("https://"):
        raise WorkerQuarantined("OAuth issuer must be HTTPS")
    return owner


def _labels(worker_id: str, generation: str, role: str) -> tuple[str, ...]:
    return (
        "--label",
        f"{MARK}.preview=1",
        "--label",
        f"{MARK}.worker={worker_id}",
        "--label",
        f"{MARK}.generation={generation}",
        "--label",
        f"{MARK}.role={role}",
    )


def provision(
    root: Path,
    owner_path: Path,
    allow_hosts: str,
    steel_image: str,
    boundary_image: str,
    binding_key: str,
) -> str:
    if len(binding_key) < 32:
        raise WorkerQuarantined("private owner binding key unavailable")
    owner = _assert_owner(private_json(owner_path))
    hosts = ",".join(_normalize_hosts(allow_hosts))
    if (
        not SECCOMP_PROFILE.is_file()
        or hashlib.sha256(SECCOMP_PROFILE.read_bytes()).hexdigest()
        != SECCOMP_SOURCE_SHA256
    ):
        raise WorkerQuarantined("vetted Chromium seccomp profile missing or modified")
    image_steel = inspect_image(steel_image)
    image_boundary = inspect_image(boundary_image)
    with exclusive_state(root) as registry:
        # Refuse duplicate assignments, including stopped/retired tombstones.
        # Keep the owner fingerprint inside the existing MAC-protected ledger:
        # the registry and physical manifests must not expose OAuth identity.
        for existing in registry:
            try:
                prior = BrowserWorkerBinding(
                    existing["route"]["binding_path"],
                    existing["worker_id"],
                    binding_key,
                    require_claimed=True,
                )
                try:
                    if prior.matches(owner):
                        raise WorkerQuarantined(
                            "OAuth owner already has a browser worker assignment"
                        )
                finally:
                    prior.close()
            except (KeyError, TypeError, WorkerOwnershipError, OSError) as exc:
                raise WorkerQuarantined(
                    "existing browser owner ledger cannot be verified"
                ) from exc
        if len(registry) >= MAX_WORKERS:
            raise WorkerQuarantined("browser worker capacity reached")
        # Operator-only allocation; neither user nor OAuth request supplies ID.
        worker_id = "w-" + secrets.token_hex(9)
        if any(entry["worker_id"] == worker_id for entry in registry):
            raise WorkerQuarantined("random browser worker identity collision")
        generation = secrets.token_hex(16)
        record_dir = root / worker_id
        record_dir.mkdir(mode=DIR_MODE)
        created_containers: list[str] = []
        created_networks: list[str] = []
        try:
            binding_file = record_dir / "owner.sqlite3"
            ledger = BrowserWorkerBinding.provision(
                str(binding_file), worker_id, binding_key
            )
            ledger.claim(owner)

            names = {
                "steel": "ccbw-steel-" + worker_id,
                "boundary": "ccbw-boundary-" + worker_id,
                "isolated": "ccbw-isolated-" + worker_id,
                "control": "ccbw-control-" + worker_id,
                "outbound": "ccbw-outbound-" + worker_id,
            }
            for name, internal in (
                (names["isolated"], True),
                (names["control"], True),
                (names["outbound"], False),
            ):
                args = ["network", "create", "--driver", "bridge", "--ipv6=false"]
                if internal:
                    args += [
                        "--internal",
                        "--opt",
                        "com.docker.network.bridge.gateway_mode_ipv4=isolated",
                    ]
                args += [name]
                network_id = command(*args)
                if not re.fullmatch(r"[0-9a-f]{64}", network_id):
                    raise WorkerQuarantined("Docker network create returned invalid ID")
                created_networks.append(network_id)

            boundary_id = command(
                "create",
                "--name",
                names["boundary"],
                "--network",
                names["isolated"],
                "--network-alias",
                "browser-boundary",
                *_labels(worker_id, generation, "boundary"),
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges:true",
                "--tmpfs",
                "/tmp:rw,nosuid,size=16m",
                "--memory",
                "128m",
                "--cpus",
                "1",
                "--pids-limit",
                "80",
                "--health-cmd",
                "python -m commandcore_server.browser_boundary_health --relay-host ccctl-"
                + worker_id
                + " --allow-hosts "
                + shlex.quote(hosts),
                "--health-interval",
                "10s",
                "--health-timeout",
                "5s",
                "--health-start-period",
                "10s",
                "--health-retries",
                "3",
                "--entrypoint",
                "python",
                image_boundary,
                "-m",
                "commandcore_server.browser_egress",
                "--allow-hosts",
                hosts,
                "--relay-bind",
                "ccctl-" + worker_id,
            )
            created_containers.append(boundary_id)
            command(
                "network",
                "connect",
                "--alias",
                "ccctl-" + worker_id,
                names["control"],
                boundary_id,
            )
            command("network", "connect", names["outbound"], boundary_id)
            command("start", boundary_id)
            # Chromium must not need Docker's UDP DNS to reach its only
            # approved TCP egress proxy. Resolve the physically created
            # boundary on the isolated network and pin it in /etc/hosts.
            network_records = (
                DockerCli().inspect(names["boundary"]).get("NetworkSettings") or {}
            ).get("Networks") or {}
            boundary_ip = (network_records.get(names["isolated"]) or {}).get(
                "IPAddress"
            )
            import ipaddress

            try:
                addr = ipaddress.ip_address(boundary_ip or "")
            except ValueError as exc:
                raise WorkerQuarantined("isolated proxy IP is unavailable") from exc
            if addr.version != 4 or not addr.is_private:
                raise WorkerQuarantined(
                    "isolated proxy requires a private IPv4 address"
                )

            steel_id = command(
                "create",
                "--name",
                names["steel"],
                "--init",
                "--network",
                names["isolated"],
                "--network-alias",
                "steel",
                "--add-host",
                f"browser-boundary:{addr}",
                *_labels(worker_id, generation, "steel"),
                "--user",
                "1000:1000",
                "--read-only",
                "--cap-drop",
                "ALL",
                "--cap-add",
                "SYS_CHROOT",
                "--security-opt",
                f"seccomp={SECCOMP_PROFILE}",
                "--security-opt",
                "no-new-privileges:true",
                "--tmpfs",
                "/tmp:rw,exec,nosuid,size=512m",
                "--tmpfs",
                "/run:rw,nosuid,size=16m",
                "--tmpfs",
                "/home/node:rw,exec,nosuid,size=128m,uid=1000,gid=1000,mode=0700",
                "--env",
                "HOME=/home/node",
                "--env",
                "DISABLE_CHROME_SANDBOX=false",
                "--memory",
                "2g",
                "--cpus",
                "1",
                "--pids-limit",
                "512",
                "--shm-size",
                "256m",
                image_steel,
                "--no-nginx",
            )
            created_containers.append(steel_id)
            command("start", steel_id)

            docker = DockerCli()
            physical = PhysicalWorker.from_dict(
                {
                    "worker_id": worker_id,
                    "generation": generation,
                    "steel_name": names["steel"],
                    "boundary_name": names["boundary"],
                    "steel_container_id": docker.inspect(names["steel"])["Id"],
                    "boundary_container_id": docker.inspect(names["boundary"])["Id"],
                    "isolated_network": names["isolated"],
                    "control_network": names["control"],
                    "outbound_network": names["outbound"],
                    "isolated_network_id": docker.inspect_network(names["isolated"])[
                        "Id"
                    ],
                    "control_network_id": docker.inspect_network(names["control"])[
                        "Id"
                    ],
                    "outbound_network_id": docker.inspect_network(names["outbound"])[
                        "Id"
                    ],
                    "steel_image_id": image_steel,
                    "boundary_image_id": image_boundary,
                }
            )
            verify_physical_worker(physical, docker)
            route = {
                "worker_id": worker_id,
                "binding_path": str(binding_file),
                "steel_url": f"http://ccctl-{worker_id}:3000",
                "cdp_url": f"ws://ccctl-{worker_id}:3000",
                "egress_proxy_url": "http://browser-boundary:8080",
                "egress_policy_url": f"http://ccctl-{worker_id}:8080",
            }
            registry.append(
                {
                    "worker_id": worker_id,
                    "state": "active",
                    "physical": vars(physical),
                    "route": route,
                }
            )
            stored(root, registry)
            return worker_id
        except BaseException:
            # Only resource IDs returned by this invocation, never shared names.
            for cid in reversed(created_containers):
                subprocess.run(
                    ["docker", "rm", "-f", cid],
                    capture_output=True,
                    timeout=20,
                    check=False,
                )
            for nid in reversed(created_networks):
                subprocess.run(
                    ["docker", "network", "rm", nid],
                    capture_output=True,
                    timeout=20,
                    check=False,
                )
            # Do not reassign a contaminated identity or owner binding.
            # Residual private state is a forensic marker if cleanup was partial.
            raise


def transition(root: Path, worker_id: str, operation: str) -> None:
    if not re.fullmatch(r"w-[0-9a-f]{18}", worker_id):
        raise WorkerQuarantined("worker ID invalid")
    with exclusive_state(root) as entries:
        entry = next((item for item in entries if item["worker_id"] == worker_id), None)
        if entry is None:
            raise WorkerQuarantined("worker is not registered")
        physical = PhysicalWorker.from_dict(entry["physical"])
        docker = DockerCli()
        if operation == "stop":
            if entry["state"] != "active":
                raise WorkerQuarantined("only active worker can stop")
            # An orderly signer shutdown may already stop these exact workers.
            # Verify immutable identity even when stopped before retirement.
            verify_physical_worker(physical, docker, require_running=False)
            entry["state"] = "stopped"
            stored(root, entries)
            command("stop", "--time", "3", physical.steel_container_id)
            command("stop", "--time", "3", physical.boundary_container_id)
        elif operation == "start":
            if entry["state"] != "stopped":
                raise WorkerQuarantined("restart requires explicitly stopped worker")
            verify_physical_worker(physical, docker, require_running=False)
            # Keep worker unpublished if the restart fails verification.
            command("start", physical.boundary_container_id)
            command("start", physical.steel_container_id)
            verify_physical_worker(physical, docker)
            entry["state"] = "active"
            stored(root, entries)
        elif operation == "retire":
            if entry["state"] != "stopped":
                raise WorkerQuarantined("retire requires explicitly stopped worker")
            verify_physical_worker(physical, docker, require_running=False)
            entry["state"] = "retired"
            stored(root, entries)
            # Only exact verified immutable container/network IDs may be deleted.
            for cid in (physical.steel_container_id, physical.boundary_container_id):
                command("rm", cid)
            for nid in (
                physical.isolated_network_id,
                physical.control_network_id,
                physical.outbound_network_id,
            ):
                command("network", "rm", nid)
            # Owner binding remains as a tombstone and is never reused.
        else:
            raise WorkerQuarantined("unknown operator lifecycle action")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", required=True)
    options = parser.add_subparsers(dest="action", required=True)
    provision_parser = options.add_parser("provision")
    provision_parser.add_argument("--owner-file", required=True)
    provision_parser.add_argument("--allow-hosts", required=True)
    provision_parser.add_argument("--steel-image", required=True)
    provision_parser.add_argument("--boundary-image", required=True)
    for op in ("stop", "start", "retire"):
        sub = options.add_parser(op)
        sub.add_argument("--worker-id", required=True)
    args = parser.parse_args()
    root = Path(args.state_dir)
    if not root.is_absolute():
        parser.error("state-dir must be absolute")
    try:
        if args.action == "provision":
            key = os.getenv("COMMANDCORE_BROWSER_WORKER_BINDING_KEY", "")
            identity = provision(
                root,
                Path(args.owner_file),
                args.allow_hosts,
                args.steel_image,
                args.boundary_image,
                key,
            )
            print("OPERATOR_WORKER_PROVISIONED", identity)
        else:
            transition(root, args.worker_id, args.action)
            print("OPERATOR_WORKER_" + args.action.upper(), args.worker_id)
    except (WorkerQuarantined, OSError, ValueError, json.JSONDecodeError) as exc:
        # Errors deliberately avoid dumping identities, paths or secret values.
        parser.exit(2, "Browser operator request refused: " + str(exc) + "\n")


if __name__ == "__main__":
    main()
