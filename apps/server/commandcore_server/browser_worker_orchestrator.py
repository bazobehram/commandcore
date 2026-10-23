"""Operator-only Docker worker identity and lifecycle guard (experimental).

This component is NOT exposed through MCP and does NOT receive Docker socket
privileges inside CommandCore. It validates physical Docker worker identity
before a private operator-generated manifest may be accepted.

Production remains blocked until independently reviewed egress, profile,
restart, and multi-user OAuth tests are complete.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

# Docker 29.1.3 normalized version of the tested, socketcall-denying
# Moby default+user-namespace seccomp profile. Fail closed on any change.
CHROMIUM_SECCOMP_PROFILE_SHA256 = (
    "91a788caa9ed8d1ff6c75c72f7e7bd419921901afb0922476eb60be89a9adda9"
)
PREFIX = "ccbw-"


def is_trusted_systemd_credential(path: Path) -> bool:
    """Allow the systemd-managed root:root 0440 credential file format only.

    Ordinary operator files must still be 0600/0400. Credentials are mounted
    per service below /run/credentials, with a root-owned nonwritable parent.
    Merely setting CREDENTIALS_DIRECTORY to an arbitrary path is insufficient.
    """
    supplied = os.environ.get("CREDENTIALS_DIRECTORY", "")
    if not supplied or not supplied.startswith("/run/credentials/"):
        return False
    directory = Path(supplied)
    credential_root = Path("/run/credentials")
    if (
        directory.parent != credential_root
        or credential_root.is_symlink()
        or path.parent != directory
        or directory.is_symlink()
    ):
        return False
    try:
        parent = directory.stat()
    except OSError:
        return False
    return (
        stat.S_ISDIR(parent.st_mode)
        and parent.st_uid == 0
        and not parent.st_mode & 0o022
        and not parent.st_mode & 0o007
    )


PROJECT_LABEL = "org.commandcore.browser.preview"
WORKER_LABEL = "org.commandcore.browser.worker"
ROLE_LABEL = "org.commandcore.browser.role"
GENERATION_LABEL = "org.commandcore.browser.generation"


class WorkerQuarantined(Exception):
    """A managed worker no longer matches its recorded physical identity."""


class DockerAdapter(Protocol):
    def inspect(self, name: str) -> dict[str, Any]: ...
    def inspect_network(self, name: str) -> dict[str, Any]: ...
    def stop(self, container_id: str) -> None: ...


class DockerCli:
    """Operator-host CLI only; never mount Docker socket into MCP/API process."""

    def _run(self, *args: str) -> str:
        try:
            result = subprocess.run(
                ["docker", *args],
                timeout=15,
                capture_output=True,
                text=True,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise WorkerQuarantined("Docker lifecycle operation unavailable") from exc
        if result.returncode:
            raise WorkerQuarantined("Docker lifecycle operation unavailable")
        return result.stdout

    def inspect(self, name: str) -> dict[str, Any]:
        try:
            records = json.loads(self._run("inspect", "--type", "container", name))
            if len(records) != 1 or not isinstance(records[0], dict):
                raise WorkerQuarantined("ambiguous Docker container identity")
            return records[0]
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            raise WorkerQuarantined("invalid Docker inspect response") from exc

    def inspect_network(self, name: str) -> dict[str, Any]:
        try:
            records = json.loads(self._run("network", "inspect", name))
            if len(records) != 1 or not isinstance(records[0], dict):
                raise WorkerQuarantined("ambiguous Docker network identity")
            return records[0]
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            raise WorkerQuarantined("invalid Docker network inspection") from exc

    def stop(self, container_id: str) -> None:
        if not re.fullmatch(r"[0-9a-f]{64}", container_id):
            raise WorkerQuarantined("container stop requires immutable Docker ID")
        self._run("stop", "--time", "3", container_id)

    def start(self, container_id: str) -> None:
        if not re.fullmatch(r"[0-9a-f]{64}", container_id):
            raise WorkerQuarantined("container start requires immutable Docker ID")
        self._run("start", container_id)


@dataclass(frozen=True)
class PhysicalWorker:
    worker_id: str
    generation: str
    steel_name: str
    steel_container_id: str
    boundary_name: str
    boundary_container_id: str
    isolated_network: str
    control_network: str
    outbound_network: str
    isolated_network_id: str
    control_network_id: str
    outbound_network_id: str
    steel_image_id: str
    boundary_image_id: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PhysicalWorker:
        if not isinstance(data, dict) or set(data) != set(cls.__dataclass_fields__):
            raise WorkerQuarantined("invalid physical worker identity record")
        if not all(isinstance(value, str) and value for value in data.values()):
            raise WorkerQuarantined("empty physical worker identity")
        worker = cls(**data)
        if not re.fullmatch(r"[a-z0-9-]{8,26}", worker.worker_id):
            raise WorkerQuarantined("unsafe worker ID")
        if not re.fullmatch(r"[0-9a-f]{32}", worker.generation):
            raise WorkerQuarantined("unsafe worker generation")
        if not all(
            re.fullmatch(r"[0-9a-f]{64}", v)
            for v in (
                worker.steel_container_id,
                worker.boundary_container_id,
                worker.isolated_network_id,
                worker.control_network_id,
                worker.outbound_network_id,
            )
        ):
            raise WorkerQuarantined("invalid Docker container immutable ID")
        if not all(
            re.fullmatch(r"sha256:[0-9a-f]{64}", v)
            for v in (
                worker.steel_image_id,
                worker.boundary_image_id,
            )
        ):
            raise WorkerQuarantined("Docker images must be pinned by image ID")
        if not worker.steel_name.startswith(
            PREFIX
        ) or not worker.boundary_name.startswith(PREFIX):
            raise WorkerQuarantined("worker resources do not use managed prefixes")
        if (
            len(
                {
                    worker.steel_name,
                    worker.boundary_name,
                    worker.isolated_network,
                    worker.control_network,
                    worker.outbound_network,
                }
            )
            != 5
        ):
            raise WorkerQuarantined("worker resource identity collision")
        return worker


def _networks(record: dict[str, Any]) -> set[str]:
    nets = (record.get("NetworkSettings") or {}).get("Networks")
    if not isinstance(nets, dict):
        raise WorkerQuarantined("Docker network inspection unavailable")
    return set(nets)


def _validate_container(
    record: dict[str, Any],
    *,
    expected_id: str,
    image: str,
    worker: PhysicalWorker,
    role: str,
    networks: set[str],
    require_running: bool = True,
) -> None:
    config = record.get("Config") or {}
    host = record.get("HostConfig") or {}
    state = record.get("State") or {}
    labels = config.get("Labels") or {}
    if (
        record.get("Id") != expected_id
        or record.get("Image") != image
        or labels.get(PROJECT_LABEL) != "1"
        or labels.get(WORKER_LABEL) != worker.worker_id
        or labels.get(GENERATION_LABEL) != worker.generation
        or labels.get(ROLE_LABEL) != role
    ):
        raise WorkerQuarantined(
            "physical worker container/label/image identity mismatch"
        )
    if require_running and state.get("Running") is not True:
        raise WorkerQuarantined("browser worker is not running")
    if (
        host.get("Privileged") is not False
        or (host.get("PortBindings") or {})
        or host.get("NetworkMode") in {"host", "container"}
        or (host.get("Binds") or [])
        or (host.get("Mounts") or [])
        or (host.get("Devices") or [])
    ):
        raise WorkerQuarantined(
            "browser worker has dangerous Docker privileges/mounts/ports"
        )
    security_options = host.get("SecurityOpt") or []
    if "no-new-privileges:true" not in security_options:
        raise WorkerQuarantined("browser worker missing no-new-privileges")
    if host.get("ReadonlyRootfs") is not True:
        raise WorkerQuarantined("browser worker must have a read-only root filesystem")
    if "ALL" not in (host.get("CapDrop") or []):
        raise WorkerQuarantined(
            "browser worker must drop all default Linux capabilities"
        )
    added = host.get("CapAdd") or []
    if role == "steel":
        if config.get("User") != "1000:1000" or added != ["CAP_SYS_CHROOT"]:
            raise WorkerQuarantined(
                "Steel must use nonroot Chromium sandbox permissions"
            )
        seccomp_specs = [
            item.partition("=")[2]
            for item in security_options
            if isinstance(item, str) and item.startswith("seccomp=")
        ]
        if len(seccomp_specs) != 1:
            raise WorkerQuarantined("Steel must have a vetted seccomp profile")
        try:
            profile = json.loads(seccomp_specs[0])
            digest = hashlib.sha256(
                json.dumps(profile, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
        except (ValueError, TypeError):
            raise WorkerQuarantined("invalid Chromium seccomp profile")
        if digest != CHROMIUM_SECCOMP_PROFILE_SHA256:
            raise WorkerQuarantined(
                "Chromium seccomp profile differs from vetted version"
            )
    elif added:
        raise WorkerQuarantined("boundary must not add Linux capabilities")
    if _networks(record) != networks:
        raise WorkerQuarantined("browser worker network drift")
    if role == "steel" and not host.get("Init"):
        raise WorkerQuarantined("Steel worker missing init reaper")
    # Route aliases must be anchored to the expected worker's physical Docker
    # network. Unique URLs alone do not prove separate actual worker instances.
    endpoints = (record.get("NetworkSettings") or {}).get("Networks") or {}
    private = endpoints.get(worker.isolated_network) or {}
    aliases = private.get("Aliases") or []
    expected_alias = "steel" if role == "steel" else "browser-boundary"
    if expected_alias not in aliases:
        raise WorkerQuarantined("browser worker isolated DNS alias mismatch")
    if role == "boundary":
        control = endpoints.get(worker.control_network) or {}
        if "ccctl-" + worker.worker_id not in (control.get("Aliases") or []):
            raise WorkerQuarantined("browser worker control DNS alias mismatch")


def verify_physical_worker(
    worker: PhysicalWorker,
    docker: DockerAdapter,
    *,
    require_running: bool = True,
) -> None:
    for name, expected_id, internal in (
        (worker.isolated_network, worker.isolated_network_id, True),
        (worker.control_network, worker.control_network_id, True),
        (worker.outbound_network, worker.outbound_network_id, False),
    ):
        network = docker.inspect_network(name)
        if (
            network.get("Id") != expected_id
            or network.get("Name") != name
            or network.get("Driver") != "bridge"
            or network.get("Internal") is not internal
            or network.get("EnableIPv6") is not False
        ):
            raise WorkerQuarantined(
                "physical Docker network identity/isolation mismatch"
            )
        if (
            internal
            and (network.get("Options") or {}).get(
                "com.docker.network.bridge.gateway_mode_ipv4"
            )
            != "isolated"
        ):
            raise WorkerQuarantined(
                "internal Docker network lacks isolated gateway mode"
            )
    steel = docker.inspect(worker.steel_name)
    boundary = docker.inspect(worker.boundary_name)
    _validate_container(
        steel,
        expected_id=worker.steel_container_id,
        image=worker.steel_image_id,
        worker=worker,
        role="steel",
        networks={worker.isolated_network},
        require_running=require_running,
    )
    _validate_container(
        boundary,
        expected_id=worker.boundary_container_id,
        image=worker.boundary_image_id,
        worker=worker,
        role="boundary",
        networks={
            worker.isolated_network,
            worker.control_network,
            worker.outbound_network,
        },
        require_running=require_running,
    )
    # Chromium's inherited seccomp filter denies INET UDP sockets. The
    # boundary proxy's DNS alias therefore must be pinned to its exact
    # physically inspected internal IPv4 address in Chromium's /etc/hosts.
    import ipaddress

    isolated = (boundary.get("NetworkSettings") or {}).get("Networks") or {}
    boundary_ip = (isolated.get(worker.isolated_network) or {}).get("IPAddress")
    extra_hosts = (steel.get("HostConfig") or {}).get("ExtraHosts") or []
    if (
        len(extra_hosts) != 1
        or not isinstance(extra_hosts[0], str)
        or not extra_hosts[0].startswith("browser-boundary:")
    ):
        raise WorkerQuarantined("Chromium DNS-free boundary mapping is missing")
    pinned_ip = extra_hosts[0].partition(":")[2]
    try:
        mapped = ipaddress.ip_address(pinned_ip)
        if mapped.version != 4 or not mapped.is_private:
            raise ValueError("unsafe pinned proxy address")
        # Stopped Docker containers may have no runtime IP assignment.
        # Their immutable container ID and ExtraHosts config remain checked.
        # On restart we re-check the *live* boundary IP before publication.
        if require_running:
            address = ipaddress.ip_address(boundary_ip or "")
            if address != mapped:
                raise WorkerQuarantined(
                    "Chromium DNS-free boundary mapping has drifted"
                )
    except ValueError as exc:
        raise WorkerQuarantined(
            "boundary isolated IP address is unavailable or unsafe"
        ) from exc

    # Container ID checks prevent replacement with a new container bearing the
    # same name, but this inspector is a point-in-time test. Runtime continuity
    # requires a privileged *separate* orchestrator reconciliation loop.


def quarantine_physical_worker(worker: PhysicalWorker, docker: DockerAdapter) -> None:
    """Stop ONLY exact-label/exact-ID managed resources; never adjacent devices."""
    for role, name, cid in (
        ("steel", worker.steel_name, worker.steel_container_id),
        ("boundary", worker.boundary_name, worker.boundary_container_id),
    ):
        try:
            current = docker.inspect(name)
        except WorkerQuarantined:
            continue
        labels = (current.get("Config") or {}).get("Labels") or {}
        if (
            current.get("Id") == cid
            and labels.get(PROJECT_LABEL) == "1"
            and labels.get(WORKER_LABEL) == worker.worker_id
            and labels.get(GENERATION_LABEL) == worker.generation
            and labels.get(ROLE_LABEL) == role
        ):
            # Docker ID, not mutable name: refuse to stop a replacement between
            # inspect and stop.
            docker.stop(cid)


def operator_reconcile(
    identities: list[PhysicalWorker], docker: DockerAdapter
) -> list[tuple[str, str]]:
    """Quarantine mismatches; return only checked worker IDs and statuses."""
    unique = set()
    for item in identities:
        attributes = (
            item.worker_id,
            item.steel_container_id,
            item.boundary_container_id,
            item.isolated_network_id,
            item.control_network_id,
            item.outbound_network_id,
            item.steel_name,
            item.boundary_name,
            item.isolated_network,
            item.control_network,
            item.outbound_network,
        )
        for value in attributes:
            if value in unique:
                raise WorkerQuarantined("duplicate physical browser worker identity")
            unique.add(value)
    result: list[tuple[str, str]] = []
    for worker in identities:
        try:
            verify_physical_worker(worker, docker)
            result.append((worker.worker_id, "verified"))
        except WorkerQuarantined:
            quarantine_physical_worker(worker, docker)
            result.append((worker.worker_id, "quarantined"))
    return result


def load_private_identities(filename: str) -> list[PhysicalWorker]:
    import stat

    from .browser_worker_binding import WorkerOwnershipError

    path = Path(filename)
    try:
        s = path.lstat()
        p = path.parent.stat()
        if (
            not path.is_absolute()
            or not stat.S_ISREG(s.st_mode)
            or (
                s.st_mode & 0o077
                and not (
                    is_trusted_systemd_credential(path)
                    and stat.S_IMODE(s.st_mode) == 0o440
                    and s.st_uid == 0
                )
            )
            or p.st_mode & 0o022
        ):
            raise WorkerQuarantined("physical worker manifest must be private")
        data = json.loads(path.read_text())
    except (OSError, ValueError, WorkerOwnershipError) as exc:
        raise WorkerQuarantined("physical worker manifest unavailable") from exc
    if not isinstance(data, dict) or not isinstance(data.get("workers"), list):
        raise WorkerQuarantined("physical worker manifest structure invalid")
    return [PhysicalWorker.from_dict(x) for x in data["workers"]]
