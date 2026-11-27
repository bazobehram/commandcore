"""Operator-side physical identity of a one-worker Unix relay.

No Docker permissions are granted to the API. This validates evidence for
the future signed operator snapshot; it does not publish or authorize a route.
"""

from __future__ import annotations

import re
import stat
from pathlib import Path

from .browser_worker_orchestrator import (
    GENERATION_LABEL,
    PROJECT_LABEL,
    ROLE_LABEL,
    WORKER_LABEL,
    DockerAdapter,
    PhysicalWorker,
    WorkerQuarantined,
)

SOCKET_TARGET = "/run/commandcore-relay"


def verify_physical_relay(
    worker: PhysicalWorker,
    docker: DockerAdapter,
    *,
    container_id: str,
    image_id: str,
    socket_root: Path,
    operator_uid: int,
    operator_gid: int,
    api_uid: int,
    api_gid: int,
) -> dict[str, str]:
    """Inspect the exact pinned relay, network membership and real socket inodes.

    The expected container/image identities and UID/GID must be provided by
    the trusted operator registry, never by an OAuth client or inspected labels.
    """
    if (
        not re.fullmatch(r"w-[0-9a-f]{18}", worker.worker_id)
        or not re.fullmatch(r"[0-9a-f]{64}", container_id)
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id)
        or any(
            type(n) is not int or n <= 0
            for n in (operator_uid, operator_gid, api_uid, api_gid)
        )
        or operator_uid == api_uid
        or container_id in (worker.steel_container_id, worker.boundary_container_id)
    ):
        raise WorkerQuarantined("invalid pinned relay identity")
    name = "ccbw-relay-" + worker.worker_id
    source = socket_root / worker.worker_id
    try:
        if not socket_root.is_absolute() or socket_root.resolve() != socket_root:
            raise WorkerQuarantined("relay socket root is not canonical")
        if socket_root.parent.stat().st_mode & 0o022:
            raise WorkerQuarantined("relay socket parent is writable")
        for directory in (socket_root, source):
            info = directory.lstat()
            if (
                not stat.S_ISDIR(info.st_mode)
                or info.st_uid != operator_uid
                or info.st_gid != operator_gid
                or stat.S_IMODE(info.st_mode) != 0o750
            ):
                raise WorkerQuarantined("relay socket directory identity mismatch")
    except OSError as exc:
        raise WorkerQuarantined("relay socket directory unavailable") from exc

    record = docker.inspect(name)
    config = record.get("Config") or {}
    host = record.get("HostConfig") or {}
    state = record.get("State") or {}
    labels = config.get("Labels") or {}
    expected_labels = {
        PROJECT_LABEL: "1",
        WORKER_LABEL: worker.worker_id,
        GENERATION_LABEL: worker.generation,
        ROLE_LABEL: "relay",
    }
    command = [
        "-m",
        "commandcore_server.browser_worker_uds_relay",
        "--worker-id",
        worker.worker_id,
        "--socket-dir",
        SOCKET_TARGET,
        "--api-uid",
        str(api_uid),
        "--api-gid",
        str(api_gid),
    ]
    started = state.get("StartedAt")
    if (
        record.get("Id") != container_id
        or record.get("Name") != "/" + name
        or record.get("Image") != image_id
        or any(labels.get(k) != v for k, v in expected_labels.items())
        or config.get("User") != f"{operator_uid}:{operator_gid}"
        or config.get("Entrypoint") != ["python"]
        or config.get("Cmd") != command
        or state.get("Running") is not True
        or not isinstance(started, str)
        or not re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z", started
        )
        or started.startswith("0001-")
    ):
        raise WorkerQuarantined("relay container identity or runtime mismatch")
    if (
        host.get("Privileged") is not False
        or host.get("ReadonlyRootfs") is not True
        or set(host.get("CapDrop") or []) != {"ALL"}
        or host.get("CapAdd")
        or set(host.get("SecurityOpt") or []) != {"no-new-privileges:true"}
        or any(
            host.get(k)
            for k in (
                "PortBindings",
                "Binds",
                "Devices",
                "DeviceRequests",
                "VolumesFrom",
                "PidMode",
                "UTSMode",
                "UsernsMode",
                "ExtraHosts",
                "Dns",
            )
        )
        or host.get("PublishAllPorts")
        or host.get("IpcMode") not in ("", "private")
        or host.get("NetworkMode")
        not in (worker.control_network, worker.control_network_id)
        or not 0 < (host.get("Memory") or 0) <= 256 * 1024 * 1024
        or not 0 < (host.get("NanoCpus") or 0) <= 1_000_000_000
        or not 0 < (host.get("PidsLimit") or 0) <= 64
        or (host.get("RestartPolicy") or {}).get("Name") != "no"
    ):
        raise WorkerQuarantined("relay container isolation mismatch")
    mounts = record.get("Mounts") or []
    if (
        len(mounts) != 1
        or mounts[0].get("Type") != "bind"
        or mounts[0].get("Source") != str(source)
        or mounts[0].get("Destination") != SOCKET_TARGET
        or mounts[0].get("RW") is not True
        or mounts[0].get("Propagation") != "rprivate"
    ):
        raise WorkerQuarantined("relay socket mount mismatch")
    endpoints = (record.get("NetworkSettings") or {}).get("Networks") or {}
    network = docker.inspect_network(worker.control_network)
    members = network.get("Containers") or {}
    if (
        set(endpoints) != {worker.control_network}
        or endpoints[worker.control_network].get("NetworkID")
        != worker.control_network_id
        or network.get("Id") != worker.control_network_id
        or network.get("Name") != worker.control_network
        or network.get("Driver") != "bridge"
        or network.get("Internal") is not True
        or network.get("EnableIPv6") is not False
        or (network.get("Options") or {}).get(
            "com.docker.network.bridge.gateway_mode_ipv4"
        )
        != "isolated"
        or set(members) != {container_id, worker.boundary_container_id}
        or members[container_id].get("Name") != name
        or members[worker.boundary_container_id].get("Name") != worker.boundary_name
    ):
        raise WorkerQuarantined("relay control network identity or membership mismatch")

    evidence = {
        "worker_id": worker.worker_id,
        "generation": worker.generation,
        "relay_container_id": container_id,
        "relay_image_id": image_id,
        "relay_started_at": started,
    }
    try:
        for service in ("steel", "policy"):
            info = (source / (service + ".sock")).lstat()
            if (
                not stat.S_ISSOCK(info.st_mode)
                or stat.S_IMODE(info.st_mode) != 0o660
                or info.st_uid != operator_uid
                or info.st_gid != operator_gid
            ):
                raise WorkerQuarantined("relay socket identity mismatch")
            evidence["relay_" + service + "_dev"] = str(info.st_dev)
            evidence["relay_" + service + "_ino"] = str(info.st_ino)
    except OSError as exc:
        raise WorkerQuarantined("relay socket unavailable") from exc
    # Inspect again to reject a relay restart during observation.
    after = docker.inspect(name)
    if (
        after.get("Id") != container_id
        or (after.get("State") or {}).get("Running") is not True
        or (after.get("State") or {}).get("StartedAt") != started
    ):
        raise WorkerQuarantined("relay incarnation changed during verification")
    return evidence
