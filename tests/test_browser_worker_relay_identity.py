"""Physical relay evidence must not accept adjacent worker infrastructure."""

from __future__ import annotations

import copy
import os
import socket
import sys
from types import SimpleNamespace

import pytest
from commandcore_server.browser_worker_orchestrator import (
    GENERATION_LABEL,
    PROJECT_LABEL,
    ROLE_LABEL,
    WORKER_LABEL,
    WorkerQuarantined,
)
from commandcore_server.browser_worker_relay_identity import (
    SOCKET_TARGET,
    verify_physical_relay,
)

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux relay topology")


@pytest.fixture
def relay(tmp_path):
    uid = os.getuid() or 10001
    gid = os.getgid() or 999
    api_uid = uid + 1
    api_gid = gid + 1
    worker = SimpleNamespace(
        worker_id="w-" + "a" * 18,
        generation="b" * 32,
        steel_container_id="c" * 64,
        boundary_container_id="d" * 64,
        boundary_name="ccbw-boundary-w-" + "a" * 18,
        control_network="ccbw-control-w-" + "a" * 18,
        control_network_id="e" * 64,
    )
    cid = "f" * 64
    image = "sha256:" + "1" * 64
    name = "ccbw-relay-" + worker.worker_id
    root = tmp_path / "s"
    child = root / worker.worker_id
    child.mkdir(parents=True)
    for path in (root, child):
        os.chown(path, uid, gid)
        path.chmod(0o750)
    sockets = []
    try:
        # Avoid platform Unix path limits in CI's long pytest temp dirs:
        # bind relative to the worker directory using a short chdir.
        old = os.getcwd()
        try:
            os.chdir(child)
            for service in ("steel", "policy"):
                sock = socket.socket(socket.AF_UNIX)
                sockets.append(sock)
                sock.bind(service + ".sock")
                os.chown(service + ".sock", uid, gid)
                os.chmod(service + ".sock", 0o660)
        finally:
            os.chdir(old)
        record = {
            "Id": cid,
            "Name": "/" + name,
            "Image": image,
            "Config": {
                "User": f"{uid}:{gid}",
                "Entrypoint": ["python"],
                "Cmd": [
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
                ],
                "Labels": {
                    PROJECT_LABEL: "1",
                    WORKER_LABEL: worker.worker_id,
                    ROLE_LABEL: "relay",
                    GENERATION_LABEL: worker.generation,
                },
            },
            "State": {"Running": True, "StartedAt": "2026-11-27T12:00:00.000000001Z"},
            "HostConfig": {
                "Privileged": False,
                "ReadonlyRootfs": True,
                "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges:true"],
                "IpcMode": "private",
                "NetworkMode": worker.control_network,
                "Memory": 128 * 1024 * 1024,
                "NanoCpus": 500_000_000,
                "PidsLimit": 64,
                "RestartPolicy": {"Name": "no"},
            },
            "Mounts": [
                {
                    "Type": "bind",
                    "Source": str(child),
                    "Destination": SOCKET_TARGET,
                    "RW": True,
                    "Propagation": "rprivate",
                }
            ],
            "NetworkSettings": {
                "Networks": {
                    worker.control_network: {"NetworkID": worker.control_network_id},
                }
            },
        }
        net = {
            "Id": worker.control_network_id,
            "Name": worker.control_network,
            "Driver": "bridge",
            "Internal": True,
            "EnableIPv6": False,
            "Options": {"com.docker.network.bridge.gateway_mode_ipv4": "isolated"},
            "Containers": {
                cid: {"Name": name},
                worker.boundary_container_id: {"Name": worker.boundary_name},
            },
        }

        def verify(*, second=None):
            records = iter([record, record if second is None else second])
            docker = SimpleNamespace(
                inspect=lambda _name: next(records),
                inspect_network=lambda _name: net,
            )
            return verify_physical_relay(
                worker,
                docker,
                container_id=cid,
                image_id=image,
                socket_root=root,
                operator_uid=uid,
                operator_gid=gid,
                api_uid=api_uid,
                api_gid=api_gid,
            )

        yield SimpleNamespace(
            verify=verify, record=record, net=net, child=child, cid=cid, image=image
        )
    finally:
        for sock in sockets:
            sock.close()


def test_attests_pinned_relay_and_live_socket_identity(relay):
    evidence = relay.verify()
    assert evidence["relay_container_id"] == relay.cid
    assert evidence["relay_image_id"] == relay.image
    for service in ("steel", "policy"):
        info = (relay.child / (service + ".sock")).lstat()
        assert evidence[f"relay_{service}_dev"] == str(info.st_dev)
        assert evidence[f"relay_{service}_ino"] == str(info.st_ino)


@pytest.mark.parametrize(
    "path,value",
    [
        (("Id",), "9" * 64),
        (("Image",), "sha256:" + "2" * 64),
        (("Config", "User"), "0:0"),
        (("Config", "Cmd"), ["other"]),
        (("Config", "Labels", ROLE_LABEL), "boundary"),
        (("State", "Running"), False),
        (("State", "StartedAt"), ""),
        (("HostConfig", "Privileged"), True),
        (("HostConfig", "ReadonlyRootfs"), False),
        (("HostConfig", "CapAdd"), ["NET_ADMIN"]),
        (("HostConfig", "CapDrop"), []),
        (
            ("HostConfig", "SecurityOpt"),
            ["seccomp=unconfined", "no-new-privileges:true"],
        ),
        (("HostConfig", "NetworkMode"), "host"),
        (("HostConfig", "Memory"), 0),
        (("HostConfig", "RestartPolicy", "Name"), "always"),
        (("HostConfig", "PortBindings"), {"3000/tcp": [{"HostPort": "3000"}]}),
        (("Mounts", 0, "Source"), "/other"),
        (("Mounts", 0, "Propagation"), "rshared"),
        (("NetworkSettings", "Networks"), {"foreign": {"NetworkID": "0" * 64}}),
    ],
)
def test_rejects_container_drift(relay, path, value):
    item = relay.record
    for key in path[:-1]:
        item = item[key]
    item[path[-1]] = value
    with pytest.raises(WorkerQuarantined):
        relay.verify()


def test_rejects_adjacent_control_network_member(relay):
    relay.net["Containers"]["2" * 64] = {"Name": "other"}
    with pytest.raises(WorkerQuarantined, match="membership"):
        relay.verify()


def test_rejects_socket_permissions_and_non_socket(relay):
    path = relay.child / "policy.sock"
    path.chmod(0o666)
    with pytest.raises(WorkerQuarantined, match="socket identity"):
        relay.verify()
    path.unlink()
    path.touch()
    with pytest.raises(WorkerQuarantined, match="socket identity"):
        relay.verify()


def test_rejects_restart_during_verification(relay):
    second = copy.deepcopy(relay.record)
    second["State"]["StartedAt"] = "2026-11-27T12:00:01Z"
    with pytest.raises(WorkerQuarantined, match="incarnation changed"):
        relay.verify(second=second)
