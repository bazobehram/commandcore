"""Operator provisioning must not reassign OAuth owners, even after retirement."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from contextlib import contextmanager
from pathlib import Path

import pytest
from commandcore_server.browser_worker_binding import BrowserWorkerBinding
from commandcore_server.browser_worker_orchestrator import WorkerQuarantined


def _load_operator():
    path = Path(__file__).resolve().parents[1] / "scripts/browser_worker_lifecycle.py"
    spec = importlib.util.spec_from_file_location(
        "commandcore_operator_lifecycle_test", path
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("prior_state", ["active", "stopped", "retired"])
def test_existing_oauth_owner_cannot_be_provisioned_again(
    tmp_path, monkeypatch, prior_state
):
    module = _load_operator()
    tmp_path.chmod(0o700)
    key = "synthetic-test-only-binding-key-long-enough"
    owner = {
        "issuer": "https://review.invalid/",
        "subject": "owner-one",
        "client_id": "review-client",
    }
    owner_file = tmp_path / "owner.json"
    owner_file.write_text(json.dumps(owner))
    owner_file.chmod(0o600)
    binding_file = tmp_path / "binding.sqlite3"
    ledger = BrowserWorkerBinding.provision(
        str(binding_file), "w-111111111111111111", key
    )
    ledger.claim((owner["issuer"], owner["subject"], owner["client_id"]))
    ledger.close()
    entries = [
        {
            "worker_id": "w-111111111111111111",
            "state": prior_state,
            "route": {"binding_path": str(binding_file)},
        }
    ]

    @contextmanager
    def isolated_state(_root):
        yield entries

    monkeypatch.setattr(module, "exclusive_state", isolated_state)
    monkeypatch.setattr(module, "inspect_image", lambda _: "sha256:" + "a" * 64)
    seccomp = tmp_path / "seccomp.json"
    seccomp.write_text("{}")
    monkeypatch.setattr(module, "SECCOMP_PROFILE", seccomp)
    monkeypatch.setattr(
        module,
        "SECCOMP_SOURCE_SHA256",
        hashlib.sha256(seccomp.read_bytes()).hexdigest(),
    )

    with pytest.raises(
        WorkerQuarantined, match="already has a browser worker assignment"
    ):
        module.provision(
            tmp_path, owner_file, "example.com", "mock:steel", "mock:boundary", key
        )
    assert entries[0]["state"] == prior_state

    binding_file.unlink()
    with pytest.raises(WorkerQuarantined, match="ledger cannot be verified"):
        module.provision(
            tmp_path, owner_file, "example.com", "mock:steel", "mock:boundary", key
        )


@pytest.fixture
def relay_lifecycle(tmp_path, monkeypatch):
    from types import SimpleNamespace

    module = _load_operator()
    worker_id = "w-" + "a" * 18
    physical = module.PhysicalWorker(
        worker_id=worker_id,
        generation="b" * 32,
        steel_name="ccbw-steel-" + worker_id,
        steel_container_id="1" * 64,
        boundary_name="ccbw-boundary-" + worker_id,
        boundary_container_id="2" * 64,
        isolated_network="ccbw-isolated-" + worker_id,
        control_network="ccbw-control-" + worker_id,
        outbound_network="ccbw-outbound-" + worker_id,
        isolated_network_id="3" * 64,
        control_network_id="4" * 64,
        outbound_network_id="5" * 64,
        steel_image_id="sha256:" + "6" * 64,
        boundary_image_id="sha256:" + "7" * 64,
    )
    relay = {
        "container_id": "8" * 64,
        "image_id": "sha256:" + "9" * 64,
        "socket_root": str(tmp_path),
        "operator_uid": 994,
        "operator_gid": 987,
        "api_uid": 10001,
        "api_gid": 999,
    }
    entry = {
        "worker_id": worker_id,
        "physical": vars(physical),
        "state": "stopped",
        "relay": relay,
        "route": {},
    }
    entries = [entry]
    running = {}
    calls = []
    ids = {
        physical.steel_name: physical.steel_container_id,
        physical.boundary_name: physical.boundary_container_id,
        "ccbw-relay-" + worker_id: relay["container_id"],
    }

    def inspect(name):
        cid = ids[name]
        return {
            "Id": cid,
            "Name": "/" + name,
            "Image": relay["image_id"],
            "State": {"Running": running.get(cid, False)},
            "Config": {
                "Labels": {
                    module.MARK + ".preview": "1",
                    module.MARK + ".worker": worker_id,
                    module.MARK + ".generation": physical.generation,
                    module.MARK + ".role": "relay",
                }
            },
        }

    def command(*args):
        calls.append(args)
        if args[0] in ("start", "stop"):
            running[args[-1]] = args[0] == "start"

    @contextmanager
    def state(_root):
        yield entries

    monkeypatch.setattr(module, "exclusive_state", state)
    monkeypatch.setattr(module, "DockerCli", lambda: SimpleNamespace(inspect=inspect))
    monkeypatch.setattr(module, "verify_physical_worker", lambda *_a, **_kw: None)
    monkeypatch.setattr(module, "command", command)
    monkeypatch.setattr(module, "_relay_ready", lambda *_a: calls.append(("verify",)))
    monkeypatch.setattr(
        module, "stored", lambda *_a: calls.append(("publish", entry["state"]))
    )
    return SimpleNamespace(
        module=module,
        root=tmp_path,
        physical=physical,
        relay=relay,
        entry=entry,
        entries=entries,
        calls=calls,
        running=running,
    )


def test_relay_start_stop_retire_order(relay_lifecycle):
    f = relay_lifecycle
    p = f.physical
    cid = f.relay["container_id"]
    f.module.transition(f.root, p.worker_id, "start", active_limit=2)
    assert f.calls == [
        ("start", p.boundary_container_id),
        ("start", p.steel_container_id),
        ("start", cid),
        ("verify",),
        ("publish", "active"),
    ]
    f.calls.clear()
    f.module.transition(f.root, p.worker_id, "stop")
    assert f.calls == [
        ("publish", "stopping"),
        ("stop", "--time", "3", cid),
        ("stop", "--time", "3", p.steel_container_id),
        ("stop", "--time", "3", p.boundary_container_id),
        ("publish", "stopped"),
    ]
    f.calls.clear()
    f.module.transition(f.root, p.worker_id, "retire")
    assert f.calls[:4] == [
        ("publish", "retired"),
        ("rm", cid),
        ("rm", p.steel_container_id),
        ("rm", p.boundary_container_id),
    ]


def test_relay_capacity_before_start(relay_lifecycle):
    f = relay_lifecycle
    f.entries.append({"worker_id": "other", "state": "active"})
    with pytest.raises(WorkerQuarantined, match="capacity"):
        f.module.transition(f.root, f.physical.worker_id, "start", active_limit=1)
    assert f.calls == []


def test_relay_stale_socket_prevents_start(relay_lifecycle):
    f = relay_lifecycle
    directory = f.root / f.physical.worker_id
    directory.mkdir()
    (directory / "steel.sock").touch()
    with pytest.raises(WorkerQuarantined, match="stale relay sockets"):
        f.module.transition(f.root, f.physical.worker_id, "start")
    assert f.calls == []


def test_failed_relay_verification_does_not_publish(relay_lifecycle, monkeypatch):
    f = relay_lifecycle

    def deny(*_args):
        raise WorkerQuarantined("relay unavailable")

    monkeypatch.setattr(f.module, "_relay_ready", deny)
    monkeypatch.setattr(
        f.module.subprocess, "run", lambda args, **_kw: f.calls.append(tuple(args))
    )
    with pytest.raises(WorkerQuarantined, match="relay unavailable"):
        f.module.transition(f.root, f.physical.worker_id, "start")
    assert f.entry["state"] == "stopped"
    assert all(call[0] != "publish" for call in f.calls)
    assert f.calls[-3:] == [
        ("docker", "stop", "--time", "3", f.relay["container_id"]),
        ("docker", "stop", "--time", "3", f.physical.steel_container_id),
        ("docker", "stop", "--time", "3", f.physical.boundary_container_id),
    ]


def test_running_relay_cannot_be_retired(relay_lifecycle):
    f = relay_lifecycle
    f.running[f.relay["container_id"]] = True
    with pytest.raises(WorkerQuarantined, match="relay must be stopped"):
        f.module.transition(f.root, f.physical.worker_id, "retire")
    assert f.calls == []


def test_stop_failure_stays_unpublished_and_reserves_capacity(
    relay_lifecycle, monkeypatch
):
    f = relay_lifecycle
    f.entry["state"] = "active"
    original = f.module.command

    def fail(*args):
        if args[0] == "stop":
            raise WorkerQuarantined("fixture stop failure")
        return original(*args)

    monkeypatch.setattr(f.module, "command", fail)
    with pytest.raises(WorkerQuarantined, match="stop failure"):
        f.module.transition(f.root, f.physical.worker_id, "stop")
    assert f.entry["state"] == "stopping"
    assert f.calls == [("publish", "stopping")]
    with pytest.raises(WorkerQuarantined, match="capacity"):
        f.module._active_capacity(f.entries, 1)
    monkeypatch.setattr(f.module, "command", original)
    f.module.transition(f.root, f.physical.worker_id, "stop")
    assert f.entry["state"] == "stopped"


def test_create_relay_uses_only_pinned_worker_network_and_image(
    relay_lifecycle, monkeypatch
):
    import os

    f = relay_lifecycle
    uid = os.geteuid() or 10001
    gid = os.getegid() or 999
    root = f.root / "relay"
    root.mkdir(mode=0o750)
    if os.geteuid() == 0:
        os.chown(root, uid, gid)
    root.chmod(0o750)
    config = {
        **f.relay,
        "socket_root": str(root),
        "operator_uid": uid,
        "operator_gid": gid,
        "api_uid": uid + 1,
    }
    cid = config.pop("container_id")
    original = f.module.command

    def create(*args):
        original(*args)
        return cid

    monkeypatch.setattr(f.module, "command", create)
    created = []
    record = f.module._create_relay(f.physical, config, created)
    assert record["container_id"] == cid and created == [cid]
    args = f.calls[0]
    assert args[args.index("--network") + 1] == f.physical.control_network
    assert args[args.index("--entrypoint") + 2] == config["image_id"]
    assert "--read-only" in args and "--privileged" not in args
    assert args.count("--mount") == 1
    assert "--no-healthcheck" in args
    assert "/data:ro,nosuid,nodev,noexec,size=1m" in args
    assert f.calls[1:] == [("start", cid), ("verify",)]
