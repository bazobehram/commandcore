"""Operator signer tests with synthetic registry and Docker inspection."""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from commandcore_server.browser_worker_attestation import BrowserAttestationError
from commandcore_server.browser_worker_attestation_ed25519 import (
    Ed25519WorkerAttestationVerifier,
    public_key_for_private_seed,
)
from commandcore_server.browser_worker_orchestrator import (
    PhysicalWorker,
    WorkerQuarantined,
)

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import browser_relay_proof_operator as signer

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux operator")
SEED = base64.b64encode(bytes(range(32))).decode()
STAMP = "2026-11-28T10:00:00Z"


@pytest.fixture
def state(tmp_path, monkeypatch):
    root = tmp_path / "registry"
    root.mkdir(mode=0o700)
    worker = PhysicalWorker(
        worker_id="w-" + "a" * 18,
        generation="b" * 32,
        steel_name="ccbw-steel-a",
        steel_container_id="1" * 64,
        boundary_name="ccbw-boundary-a",
        boundary_container_id="2" * 64,
        isolated_network="ccbw-isolated-a",
        isolated_network_id="3" * 64,
        control_network="ccbw-control-a",
        control_network_id="4" * 64,
        outbound_network="ccbw-outbound-a",
        outbound_network_id="5" * 64,
        steel_image_id="sha256:" + "6" * 64,
        boundary_image_id="sha256:" + "7" * 64,
    )
    relay = {
        "container_id": "8" * 64,
        "image_id": "sha256:" + "9" * 64,
        "socket_root": str(tmp_path / "sockets"),
        "operator_uid": 994,
        "operator_gid": 987,
        "api_uid": 10001,
        "api_gid": 999,
    }
    entry = {
        "state": "active",
        "worker_id": worker.worker_id,
        "physical": vars(worker),
        "relay": relay,
    }
    registry = root / "registry.json"
    destination = tmp_path / "proof.json"

    def store(entries):
        registry.write_text(json.dumps({"workers": entries}))
        registry.chmod(0o600)

    store([entry])
    networks = {
        worker.isolated_network: {
            "Id": worker.isolated_network_id,
            "Containers": {
                worker.steel_container_id: {},
                worker.boundary_container_id: {},
            },
        },
        worker.outbound_network: {
            "Id": worker.outbound_network_id,
            "Containers": {worker.boundary_container_id: {}},
        },
    }
    docker = SimpleNamespace(
        inspect=lambda name: (
            {
                "Id": worker.steel_container_id,
                "State": {"Running": True, "StartedAt": STAMP},
            }
            if name == worker.steel_name
            else {
                "Id": worker.boundary_container_id,
                "Mounts": [],
                "HostConfig": {"Tmpfs": {"/data": "ro,nosuid,nodev,noexec,size=1m"}},
            }
        ),
        inspect_network=lambda name: networks[name],
    )
    monkeypatch.setattr(signer, "verify_physical_worker", lambda *_a: None)

    def verify(physical, _docker, **kwargs):
        assert physical == worker and kwargs["container_id"] == relay["container_id"]
        assert isinstance(kwargs["socket_root"], Path)
        return {
            "worker_id": worker.worker_id,
            "generation": worker.generation,
            "relay_container_id": relay["container_id"],
            "relay_image_id": relay["image_id"],
            "relay_started_at": STAMP,
            "relay_steel_dev": "1",
            "relay_steel_ino": "2",
            "relay_policy_dev": "1",
            "relay_policy_ino": "3",
        }

    monkeypatch.setattr(signer, "verify_physical_relay", verify)
    verifier = Ed25519WorkerAttestationVerifier(
        str(destination), public_key_for_private_seed(SEED)
    )
    return SimpleNamespace(
        worker=worker,
        entry=entry,
        store=store,
        docker=docker,
        networks=networks,
        verifier=verifier,
        destination=destination,
        run=lambda: signer.reconcile_once(
            root, destination, SEED, proof_gid=None, docker=docker
        ),
    )


def test_signs_fresh_v2_and_withdraws_stopped_worker(state):
    assert state.run() == 1
    assert (
        state.verifier.verify(state.worker.worker_id)["relay_container_id"] == "8" * 64
    )
    state.entry["state"] = "stopping"
    state.store([state.entry])
    assert state.run() == 0
    with pytest.raises(BrowserAttestationError):
        state.verifier.verify(state.worker.worker_id)


@pytest.mark.parametrize(
    "fault", ["extra-member", "relay", "duplicate", "slow", "restart", "missing-relay"]
)
def test_observed_failure_replaces_old_proof_with_signed_empty(
    state, monkeypatch, fault
):
    assert state.run() == 1
    if fault == "extra-member":
        state.networks[state.worker.isolated_network]["Containers"]["foreign"] = {}
    elif fault == "relay":

        def deny(*_a, **_kw):
            raise WorkerQuarantined("fixture relay mismatch")

        monkeypatch.setattr(signer, "verify_physical_relay", deny)
    elif fault == "duplicate":
        state.store([state.entry, state.entry])
    elif fault == "slow":
        clock = iter([0.0, 7.0])
        monkeypatch.setattr(signer.time, "monotonic", lambda: next(clock))
    elif fault == "restart":
        stamps = iter([STAMP, "2026-11-28T10:00:01Z"])
        monkeypatch.setattr(signer, "_steel_stamp", lambda *_a: next(stamps))
    else:
        state.entry.pop("relay")
        state.store([state.entry])
    assert state.run() == 0
    assert json.loads(state.destination.read_text())["version"] == 2
    with pytest.raises(BrowserAttestationError):
        state.verifier.verify(state.worker.worker_id)


def test_seed_reader_rejects_world_readable_and_symlink(tmp_path):
    key = tmp_path / "fixture"
    key.write_text(SEED)
    key.chmod(0o600)
    assert signer.read_seed(key) == SEED
    key.chmod(0o644)
    with pytest.raises(BrowserAttestationError):
        signer.read_seed(key)
    key.chmod(0o600)
    alias = tmp_path / "alias"
    alias.symlink_to(key)
    with pytest.raises(BrowserAttestationError):
        signer.read_seed(alias)


@pytest.mark.parametrize(
    "tmpfs,mounts",
    [
        (None, []),
        ({"/data": "rw"}, []),
        (
            {"/data": "ro,nosuid,nodev,noexec,size=1m"},
            [{"Type": "volume", "Destination": "/data"}],
        ),
    ],
)
def test_boundary_persistent_mount_denies_proof(state, tmpfs, mounts):
    assert state.run() == 1
    original = state.docker.inspect

    def inspect(name):
        record = original(name)
        if name == state.worker.boundary_name:
            record["HostConfig"]["Tmpfs"] = tmpfs
            record["Mounts"] = mounts
        return record

    state.docker.inspect = inspect
    assert state.run() == 0
    with pytest.raises(BrowserAttestationError):
        state.verifier.verify(state.worker.worker_id)
