"""Synthetic Ed25519 proofs and real local Unix sockets; no Docker or OAuth."""

from __future__ import annotations

import base64
import json
import os
import socket
import sys
import time

import pytest
from commandcore_server.browser_errors import BrowserError
from commandcore_server.browser_gateway import BrowserGateway
from commandcore_server.browser_worker_attestation import BrowserAttestationError
from commandcore_server.browser_worker_attestation_ed25519 import (
    Ed25519WorkerAttestationVerifier,
    public_key_for_private_seed,
    write_operator_ed25519_attestation,
)
from commandcore_server.browser_worker_binding import BrowserWorkerBinding
from commandcore_server.browser_worker_orchestrator import PhysicalWorker
from commandcore_server.browser_worker_pool import OwnerBrowserWorkerPool
from commandcore_server.browser_worker_uds_client import WorkerUnixClient

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux Unix sockets")
WORKER = "w-" + "a" * 18
OWNER = ("https://fixture.invalid/", "fixture-owner", "fixture-client")
STAMP = "2026-11-27T12:00:00Z"
SEED = base64.b64encode(bytes(range(32))).decode()


@pytest.fixture
def fixture(tmp_path, monkeypatch):
    monkeypatch.setenv("COMMANDCORE_BROWSER_JOURNAL_DIR", str(tmp_path / "journals"))
    tmp_path.chmod(0o700)
    root = tmp_path / "s"
    root.mkdir(mode=0o700)
    directory = root / WORKER
    directory.mkdir(mode=0o700)
    physical = PhysicalWorker(
        worker_id=WORKER,
        generation="b" * 32,
        steel_name="ccbw-steel-" + WORKER,
        steel_container_id="c" * 64,
        boundary_name="ccbw-boundary-" + WORKER,
        boundary_container_id="d" * 64,
        isolated_network="ccbw-isolated-" + WORKER,
        control_network="ccbw-control-" + WORKER,
        outbound_network="ccbw-outbound-" + WORKER,
        isolated_network_id="e" * 64,
        control_network_id="f" * 64,
        outbound_network_id="1" * 64,
        steel_image_id="sha256:" + "2" * 64,
        boundary_image_id="sha256:" + "3" * 64,
    )
    evidence = {
        "worker_id": WORKER,
        "generation": physical.generation,
        "relay_container_id": "4" * 64,
        "relay_image_id": "sha256:" + "5" * 64,
        "relay_started_at": STAMP,
    }
    sockets = []
    binding = None
    try:
        previous = os.getcwd()
        try:
            os.chdir(directory)
            for service in ("steel", "policy"):
                sock = socket.socket(socket.AF_UNIX)
                sockets.append(sock)
                sock.bind(service + ".sock")
                os.chmod(service + ".sock", 0o660)
                info = os.stat(service + ".sock")
                evidence[f"relay_{service}_dev"] = str(info.st_dev)
                evidence[f"relay_{service}_ino"] = str(info.st_ino)
        finally:
            os.chdir(previous)
        proof = tmp_path / "proof.json"

        def publish(relays=None, now=None):
            write_operator_ed25519_attestation(
                str(proof),
                SEED,
                [physical],
                started_at_by_worker={WORKER: STAMP},
                verified_relays=relays,
                now=now,
            )

        publish({WORKER: evidence})
        verifier = Ed25519WorkerAttestationVerifier(
            str(proof), public_key_for_private_seed(SEED)
        )
        binding = BrowserWorkerBinding.provision(
            str(tmp_path / "binding.sqlite3"), WORKER, "fixture-only-" * 4
        )
        binding.claim(OWNER)
        gateway = BrowserGateway(
            base_url=f"http://ccctl-{WORKER}:3000",
            cdp_url=f"ws://ccctl-{WORKER}:3000",
            egress_proxy_url="http://browser-boundary:8080",
            egress_policy_url=f"http://ccctl-{WORKER}:8080",
            allow_hosts=("example.com",),
            worker_binding=binding,
        )
        gateway.control_relay = WorkerUnixClient(
            str(root), WORKER, operator_uid=os.getuid(), operator_gid=os.getgid()
        )
        pool = OwnerBrowserWorkerPool([gateway], attestation=verifier)
        yield pool, gateway, evidence, publish, verifier, proof, directory
    finally:
        if binding:
            binding.close()
        for sock in sockets:
            sock.close()


def test_signed_relay_v2_allows_only_bound_owner(fixture):
    pool, _, evidence, _, verifier, _, _ = fixture
    assert (
        verifier.verify(WORKER)["relay_container_id"] == evidence["relay_container_id"]
    )
    assert pool.available(*OWNER)
    assert not pool.available(OWNER[0], "other-owner", OWNER[2])


def test_legacy_proof_remains_valid_for_private_but_denies_relay(fixture):
    pool, gateway, _, publish, verifier, _, _ = fixture
    assert pool.available(*OWNER)
    gateway.sessions[OWNER] = object()
    publish()
    assert "relay_container_id" not in verifier.verify(WORKER)
    assert not pool.available(*OWNER)
    assert not gateway.sessions
    gateway.control_relay = None
    assert pool.available(*OWNER)


@pytest.mark.parametrize(
    "field,value",
    [
        ("relay_container_id", "6" * 64),
        ("relay_image_id", "sha256:" + "7" * 64),
        ("relay_started_at", "2026-11-27T12:00:01Z"),
        ("relay_policy_ino", "123456789"),
    ],
)
def test_changed_signed_identity_denies_and_clears_session(fixture, field, value):
    pool, gateway, evidence, publish, _, _, _ = fixture
    assert pool.available(*OWNER)
    gateway.sessions[OWNER] = object()
    publish({WORKER: {**evidence, field: value}})
    assert not pool.available(*OWNER)
    assert not gateway.sessions


def test_socket_replacement_without_new_proof_denied(fixture):
    pool, gateway, _, _, _, _, directory = fixture
    assert pool.available(*OWNER)
    gateway.sessions[OWNER] = object()
    path = directory / "steel.sock"
    path.rename(directory / "original.sock")
    with socket.socket(socket.AF_UNIX) as replacement:
        previous = os.getcwd()
        try:
            os.chdir(directory)
            replacement.bind("steel.sock")
            path.chmod(0o660)
        finally:
            os.chdir(previous)
        assert not pool.available(*OWNER)
        assert not gateway.sessions


def test_tampered_and_expired_proof_denied(fixture):
    pool, gateway, evidence, publish, _, proof, _ = fixture
    assert pool.available(*OWNER)
    gateway.sessions[OWNER] = object()
    document = json.loads(proof.read_text())
    document["workers"][0]["relay_container_id"] = "9" * 64
    proof.write_text(json.dumps(document))
    assert not pool.available(*OWNER)
    assert not gateway.sessions
    publish({WORKER: evidence}, now=int(time.time()) - 60)
    assert not pool.available(*OWNER)


def test_writer_rejects_missing_or_foreign_evidence(fixture):
    _, _, evidence, publish, _, _, _ = fixture
    for bad in (
        {},
        {WORKER: {**evidence, "generation": "0" * 32}},
        {WORKER: {**evidence, "relay_image_id": "latest"}},
    ):
        with pytest.raises(BrowserAttestationError):
            publish(bad)


def test_relay_requires_signed_proof_even_without_attestation(fixture):
    pool, gateway, _, _, _, _, _ = fixture
    gateway.sessions[OWNER] = object()
    pool.attestation = None
    with pytest.raises(BrowserError, match="signed physical proof"):
        pool._find_worker(OWNER)
    assert not gateway.sessions


@pytest.mark.asyncio
async def test_result_withheld_when_signed_relay_changes_during_action(
    fixture, monkeypatch
):
    pool, gateway, evidence, publish, _, _, _ = fixture

    async def action(**kwargs):
        gateway.sessions[OWNER] = object()
        publish({WORKER: {**evidence, "relay_started_at": "2026-11-27T12:00:01Z"}})
        return {"screenshot": "fixture-must-not-be-returned"}

    monkeypatch.setattr(gateway, "call", action)
    with pytest.raises(BrowserError, match="incarnation changed"):
        await pool.call(
            subject=OWNER[1],
            issuer=OWNER[0],
            client_id=OWNER[2],
            name="browser.screenshot",
            args={},
        )
    assert not gateway.sessions
