from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from commandcore_server.agent_gateway import AgentConnection, AgentManager
from commandcore_server.db import Database
from commandcore_server.metrics import Metrics
from commandcore_agent.state import (
    AgentState,
    begin_key_rotation,
    load,
    promote_pending_key,
    save,
)


def pair():
    private = Ed25519PrivateKey.generate()
    private_b64 = base64.b64encode(
        private.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
    ).decode()
    public_b64 = base64.b64encode(
        private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    ).decode()
    return private, private_b64, public_b64


class FakeWebSocket:
    def __init__(self):
        self.sent = []

    async def send_json(self, payload):
        self.sent.append(payload)


@pytest.mark.asyncio
async def test_two_phase_device_key_rotation_requires_both_keys(tmp_path):
    old, _, old_pub = pair()
    new, _, new_pub = pair()
    db = Database(str(tmp_path / "db.sqlite3"))
    reg = db.register_device(
        owner_id="owner",
        display_name="d",
        hostname="d",
        platform="Linux",
        architecture="x86_64",
        agent_version="0.5.0",
        agent_protocol_version="1",
        public_key_b64=old_pub,
        capabilities={},
        auto_approve=True,
    )
    mgr = AgentManager(db, Metrics(), 4096)
    ws = FakeWebSocket()
    conn = AgentConnection(reg["device_id"], ws)
    nonce = "rotation-nonce"
    proof = f"commandcore-key-rotation-prepare-v1\n{reg['device_id']}\n{nonce}\n{new_pub}".encode()
    await mgr._handle_key_rotation_prepare(
        conn,
        reg["device_id"],
        nonce,
        {
            "type": "device.key.rotate.prepare",
            "request_id": "r1",
            "new_public_key_b64": new_pub,
            "old_signature": base64.b64encode(old.sign(proof)).decode(),
            "new_signature": base64.b64encode(new.sign(proof)).decode(),
        },
    )
    prepared = ws.sent[-1]
    assert prepared["type"] == "device.key.rotate.prepared"
    assert db.get_device_auth_row(reg["device_id"])["public_key_b64"] == old_pub

    rotation_id = prepared["rotation_id"]
    confirm = f"commandcore-key-rotation-confirm-v1\n{reg['device_id']}\n{rotation_id}".encode()
    await mgr._handle_key_rotation_confirm(
        conn,
        reg["device_id"],
        {
            "type": "device.key.rotate.confirm",
            "request_id": "r2",
            "rotation_id": rotation_id,
            "new_signature": base64.b64encode(new.sign(confirm)).decode(),
        },
    )
    ack = ws.sent[-1]
    assert ack["type"] == "device.key.rotate.ack"
    assert ack["key_generation"] == 2
    row = db.get_device_auth_row(reg["device_id"])
    assert row["public_key_b64"] == new_pub
    assert row["previous_public_key_b64"] == old_pub
    assert row["pending_public_key_b64"] is None


@pytest.mark.asyncio
async def test_key_rotation_rejects_missing_old_key_proof(tmp_path):
    old, _, old_pub = pair()
    new, _, new_pub = pair()
    db = Database(str(tmp_path / "db.sqlite3"))
    reg = db.register_device(
        owner_id="owner",
        display_name="d",
        hostname="d",
        platform="Linux",
        architecture="x86_64",
        agent_version="0.5.0",
        agent_protocol_version="1",
        public_key_b64=old_pub,
        capabilities={},
        auto_approve=True,
    )
    mgr = AgentManager(db, Metrics(), 4096)
    ws = FakeWebSocket()
    conn = AgentConnection(reg["device_id"], ws)
    proof = f"commandcore-key-rotation-prepare-v1\n{reg['device_id']}\nn\n{new_pub}".encode()
    await mgr._handle_key_rotation_prepare(
        conn,
        reg["device_id"],
        "n",
        {
            "request_id": "x",
            "new_public_key_b64": new_pub,
            "old_signature": base64.b64encode(new.sign(proof)).decode(),
            "new_signature": base64.b64encode(new.sign(proof)).decode(),
        },
    )
    assert ws.sent[-1]["type"] == "device.key.rotate.error"
    assert db.pending_device_key_rotation(reg["device_id"]) is None


def test_agent_state_rotation_is_crash_recoverable_and_atomic(tmp_path):
    path = tmp_path / "agent.json"
    state = AgentState(
        "d", "t" * 40, "oldpriv", "oldpub", "https://api", "wss://agent", "d"
    )
    save(state, path)
    begin_key_rotation(
        state, private_key_b64="newpriv", public_key_b64="newpub", rotation_id="rot"
    )
    save(state, path)
    reloaded = load(path)
    assert reloaded.private_key_b64 == "oldpriv"
    assert reloaded.pending_private_key_b64 == "newpriv"
    promote_pending_key(reloaded, key_generation=2)
    save(reloaded, path)
    final = load(path)
    assert final.private_key_b64 == "newpriv"
    assert final.public_key_b64 == "newpub"
    assert final.key_generation == 2
    assert final.pending_private_key_b64 is None


def test_expired_pending_rotation_is_cleared_and_does_not_stick(tmp_path):
    old, _, old_pub = pair()
    _new, _, new_pub = pair()
    db = Database(str(tmp_path / "db.sqlite3"))
    reg = db.register_device(
        owner_id="owner",
        display_name="d",
        hostname="d",
        platform="Linux",
        architecture="x86_64",
        agent_version="0.5.0",
        agent_protocol_version="1",
        public_key_b64=old_pub,
        capabilities={},
        auto_approve=True,
    )
    prepared = db.prepare_device_key_rotation(reg["device_id"], old_pub, new_pub)
    with db.lock:
        db.conn.execute(
            "UPDATE devices SET pending_key_expires_at=? WHERE id=?",
            (0.0, reg["device_id"]),
        )
        db.conn.commit()
    assert prepared["rotation_id"]
    # Public metadata must not show an already-expired rotation as pending.
    assert db.get_device(reg["device_id"])["key_rotation_pending"] is False
    assert db.pending_device_key_rotation(reg["device_id"]) is None
    row = db.get_device_auth_row(reg["device_id"])
    assert row["pending_public_key_b64"] is None
    assert row["pending_key_rotation_id"] is None


@pytest.mark.asyncio
async def test_agent_rotate_key_recovers_when_server_forgot_stale_pending(
    tmp_path, monkeypatch
):
    import argparse
    import commandcore_agent.cli as cli

    old, old_priv, old_pub = pair()
    _pending, pending_priv, pending_pub = pair()
    path = tmp_path / "agent.json"
    state = AgentState(
        "device-1",
        "t" * 40,
        old_priv,
        old_pub,
        "https://api.example",
        "wss://agent.example/agent",
        "device-1",
    )
    begin_key_rotation(
        state,
        private_key_b64=pending_priv,
        public_key_b64=pending_pub,
        rotation_id="stale-rotation",
    )
    save(state, path)

    class FakeSocket:
        def __init__(self, responses):
            self.responses = list(responses)
            self.sent = []
            self.closed = False

        async def send(self, payload):
            self.sent.append(__import__("json").loads(payload))

        async def recv(self):
            return __import__("json").dumps(self.responses.pop(0))

        async def close(self):
            self.closed = True

    stale_ws = FakeSocket(
        [
            {"type": "device.key.rotate.error", "error": "key_rotation_not_pending"},
        ]
    )
    fresh_ws = FakeSocket(
        [
            {
                "type": "device.key.rotate.prepared",
                "rotation_id": "fresh-rotation",
                "current_generation": 1,
            },
            {
                "type": "device.key.rotate.ack",
                "rotation_id": "fresh-rotation",
                "key_generation": 2,
            },
        ]
    )
    calls = []

    async def fake_connect(current_state, private_key_b64):
        calls.append(private_key_b64)
        # First call tries the stale pending identity; the server has not promoted it.
        if len(calls) == 1:
            raise RuntimeError("device_signature_invalid")
        # Second call authenticates old key and discovers stale pending server state.
        if len(calls) == 2:
            return stale_ws, {"key_rotation_nonce": "nonce-stale", "key_generation": 1}
        # Recursive fresh attempt uses the still-valid old key.
        return fresh_ws, {"key_rotation_nonce": "nonce-fresh", "key_generation": 1}

    monkeypatch.setattr(cli, "_connect_authenticated", fake_connect)
    rc = await cli._rotate_key_async(argparse.Namespace(state=str(path)))
    assert rc == 0
    final = load(path)
    assert final.key_generation == 2
    assert final.pending_private_key_b64 is None
    assert final.private_key_b64 != old_priv
    assert len(calls) == 3
