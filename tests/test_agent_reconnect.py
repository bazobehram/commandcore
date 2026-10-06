import asyncio
import base64
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi import WebSocketDisconnect

from commandcore_server.agent_gateway import AgentManager, PendingJob
from commandcore_server.db import Database
from commandcore_server.metrics import Metrics


class Socket:
    def __init__(self, device, key):
        self.device = device
        self.key = key
        self.headers = {
            "authorization": f"Device {device['device_id']}:{device['device_token']}"
        }
        self.client = SimpleNamespace(host="127.0.0.1")
        self.ack = asyncio.Event()
        self.closed = asyncio.Event()
        self.messages = asyncio.Queue()
        self.hello = False

    async def accept(self):
        pass

    async def close(self, code):
        self.closed.set()

    async def send_json(self, message):
        if message["type"] == "challenge":
            self.nonce = message["nonce"]
        if message["type"] == "hello.ack":
            self.ack.set()

    async def receive_json(self):
        if not self.hello:
            self.hello = True
            signed = f"commandcore-agent-auth-v1\n{self.device['device_id']}\n{self.nonce}".encode()
            return {
                "type": "hello",
                "device_id": self.device["device_id"],
                "protocol_version": "1",
                "agent_version": "test",
                "capabilities": {},
                "signature": base64.b64encode(self.key.sign(signed)).decode(),
            }
        item = await self.messages.get()
        if item is None:
            raise WebSocketDisconnect()
        return item


@pytest.mark.asyncio
async def test_delayed_old_disconnect_cannot_offline_replacement(tmp_path):
    db = Database(str(tmp_path / "db.sqlite3"))
    key = Ed25519PrivateKey.generate()
    device = db.register_device(
        owner_id="owner",
        display_name="test",
        hostname="test",
        platform="Linux",
        architecture="x86_64",
        agent_version="test",
        agent_protocol_version="1",
        public_key_b64=base64.b64encode(
            key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        ).decode(),
        capabilities={},
        auto_approve=True,
    )
    manager = AgentManager(db, Metrics(), 1024)
    old, new = Socket(device, key), Socket(device, key)
    tasks = [asyncio.create_task(manager.handle_websocket(old))]
    try:
        await asyncio.wait_for(old.ack.wait(), 2)
        tasks.append(asyncio.create_task(manager.handle_websocket(new)))
        await asyncio.wait_for(new.ack.wait(), 2)
        await asyncio.wait_for(old.closed.wait(), 2)
        job = PendingJob(
            "new-job", device["device_id"], asyncio.get_running_loop().create_future()
        )
        manager.jobs[job.execution_id] = job
        await old.messages.put(None)
        await asyncio.wait_for(tasks[0], 2)
        assert db.get_device_auth_row(device["device_id"])["status"] == "online"
        assert manager.connections[device["device_id"]].websocket is new
        assert not job.future.done()
    finally:
        await new.messages.put(None)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


def test_authenticated_heartbeat_recovers_expired_status_but_not_revocation(tmp_path):
    db = Database(str(tmp_path / "db.sqlite3"))
    device = db.register_device(
        owner_id="owner",
        display_name="test",
        hostname="test",
        platform="Linux",
        architecture="x86_64",
        agent_version="test",
        agent_protocol_version="1",
        public_key_b64="AAAA",
        capabilities={},
        auto_approve=True,
    )
    device_id = device["device_id"]
    db.mark_online(
        device_id,
        ip=None,
        agent_version="test",
        capabilities={},
        agent_protocol_version="1",
    )
    db.expire_stale_devices(float("inf"))
    db.heartbeat(device_id)
    assert db.get_device_auth_row(device_id)["status"] == "online"
    db.revoke_device("owner", device_id)
    db.heartbeat(device_id)
    assert db.get_device_auth_row(device_id)["revoked_at"] is not None
    assert db.get_device_auth_row(device_id)["status"] != "online"
