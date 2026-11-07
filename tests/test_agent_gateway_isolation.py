import asyncio

import pytest
from commandcore_server.agent_gateway import AgentConnection, AgentManager, PendingJob
from commandcore_server.db import Database
from commandcore_server.metrics import Metrics


@pytest.mark.asyncio
async def test_job_output_is_device_scoped(tmp_path):
    db = Database(str(tmp_path / "db.sqlite3"))
    mgr = AgentManager(db, Metrics(), 1024)
    fut = asyncio.get_running_loop().create_future()
    mgr.jobs["e1"] = PendingJob(execution_id="e1", device_id="device-a", future=fut)
    await mgr._handle_output(
        "device-b", {"execution_id": "e1", "stream": "stdout", "data": "spoofed"}
    )
    assert mgr.jobs["e1"].stdout_parts == []
    await mgr._handle_output(
        "device-a", {"execution_id": "e1", "stream": "stdout", "data": "valid"}
    )
    assert mgr.jobs["e1"].stdout_parts == ["valid"]


@pytest.mark.asyncio
async def test_job_result_is_device_scoped(tmp_path):
    db = Database(str(tmp_path / "db.sqlite3"))
    mgr = AgentManager(db, Metrics(), 1024)
    fut = asyncio.get_running_loop().create_future()
    mgr.jobs["e1"] = PendingJob(execution_id="e1", device_id="device-a", future=fut)
    await mgr._handle_result(
        "device-b", {"execution_id": "e1", "status": "ok", "result": {"x": 1}}
    )
    assert not fut.done()
    await mgr._handle_result(
        "device-a", {"execution_id": "e1", "status": "ok", "result": {"x": 1}}
    )
    assert fut.done()
    assert fut.result().result == {"x": 1}


@pytest.mark.asyncio
async def test_request_output_cap_counts_discarded_bytes_and_keeps_valid_utf8(tmp_path):
    manager = AgentManager(Database(str(tmp_path / "db.sqlite3")), Metrics(), 4)
    pending = PendingJob(
        "fixture", "device-a", asyncio.get_running_loop().create_future()
    )
    manager.jobs["fixture"] = pending
    await manager._handle_output("device-a", {"execution_id": "fixture", "data": "€€"})
    await manager._handle_output("device-a", {"execution_id": "fixture", "data": "ab"})
    assert "".join(pending.stdout_parts) == "€a"
    assert pending.output_bytes == 4
    assert pending.observed_output_bytes == 8


@pytest.mark.asyncio
async def test_short_shell_send_lock_wait_is_bounded(tmp_path, monkeypatch):
    from commandcore_server import agent_gateway

    monkeypatch.setattr(agent_gateway, "SHORT_SHELL_SEND_SECONDS", 0.025)
    db = Database(str(tmp_path / "db.sqlite3"))
    registered = db.register_device(
        owner_id="owner",
        display_name="target",
        hostname="target",
        platform="Linux",
        architecture="x86_64",
        agent_version="1",
        agent_protocol_version="1",
        public_key_b64="AAAA",
        capabilities={"shell": True},
        auto_approve=True,
    )
    device_id = registered["device_id"]
    manager = AgentManager(db, Metrics(), 1024)

    class NeverSend:
        async def send_json(self, payload):
            raise AssertionError("send called despite locked socket")

    conn = AgentConnection(device_id=device_id, websocket=NeverSend())
    await conn.send_lock.acquire()
    manager.connections[device_id] = conn
    try:
        result = await asyncio.wait_for(
            manager.dispatch(
                owner_id="owner",
                device={
                    "id": device_id,
                    "display_name": "target",
                    "permission_profile": "STANDARD",
                },
                tool="shell.exec",
                arguments={"command": "not-executed"},
                timeout_ms=8000,
            ),
            timeout=1,
        )
        assert result.status == "agent_disconnected"
        assert result.execution_id not in manager.jobs
    finally:
        conn.send_lock.release()
