import asyncio

import pytest

from commandcore_server.agent_gateway import AgentManager, PendingJob
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
