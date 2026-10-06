from __future__ import annotations


import pytest

from commandcore_server.db import Database
from commandcore_server.models import JobResult, Principal
from commandcore_server.tools import ToolService


class FakeAgents:
    def __init__(self):
        self.last_device = None

    async def dispatch(self, *, owner_id, device, tool, arguments, timeout_ms):
        self.last_device = device["id"]
        return JobResult(
            execution_id="exec-1", status="ok", result={"ok": True}, exit_code=0
        )


def create_device(db, name):
    x = db.register_device(
        owner_id="owner",
        display_name=name,
        hostname=name,
        platform="Linux",
        architecture="x86_64",
        agent_version="0.1.0",
        agent_protocol_version="1",
        public_key_b64="AAAA",
        capabilities={"filesystem": True, "privileged_helper": False},
        auto_approve=True,
    )
    db.mark_online(
        x["device_id"],
        ip="127.0.0.1",
        agent_version="0.1.0",
        capabilities={"filesystem": True},
        agent_protocol_version="1",
    )
    return x["device_id"]


@pytest.mark.asyncio
async def test_selection_and_explicit_device_override(tmp_path):
    db = Database(str(tmp_path / "db.sqlite3"))
    agents = FakeAgents()
    svc = ToolService(db, agents, 60)
    a = create_device(db, "a")
    b = create_device(db, "b")
    principal = Principal("owner", "test-client")
    selected = await svc.call(principal, "devices.select", {"device": a})
    await svc.call(
        principal,
        "system.info",
        {"selection_id": selected["selection_id"], "device_id": b},
    )
    assert agents.last_device == b


@pytest.mark.asyncio
async def test_audit_record_created(tmp_path):
    db = Database(str(tmp_path / "db.sqlite3"))
    agents = FakeAgents()
    svc = ToolService(db, agents, 60)
    a = create_device(db, "a")
    principal = Principal("owner", "test-client")
    await svc.call(principal, "system.info", {"device_id": a})
    events = db.recent_audit("owner")
    assert events and events[0]["tool"] == "system.info"
    assert events[0]["device_id"] == a
    assert events[0]["execution_id"] == "exec-1"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "tool,args",
    [
        ("process.list", {"contains_any": ["python", "compiler"]}),
        ("fs.search", {"root": "/tmp", "query": "probe", "exclude_dirs": ["target"]}),
    ],
)
async def test_older_agent_never_silently_ignores_narrowing_arguments(
    tmp_path, tool, args
):
    from commandcore_server.tools import ToolError

    db = Database(str(tmp_path / "db.sqlite3"))
    agents = FakeAgents()
    service = ToolService(db, agents, 60)
    device = create_device(db, "old-agent")
    with pytest.raises(ToolError) as error:
        await service.call(
            Principal("owner", "test-client"), tool, {"device_id": device, **args}
        )
    assert error.value.code == "unsupported_argument"
    assert agents.last_device is None
