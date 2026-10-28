import json
import uuid
from types import SimpleNamespace

import pytest
from starlette.requests import Request

from commandcore_server.execution_timeline import LiveExecutionTimeline
from commandcore_server.live_activity import LiveActivity
from commandcore_server.mcp import MCPHandler, TIMELINE_UI_URI
from commandcore_server.models import Principal
from commandcore_server.tools import ToolError, ToolService


OWNER = Principal(
    "owner", "client", "oauth2", ("commandcore:standard",), "https://idp.test"
)
DEVICE = {
    "id": "device-a",
    "permission_profile": "STANDARD",
    "access_max_permission_profile": "STANDARD",
    "capabilities": {"local_max_permission_profile": "STANDARD"},
}


def test_timeline_limits_identity_grants_and_output():
    activity = LiveActivity()
    timeline = LiveExecutionTimeline(activity.session_tag)
    operation = str(uuid.uuid4())
    assert timeline.begin(
        OWNER, "chat-a", operation, "shell.exec", {"command": "hostname"}
    )
    timeline.device(operation, "device-a")
    timeline.output(operation, "stdout", "host\ntoken=secret-value")
    timeline.finish(operation, status="ok", exit_code=0, duration_ms=3)
    events = timeline.read(OWNER, "chat-a", [DEVICE])["events"]
    assert events and "secret-value" not in json.dumps(events)
    assert "[REDACTED]" in json.dumps(events)
    assert not timeline.read(OWNER, "chat-b", [DEVICE])["events"]
    other = Principal(
        "other", "client", "oauth2", ("commandcore:standard",), "https://idp.test"
    )
    assert not timeline.read(other, "chat-a", [DEVICE])["events"]
    assert timeline.read(other, "chat-a", [DEVICE])["latest_sequence"] == 0
    assert timeline.read(OWNER, "chat-b", [DEVICE])["latest_sequence"] == 0
    other_operation = str(uuid.uuid4())
    assert timeline.begin(
        other, "chat-a", other_operation, "shell.exec", {"command": "hostname"}
    )
    timeline.device(other_operation, "device-a")
    assert timeline.read(other, "chat-a", [DEVICE])["events"][0]["seq"] == 1
    assert not timeline.read(OWNER, "chat-a", [])["events"]
    assert not timeline.read(OWNER, "chat-a", [{**DEVICE, "revoked_at": 1}])["events"]
    assert not timeline.read(
        OWNER, "chat-a", [{**DEVICE, "access_max_permission_profile": "READ_ONLY"}]
    )["events"]
    assert not timeline.read(
        OWNER, "chat-a", [{**DEVICE, "permission_profile": "READ_ONLY"}]
    )["events"]
    assert not timeline.read(
        OWNER,
        "chat-a",
        [{**DEVICE, "capabilities": {"local_max_permission_profile": "READ_ONLY"}}],
    )["events"]
    with pytest.raises(PermissionError):
        timeline.read(
            Principal(
                "owner", "client", "oauth2", ("commandcore:read",), "https://idp.test"
            ),
            "chat-a",
            [DEVICE],
        )
    with pytest.raises(ValueError):
        timeline.read(OWNER, "chat-a", [DEVICE], limit=101)
    hidden = str(uuid.uuid4())
    timeline.begin(
        OWNER, "chat-a", hidden, "shell.exec", {"command": "cat private.txt"}
    )
    timeline.device(hidden, "device-a")
    timeline.output(hidden, "stdout", "private-content")
    assert "private-content" not in json.dumps(timeline.read(OWNER, "chat-a", [DEVICE]))


class FakeDB:
    def list_accessible_devices(self, subject):
        return [DEVICE] if subject == "owner" else []

    def add_audit(self, **kwargs):
        return 1


@pytest.mark.asyncio
async def test_timeline_viewer_is_bound_to_principal_and_conversation():
    svc = ToolService(FakeDB(), None, 60)
    ref = (
        await svc.call(OWNER, "execution.timeline.watch", {}, host_session="chat-a")
    )["session_ref"]
    assert "events" in await svc.call(OWNER, "execution.timeline", {"session_ref": ref})
    with pytest.raises(ToolError, match="another conversation"):
        await svc.call(
            OWNER, "execution.timeline", {"session_ref": ref}, host_session="chat-b"
        )
    other = Principal(
        "other", "client", "oauth2", ("commandcore:standard",), "https://idp.test"
    )
    with pytest.raises(ToolError):
        await svc.call(other, "execution.timeline", {"session_ref": ref})
    with pytest.raises(ToolError):
        await svc.call(
            Principal("owner"), "execution.timeline.watch", {}, host_session="chat-a"
        )


@pytest.mark.asyncio
async def test_oauth_discovery_and_resource_keep_timeline_card():
    handler = MCPHandler(
        SimpleNamespace(), SimpleNamespace(inc=lambda _: None), "candidate"
    )

    async def invoke(method, params):
        async def receive():
            return {
                "type": "http.request",
                "body": json.dumps(
                    {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
                ).encode(),
                "more_body": False,
            }

        request = Request(
            {"type": "http", "method": "POST", "path": "/mcp", "headers": []}, receive
        )
        return json.loads((await handler.handle(request, OWNER)).body)["result"]

    definitions = {
        entry["name"]: entry for entry in (await invoke("tools/list", {}))["tools"]
    }
    watch = definitions["execution.timeline.watch"]
    assert watch["_meta"]["ui"]["resourceUri"] == TIMELINE_UI_URI
    assert watch["securitySchemes"] == [
        {"type": "oauth2", "scopes": ["commandcore:standard"]}
    ]
    html = (await invoke("resources/read", {"uri": TIMELINE_UI_URI}))["contents"][0][
        "text"
    ]
    assert 'callTool("execution.timeline"' in html
    assert "!sessionRef" in html


@pytest.mark.asyncio
async def test_device_call_records_authorized_timeline_and_rechecks_grant(tmp_path):
    from commandcore_server.db import Database
    from commandcore_server.models import JobResult

    class Agent:
        async def dispatch(self, **kwargs):
            return JobResult("execution", "ok", {}, 0, stdout="fixture-host\n")

    db = Database(str(tmp_path / "timeline.sqlite3"))
    result = db.register_device(
        owner_id="owner",
        display_name="fixture",
        hostname="fixture",
        platform="Linux",
        architecture="x86_64",
        agent_version="1",
        agent_protocol_version="1",
        public_key_b64="AAAA",
        capabilities={},
        auto_approve=True,
    )
    device = result["device_id"]
    db.mark_online(
        device,
        ip="127.0.0.1",
        agent_version="1",
        capabilities={},
        agent_protocol_version="1",
    )
    svc = ToolService(db, Agent(), 60)
    response = await svc.call(
        OWNER,
        "shell.exec",
        {"device_id": device, "command": "hostname"},
        host_session="chat-a",
    )
    assert response["stdout"] == "fixture-host\n"
    rows = (await svc.call(OWNER, "execution.timeline", {}, host_session="chat-a"))[
        "events"
    ]
    assert {row["kind"] for row in rows} >= {"started", "device", "output", "finished"}
    assert "fixture-host" in json.dumps(rows)
    assert (await svc.call(OWNER, "execution.timeline", {}, host_session="chat-b"))[
        "events"
    ] == []
    db.conn.execute(
        "UPDATE devices SET revoked_at = ? WHERE id = ?", ("2026-01-01", device)
    )
    db.conn.commit()
    assert (await svc.call(OWNER, "execution.timeline", {}, host_session="chat-a"))[
        "events"
    ] == []


@pytest.mark.asyncio
async def test_timeline_scope_and_verified_client_contract():
    service = ToolService(FakeDB(), None, 60)
    reader = Principal(
        "owner", "client", "oauth2", ("commandcore:read",), "https://idp.test"
    )
    for tool in ("execution.timeline", "execution.timeline.watch"):
        assert service._required_scope(tool) == "commandcore:standard"
        with pytest.raises(ToolError, match="requires OAuth scope"):
            await service.call(reader, tool, {}, host_session="chat-a")

    for client_id in ("", "unknown", "oauth-client"):
        unverified = Principal(
            "owner", client_id, "oauth2", ("commandcore:standard",), "https://idp.test"
        )
        with pytest.raises(ToolError, match="insufficient_scope"):
            await service.call(
                unverified, "execution.timeline.watch", {}, host_session="chat-a"
            )

    result = await service.call(
        OWNER, "execution.timeline.watch", {}, host_session="chat-a"
    )
    assert result["session_available"] is True
    assert result["session_ref"]


@pytest.mark.parametrize("tool", ["shell.exec", "process.start"])
@pytest.mark.parametrize(
    "override",
    [
        {"env": {"PATH": "/tmp/fixture"}},
        {"env": {"BASH_ENV": "/tmp/fixture"}},
        {"cwd": "/tmp/fixture"},
    ],
)
def test_timeline_hides_allowlisted_command_output_with_execution_overrides(
    tool, override
):
    activity = LiveActivity()
    timeline = LiveExecutionTimeline(activity.session_tag)
    operation = str(uuid.uuid4())
    assert timeline.begin(
        OWNER, "chat-a", operation, tool, {"command": "hostname", **override}
    )
    timeline.device(operation, "device-a")
    timeline.output(operation, "stdout", "fixture-private-output")
    timeline.finish(operation, status="ok", exit_code=0, duration_ms=1)
    events = timeline.read(OWNER, "chat-a", [DEVICE])["events"]
    assert events[0]["summary"]["output_policy"] == "hidden"
    assert "fixture-private-output" not in json.dumps(events)
    assert not any(event["kind"] == "output" for event in events)


@pytest.mark.asyncio
async def test_path_override_can_change_allowlisted_command_output(tmp_path):
    import os
    from commandcore_agent.executor import Executor

    if os.name != "posix":
        pytest.skip("POSIX shell fixture")
    executable = tmp_path / "hostname"
    executable.write_text("#!/bin/sh\nprintf fixture-private-output\\n\n")
    executable.chmod(0o700)
    args = {"command": "hostname", "env": {"PATH": str(tmp_path)}}
    activity = LiveActivity()
    timeline = LiveExecutionTimeline(activity.session_tag)
    operation = str(uuid.uuid4())
    assert timeline.begin(OWNER, "chat-a", operation, "shell.exec", args)
    timeline.device(operation, "device-a")
    shell_output = []

    async def on_output(stream, chunk):
        shell_output.append(chunk)
        timeline.output(operation, stream, chunk)

    result = await Executor()._shell_exec(operation, args, on_output)
    timeline.finish(
        operation, status="ok", exit_code=result["exit_code"], duration_ms=1
    )
    assert result["exit_code"] == 0
    assert "fixture-private-output" in "".join(shell_output)
    assert "fixture-private-output" not in json.dumps(
        timeline.read(OWNER, "chat-a", [DEVICE])
    )
