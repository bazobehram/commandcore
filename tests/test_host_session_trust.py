"""Known host-session trust gap; remove xfail only after an authenticated binding."""

import json
import uuid

import pytest
from starlette.requests import Request

from commandcore_server.mcp import MCPHandler
from commandcore_server.metrics import Metrics
from commandcore_server.models import Principal
from commandcore_server.tools import ToolService


class UnauthenticatedSessionSpoof(Exception):
    pass


@pytest.mark.asyncio
@pytest.mark.xfail(
    strict=True,
    raises=UnauthenticatedSessionSpoof,
    reason="openai/session is caller-supplied and not authenticated",
)
async def test_known_session_value_cannot_impersonate_another_conversation(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("COMMANDCORE_UI_TASK_DB", str(tmp_path / "tasks.sqlite3"))

    class DB:
        def list_accessible_devices(self, subject):
            return [
                {
                    "id": "device-a",
                    "permission_profile": "STANDARD",
                    "access_max_permission_profile": "STANDARD",
                    "capabilities": {},
                }
            ]

        def add_audit(self, **kwargs):
            return 1

    principal = Principal(
        "owner", "client", "oauth2", ("commandcore:standard",), "https://idp.test"
    )
    service = ToolService(DB(), None, 60)
    handler = MCPHandler(service, Metrics(), "candidate")
    operation = str(uuid.uuid4())
    assert service.timeline.begin(
        principal, "victim-session", operation, "shell.exec", {"command": "hostname"}
    )
    service.timeline.device(operation, "device-a")
    service.timeline.finish(operation, status="ok", exit_code=0, duration_ms=1)

    async def request(session):
        async def receive():
            body = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "execution.timeline",
                    "arguments": {},
                    "_meta": {"openai/session": session},
                },
            }
            return {
                "type": "http.request",
                "body": json.dumps(body).encode(),
                "more_body": False,
            }

        response = await handler.handle(
            Request(
                {"type": "http", "method": "POST", "path": "/mcp", "headers": []},
                receive,
            ),
            principal,
        )
        return json.loads(response.body)["result"]["structuredContent"]["events"]

    assert not await request("other-session")
    # Same OAuth identity and known copied metadata are not proof of host context.
    if await request("victim-session"):
        raise UnauthenticatedSessionSpoof


@pytest.mark.asyncio
@pytest.mark.xfail(
    strict=True,
    raises=UnauthenticatedSessionSpoof,
    reason="activity conversation metadata is not authenticated",
)
async def test_known_session_value_cannot_impersonate_activity_conversation():
    class DB:
        def list_accessible_devices(self, subject):
            return [{"id": "device-a", "display_name": "Fixture"}]

        def recent_audit(self, subject, limit):
            return []

        def add_audit(self, **kwargs):
            return 1

    principal = Principal(
        "owner", "client", "oauth2", ("commandcore:standard",), "https://idp.test"
    )
    service = ToolService(DB(), None, 60)
    op = service.live_activity.begin(
        principal, "shell.exec", {"command": "hostname"}, host_session="victim-session"
    )
    service.live_activity.set_device(op, "device-a")
    service.live_activity.finish(op, status="ok")
    args = {"view": "conversation", "include_details": True}
    other = await service.call(
        principal, "activity.feed", args, host_session="other-session"
    )
    assert not any(e.get("operation_id") == op for e in other["events"])
    spoofed = await service.call(
        principal, "activity.feed", args, host_session="victim-session"
    )
    if any(e.get("operation_id") == op for e in spoofed["events"]):
        raise UnauthenticatedSessionSpoof


@pytest.mark.xfail(
    strict=True,
    raises=UnauthenticatedSessionSpoof,
    reason="Browser conversation metadata is not authenticated",
)
def test_known_session_value_cannot_impersonate_browser_conversation():
    from types import SimpleNamespace
    from commandcore_server.tools import ToolError

    principal = Principal(
        "owner", "client", "oauth2", ("commandcore:standard",), "https://idp.test"
    )
    service = ToolService(None, None, 60)
    service.browser = SimpleNamespace(sessions={})
    service._browser_scope_args(principal, "browser.open", {}, "victim-session")
    with pytest.raises(ToolError, match="Another conversation"):
        service._browser_scope_args(principal, "browser.close", {}, "other-session")
    try:
        service._browser_scope_args(principal, "browser.close", {}, "victim-session")
    except ToolError:
        return
    # The gate accepted the copied metadata; no Browser worker was started.
    raise UnauthenticatedSessionSpoof
