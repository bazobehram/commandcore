"""Compare authenticated MCP discovery with the observed production contract."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from starlette.requests import Request

from commandcore_server.mcp import MCPHandler
from commandcore_server.metrics import Metrics
from commandcore_server.models import Principal


@pytest.mark.asyncio
async def test_authenticated_discovery_preserves_live_tools_and_cards(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("COMMANDCORE_UI_TASK_DB", str(tmp_path / "tasks.sqlite3"))
    baseline = json.loads(
        (
            Path(__file__).parent / "fixtures/private-production-mcp-discovery.json"
        ).read_text()
    )
    handler = MCPHandler(SimpleNamespace(), Metrics(), "candidate")

    async def receive():
        return {
            "type": "http.request",
            "body": json.dumps(
                {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
            ).encode(),
            "more_body": False,
        }

    principal = Principal(
        "owner", "client", "oauth2", ("commandcore:standard",), "https://idp.test"
    )
    request = Request(
        {"type": "http", "method": "POST", "path": "/mcp", "headers": []}, receive
    )
    response = await handler.handle(request, principal)
    tools = json.loads(response.body)["result"]["tools"]
    actual = {item["name"]: item for item in tools}
    assert len(actual) == len(tools), "duplicate discovered names"
    missing = sorted(baseline.keys() - actual.keys())
    unexpected = sorted(actual.keys() - baseline.keys())
    changed = sorted(
        name
        for name in baseline.keys() & actual.keys()
        if baseline[name]["schema"] != actual[name]["inputSchema"]
    )
    missing_cards = sorted(
        name
        for name in baseline.keys() & actual.keys()
        if baseline[name]["uri"]
        and not actual[name].get("_meta", {}).get("ui", {}).get("resourceUri")
    )
    assert not missing and not unexpected and not changed and not missing_cards, (
        f"missing={missing}, unexpected={unexpected}, changed_schemas={changed}, missing_cards={missing_cards}"
    )

    # Discovery may advertise a new version to avoid host caches; previously
    # issued card URIs must remain resolvable to an authenticated caller.
    for name, contract in baseline.items():
        uri = contract["uri"]
        if not uri:
            continue

        async def read():
            return {
                "type": "http.request",
                "body": json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 2,
                        "method": "resources/read",
                        "params": {"uri": uri},
                    }
                ).encode(),
                "more_body": False,
            }

        response = await handler.handle(
            Request(
                {"type": "http", "method": "POST", "path": "/mcp", "headers": []}, read
            ),
            principal,
        )
        result = json.loads(response.body)
        assert "error" not in result, f"captured card unavailable: {name}"
        resource = result["result"]["contents"][0]
        assert resource["uri"] == uri
        assert resource["mimeType"] == "text/html;profile=mcp-app"
        assert "<html" in resource["text"].lower()


@pytest.mark.asyncio
async def test_shell_native_uses_existing_authorized_execution_path(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("COMMANDCORE_UI_TASK_DB", str(tmp_path / "tasks.sqlite3"))
    from commandcore_server.tools import ToolError

    class FakeTools:
        async def call(self, principal, name, args, host_session=None):
            assert name == "shell.exec"
            assert args == {"command": "hostname"}
            raise ToolError("permission_denied")

    handler = MCPHandler(FakeTools(), Metrics(), "candidate")
    with pytest.raises(ToolError, match="permission_denied"):
        await handler._call_tools(
            Principal("owner"), "shell.native", {"command": "hostname"}, None
        )
    native = next(
        tool for tool in handler.definitions if tool["name"] == "shell.native"
    )
    assert native["_meta"]["ui"] == {"visibility": ["model"]}
    assert native["_meta"]["openai/widgetAccessible"] is False


@pytest.mark.asyncio
async def test_operation_render_denies_cross_conversation_identity_and_revoked_grant(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("COMMANDCORE_UI_TASK_DB", str(tmp_path / "tasks.sqlite3"))
    from commandcore_server.live_activity import LiveActivity
    from commandcore_server.tools import ToolError

    principal = Principal(
        "owner", "client", "oauth2", ("commandcore:standard",), "https://idp.test"
    )
    live = LiveActivity()
    db = SimpleNamespace(list_accessible_devices=lambda _: [{"id": "device-a"}])
    handler = MCPHandler(
        SimpleNamespace(live_activity=live, db=db), Metrics(), "candidate"
    )
    operation = live.begin(
        principal, "shell.exec", {"command": "hostname"}, host_session="chat-a"
    )
    live.set_device(operation, "device-a")
    live.finish(operation, status="ok", exit_code=0)
    result = await handler._call_tools(
        principal, "operation.render", {"operation_id": operation}, "chat-a"
    )
    assert result["operation"]["operation_id"] == operation
    assert result["operation"]["output_available"] is False
    assert "stdout" not in result["operation"] and "command" not in result["operation"]
    with pytest.raises(ToolError, match="Operation unavailable"):
        await handler._call_tools(
            principal, "operation.render", {"operation_id": operation}, "chat-b"
        )
    other = Principal(
        "other", "client", "oauth2", ("commandcore:standard",), "https://idp.test"
    )
    with pytest.raises(ToolError, match="Operation unavailable"):
        await handler._call_tools(
            other, "operation.render", {"operation_id": operation}, "chat-a"
        )
    db.list_accessible_devices = lambda _: []
    with pytest.raises(ToolError, match="Operation unavailable"):
        await handler._call_tools(
            principal, "operation.render", {"operation_id": operation}, "chat-a"
        )


def test_shell_card_preserves_results_without_exposing_sensitive_preview():
    from commandcore_server.mcp import _safe_shell_card_command, _tool_result

    operation = {
        "tool": "shell.exec",
        "operation_id": "12345678-1234-4234-8234-123456789abc",
        "status": "ok",
        "device": "fixture",
    }
    command = _safe_shell_card_command({"command": "hostname"})
    payload = {
        "_ui_operation": operation,
        "_ui_shell_command": command,
        "stdout": "fixture\ntoken=hidden",
        "stderr": "",
        "exit_code": 0,
    }
    card = _tool_result(payload, False)["structuredContent"]["shell_card"]
    assert card["command"] == "hostname" and card["status"] == "completed"
    assert "token=hidden" not in card["stdout"] and "[REDACTED]" in card["stdout"]
    for unsafe in (
        {"command": "cat ~/.ssh/id_ed25519"},
        {"command": "hostname", "env": {"TOKEN": "secret"}},
        {"command": "echo password=secret"},
    ):
        assert _safe_shell_card_command(unsafe) is None
        protected = _tool_result({**payload, "_ui_shell_command": None}, False)[
            "structuredContent"
        ]["shell_card"]
        assert protected["command"] == protected["stdout"] == protected["stderr"] == ""


@pytest.mark.asyncio
async def test_shell_native_propagates_oauth_scope_challenge(tmp_path, monkeypatch):
    monkeypatch.setenv("COMMANDCORE_UI_TASK_DB", str(tmp_path / "tasks.sqlite3"))
    from commandcore_server.tools import ToolError

    class DeniedTools:
        live_activity = SimpleNamespace(session_tag=lambda _: None)

        async def call(self, principal, name, args, host_session=None):
            assert name == "shell.exec"
            raise ToolError("insufficient_scope")

        def _required_scope(self, name):
            assert name == "shell.exec"
            return "commandcore:standard"

    handler = MCPHandler(
        DeniedTools(),
        Metrics(),
        "candidate",
        scope_challenge=lambda scope: "scope=" + scope,
    )

    async def receive():
        body = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "shell.native", "arguments": {"command": "hostname"}},
        }
        return {
            "type": "http.request",
            "body": json.dumps(body).encode(),
            "more_body": False,
        }

    principal = Principal(
        "owner", "client", "oauth2", ("commandcore:read",), "https://idp.test"
    )
    request = Request(
        {"type": "http", "method": "POST", "path": "/mcp", "headers": []}, receive
    )
    result = json.loads((await handler.handle(request, principal)).body)["result"]
    assert result["isError"]
    assert result["_meta"]["mcp/www_authenticate"] == ["scope=commandcore:standard"]
