from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from commandcore_server.mcp import MODERN_PROTOCOL, MCPHandler, _modernize
from commandcore_server.models import Principal
from commandcore_server.tools import ToolError
from starlette.requests import Request


@pytest.mark.asyncio
async def test_core_surface_lists_only_daily_tools_and_rejects_admin():
    from commandcore_server.tools import CORE_TOOL_DEFINITIONS, CORE_TOOL_NAMES

    handler = MCPHandler(
        SimpleNamespace(),
        SimpleNamespace(inc=lambda name: None),
        "candidate",
        definitions=CORE_TOOL_DEFINITIONS,
        name="CommandCore Core",
    )

    async def request_for(method, params):
        async def receive():
            return {
                "type": "http.request",
                "body": json.dumps(
                    {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
                ).encode(),
                "more_body": False,
            }

        return Request(
            {"type": "http", "method": "POST", "path": "/mcp/core", "headers": []},
            receive,
        )

    response = await handler.handle(
        await request_for("tools/list", {}), Principal("owner")
    )
    assert {
        t["name"] for t in json.loads(response.body)["result"]["tools"]
    } == CORE_TOOL_NAMES
    assert len(CORE_TOOL_NAMES) == 26
    response = await handler.handle(
        await request_for("tools/call", {"name": "system.reboot", "arguments": {}}),
        Principal("owner"),
    )
    assert json.loads(response.body)["result"]["isError"] is True


@pytest.mark.asyncio
async def test_supported_progress_uses_standard_sse_and_final_rpc_result():
    from commandcore_server.activity import notify

    class Tools:
        async def call(self, principal, name, args):
            await notify(
                {"tool": name, "execution_id": "execution", "status": "running"}
            )
            await notify({"tool": name, "execution_id": "execution", "status": "ok"})
            return {"status": "ok", "result": {}}

    handler = MCPHandler(Tools(), SimpleNamespace(inc=lambda name: None), "candidate")
    body = {
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {
            "name": "system.info",
            "arguments": {},
            "_meta": {"progressToken": "fixture-progress"},
        },
    }

    async def receive():
        return {
            "type": "http.request",
            "body": json.dumps(body).encode(),
            "more_body": False,
        }

    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/mcp",
            "headers": [(b"accept", b"application/json, text/event-stream")],
        },
        receive,
    )
    response = await handler.handle(request, Principal("owner"))
    chunks = [chunk async for chunk in response.body_iterator]
    messages = [json.loads(chunk.split("data: ", 1)[1]) for chunk in chunks]
    assert [m["params"]["progress"] for m in messages[:2]] == [0, 1]
    assert all(m["method"] == "notifications/progress" for m in messages[:2])
    assert messages[-1]["id"] == 7
    assert messages[-1]["result"]["isError"] is False


def test_modern_cacheable_result_has_required_fields():
    x = _modernize("tools/list", {"tools": []})
    assert x["resultType"] == "complete"
    assert x["ttlMs"] == 0
    assert x["cacheScope"] == "private"


def test_modern_tool_call_result_gets_result_type_only():
    x = _modernize("tools/call", {"content": []})
    assert x["resultType"] == "complete"
    assert "ttlMs" not in x


def test_tool_definitions_have_mcp_risk_annotations():
    from commandcore_server.tools import TOOL_DEFINITIONS

    by_name = {t["name"]: t for t in TOOL_DEFINITIONS}
    for tool in TOOL_DEFINITIONS:
        assert tool["_meta"]["securitySchemes"] == tool["securitySchemes"]
        for key in ("openai/toolInvocation/invoking", "openai/toolInvocation/invoked"):
            assert 0 < len(tool["_meta"][key]) <= 64
    assert by_name["fs.read"]["annotations"]["readOnlyHint"] is True
    assert by_name["fs.delete"]["annotations"]["destructiveHint"] is True
    assert by_name["shell.exec"]["annotations"]["openWorldHint"] is True
    assert by_name["package.install"]["annotations"]["openWorldHint"] is True


def test_modern_results_can_be_stamped_with_server_info():
    from commandcore_server.mcp import _with_server_info

    out = _with_server_info({"resultType": "complete"}, "0.3.0")
    assert out["_meta"]["io.modelcontextprotocol/serverInfo"] == {
        "name": "commandcore",
        "version": "0.3.0",
    }


@pytest.mark.asyncio
async def test_oauth_scope_failure_gives_mcp_reauthorization_challenge():
    class Tools:
        _required_scope = staticmethod(lambda name: "commandcore:standard")

        async def call(self, principal, name, args):
            raise ToolError("insufficient_scope", "scope required")

    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "shell.exec",
            "arguments": {},
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": MODERN_PROTOCOL,
                "io.modelcontextprotocol/clientCapabilities": {},
            },
        },
    }

    async def receive():
        return {
            "type": "http.request",
            "body": json.dumps(body).encode(),
            "more_body": False,
        }

    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/mcp",
            "headers": [
                (b"mcp-protocol-version", MODERN_PROTOCOL.encode()),
                (b"mcp-method", b"tools/call"),
                (b"mcp-name", b"shell.exec"),
            ],
        },
        receive,
    )
    challenge = 'Bearer resource_metadata="https://mcp.example/.well-known/oauth-protected-resource", scope="commandcore:standard", error="insufficient_scope", error_description="Additional authorization is required for this tool"'
    handler = MCPHandler(
        Tools(),
        SimpleNamespace(inc=lambda name: None),
        "0.9.0-rc1",
        lambda scope: challenge,
    )
    response = await handler.handle(
        request, Principal("user", "client", "oauth2", ("commandcore:read",))
    )
    result = json.loads(response.body)["result"]
    assert result["isError"] is True
    assert result["_meta"]["mcp/www_authenticate"] == [challenge]
    assert "io.modelcontextprotocol/serverInfo" in result["_meta"]
