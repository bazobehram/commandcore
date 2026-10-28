from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from commandcore_server.mcp import MODERN_PROTOCOL, MCPHandler, _modernize
from commandcore_server.models import Principal
from commandcore_server.tools import ToolError
from starlette.requests import Request


@pytest.mark.asyncio
@pytest.mark.parametrize("protocol", ["2025-11-25", "2025-06-18", MODERN_PROTOCOL])
async def test_brand_icon_discovery_preserves_older_protocols(protocol):
    icons = [
        {"src": "https://control.example/commandcore-icon.png", "mimeType": "image/png"}
    ]
    handler = MCPHandler(
        SimpleNamespace(), SimpleNamespace(inc=lambda _: None), "candidate", icons=icons
    )
    modern = protocol == MODERN_PROTOCOL
    method = "server/discover" if modern else "initialize"
    params = {"protocolVersion": protocol}
    headers = []
    if modern:
        params = {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": protocol,
                "io.modelcontextprotocol/clientCapabilities": {},
            }
        }
        headers = [
            (b"mcp-protocol-version", protocol.encode()),
            (b"mcp-method", method.encode()),
        ]

    async def receive():
        return {
            "type": "http.request",
            "body": json.dumps(
                {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
            ).encode(),
        }

    response = await handler.handle(
        Request(
            {"type": "http", "method": "POST", "path": "/mcp", "headers": headers},
            receive,
        ),
        Principal("owner"),
    )
    result = json.loads(response.body)["result"]
    instructions = result["instructions"]
    assert "browser.watch" in instructions
    assert "shell.exec without commandcore.watch" in instructions
    assert "explicitly requested aggregate task" in instructions
    info = (
        result["_meta"]["io.modelcontextprotocol/serverInfo"]
        if modern
        else result["serverInfo"]
    )
    assert info["name"] == "commandcore"
    if protocol == "2025-06-18":
        assert "icons" not in info
    else:
        assert info["icons"] == icons


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
    } == CORE_TOOL_NAMES | {
        "commandcore.viewer",
        "commandcore.finish",
        "commandcore.workspace",
        "operation.render",
        "shell.native",
    }
    assert len(CORE_TOOL_NAMES) == 50
    response = await handler.handle(
        await request_for("tools/call", {"name": "system.reboot", "arguments": {}}),
        Principal("owner"),
    )
    assert json.loads(response.body)["result"]["isError"] is True


@pytest.mark.asyncio
async def test_oauth_discovery_preserves_browser_close_safety_contract():
    handler = MCPHandler(
        SimpleNamespace(), SimpleNamespace(inc=lambda _: None), "candidate"
    )

    async def receive():
        return {
            "type": "http.request",
            "body": json.dumps(
                {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
            ).encode(),
            "more_body": False,
        }

    request = Request(
        {"type": "http", "method": "POST", "path": "/mcp", "headers": []},
        receive,
    )
    principal = Principal(
        "owner", "client", "oauth2", ("commandcore:standard",), "https://idp.test"
    )
    response = await handler.handle(request, principal)
    tools = json.loads(response.body)["result"]["tools"]
    close = next(tool for tool in tools if tool["name"] == "browser.close")
    assert close["inputSchema"] == {
        "type": "object",
        "properties": {
            "session_ref": {"type": "string", "maxLength": 128},
            "expected_session_id": {"type": "string", "minLength": 1, "maxLength": 128},
        },
        "required": [],
        "additionalProperties": False,
    }
    assert {"type": "oauth2", "scopes": ["commandcore:standard"]} in close[
        "securitySchemes"
    ]


@pytest.mark.asyncio
async def test_supported_progress_uses_standard_sse_and_final_rpc_result():
    from commandcore_server.activity import notify

    class Tools:
        live_activity = SimpleNamespace(
            issue_viewer=lambda principal, session: {"fixture": True},
            session_tag=lambda session: None,
        )

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


@pytest.mark.asyncio
async def test_discovery_preserves_independent_shell_and_browser_guidance():
    handler = MCPHandler(
        SimpleNamespace(), SimpleNamespace(inc=lambda _: None), "candidate"
    )
    descriptions = {
        entry["name"]: entry["description"] for entry in handler.definitions
    }
    assert "explicitly requested" in descriptions["commandcore.watch"]
    for tool in ("shell.exec", "browser.open"):
        assert "do not start commandcore.watch automatically" in descriptions[tool]
        assert "per-operation terminal widget" in descriptions["shell.exec"]
        assert "Before a new user device/Browser task" not in descriptions[tool]


@pytest.mark.asyncio
async def test_standalone_resources_resolve_for_existing_cards():
    from commandcore_server.mcp import ACTIVITY_UI_URI, BROWSER_WIDGET_URI

    handler = MCPHandler(
        SimpleNamespace(), SimpleNamespace(inc=lambda _: None), "candidate"
    )
    definitions = {entry["name"]: entry for entry in handler.definitions}
    assert (
        definitions["browser.watch"]["_meta"]["ui"]["resourceUri"] == BROWSER_WIDGET_URI
    )
    assert (
        definitions["activity.watch"]["_meta"]["ui"]["resourceUri"] == ACTIVITY_UI_URI
    )
    assert ACTIVITY_UI_URI != BROWSER_WIDGET_URI
    for uri, view in ((BROWSER_WIDGET_URI, "browser"), (ACTIVITY_UI_URI, "activity")):

        async def receive():
            return {
                "type": "http.request",
                "body": json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "resources/read",
                        "params": {"uri": uri},
                    }
                ).encode(),
            }

        response = await handler.handle(
            Request(
                {"type": "http", "method": "POST", "path": "/mcp", "headers": []},
                receive,
            ),
            Principal(
                "owner",
                "client",
                "oauth2",
                ("commandcore:standard",),
                "https://issuer.test",
            ),
        )
        content = json.loads(response.body)["result"]["contents"][0]
        assert content["uri"] == uri
        assert f'function select(view){{view="{view}";' in content["text"]


@pytest.mark.asyncio
async def test_operation_card_resource_display_metadata():
    from commandcore_server.mcp import RENDER_UI_URI, SHELL_UI_URI, TIMELINE_UI_URI

    handler = MCPHandler(
        SimpleNamespace(), SimpleNamespace(inc=lambda _: None), "candidate"
    )
    owner = Principal(
        "owner", "client", "oauth2", ("commandcore:standard",), "https://issuer.test"
    )

    async def invoke(method, params):
        async def receive():
            return {
                "type": "http.request",
                "body": json.dumps(
                    {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
                ).encode(),
            }

        response = await handler.handle(
            Request(
                {"type": "http", "method": "POST", "path": "/mcp", "headers": []},
                receive,
            ),
            owner,
        )
        return json.loads(response.body)["result"]

    listed = {
        item["uri"]: item["_meta"]
        for item in (await invoke("resources/list", {}))["resources"]
    }
    for uri, height in (
        (RENDER_UI_URI, 180),
        (TIMELINE_UI_URI, 520),
        (SHELL_UI_URI, None),
    ):
        metadata = (await invoke("resources/read", {"uri": uri}))["contents"][0][
            "_meta"
        ]
        for meta in (listed[uri], metadata):
            assert meta["openai/ui"] == {
                "availableDisplayModes": ["inline"],
                "preferredDisplayMode": "inline",
            }
            if height is not None:
                assert meta["openai/widgetHeightHint"] == height
                assert meta["openai/widgetMinFrameHeight"] == 1
            else:
                assert "openai/widgetHeightHint" not in meta
