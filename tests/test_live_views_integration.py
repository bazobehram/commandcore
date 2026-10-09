"""Prove both independent MCP Apps viewers coexist on one CommandCore surface."""

import json
import unittest
from types import SimpleNamespace

from starlette.requests import Request

from commandcore_server.mcp import (
    ACTIVITY_UI_URI,
    BROWSER_WIDGET_URI,
    COMMANDCORE_UI_URI,
    MCPHandler,
    MODERN_PROTOCOL,
)
from commandcore_server.models import Principal
from commandcore_server.tools import CORE_TOOL_NAMES, TOOL_DEFINITIONS


class FakeTools:
    async def call(self, principal, name, args):
        if name == "activity.watch":
            return {"state": "monitor_ready", "mode": "read_only"}
        if name == "browser.watch":
            return {"state": "viewer_ready", "mode": "read_only"}
        if name == "commandcore.watch":
            return {
                "state": "dashboard_ready",
                "mode": "read_only",
                "browser_available": True,
            }
        raise AssertionError(name)


def rpc(method, params=None):
    data = dict(params or {})
    data["_meta"] = {
        "io.modelcontextprotocol/protocolVersion": MODERN_PROTOCOL,
        "io.modelcontextprotocol/clientCapabilities": {},
    }
    headers = [
        (b"content-type", b"application/json"),
        (b"mcp-protocol-version", MODERN_PROTOCOL.encode()),
        (b"mcp-method", method.encode()),
    ]
    if method == "tools/call":
        headers.append((b"mcp-name", data["name"].encode()))
    body = json.dumps({"jsonrpc": "2.0", "id": 3, "method": method, "params": data})

    async def receive():
        return {"type": "http.request", "body": body.encode(), "more_body": False}

    return Request(
        {"type": "http", "method": "POST", "path": "/mcp/core", "headers": headers},
        receive,
    )


class LiveViewsCombinedTests(unittest.IsolatedAsyncioTestCase):
    async def invoke(self, handler, method, params=None):
        response = await handler.handle(rpc(method, params), Principal("test-user"))
        return json.loads(response.body)["result"]

    async def test_both_activity_tools_on_core_surface(self):
        self.assertTrue(
            {"activity.feed", "activity.watch", "commandcore.watch"} <= CORE_TOOL_NAMES
        )

    async def test_both_resources_and_tool_render_metadata(self):
        definitions = [
            tool
            for tool in TOOL_DEFINITIONS
            if tool["name"] in {"browser.watch", "activity.watch", "commandcore.watch"}
        ]
        server = MCPHandler(
            FakeTools(),
            SimpleNamespace(inc=lambda _key: None),
            "test",
            definitions=definitions,
        )
        tools = (await self.invoke(server, "tools/list"))["tools"]
        assert len(tools) == 3
        byname = {tool["name"]: tool for tool in tools}
        self.assertEqual(
            byname["browser.watch"]["_meta"]["ui"]["resourceUri"], BROWSER_WIDGET_URI
        )
        self.assertEqual(
            byname["commandcore.watch"]["_meta"]["ui"]["resourceUri"],
            COMMANDCORE_UI_URI,
        )
        self.assertEqual(
            byname["activity.watch"]["_meta"]["ui"]["resourceUri"], ACTIVITY_UI_URI
        )
        self.assertEqual(
            byname["browser.watch"]["securitySchemes"][0]["scopes"],
            ["commandcore:standard"],
        )
        self.assertEqual(
            byname["activity.watch"]["securitySchemes"][0]["scopes"],
            ["commandcore:read"],
        )

        resources = await self.invoke(server, "resources/list")
        self.assertEqual(
            {x["uri"] for x in resources["resources"]},
            {ACTIVITY_UI_URI, BROWSER_WIDGET_URI, COMMANDCORE_UI_URI},
        )
        for name, uri, contains in [
            ("browser.watch", BROWSER_WIDGET_URI, "browser.observe"),
            ("activity.watch", ACTIVITY_UI_URI, "activity.feed"),
            ("commandcore.watch", COMMANDCORE_UI_URI, "browser.observe"),
        ]:
            resource = await self.invoke(server, "resources/read", {"uri": uri})
            page = resource["contents"][0]["text"]
            self.assertIn(contains, page)
            self.assertIn("ui/initialize", page)
            rendered = await self.invoke(
                server,
                "tools/call",
                {
                    "name": name,
                    "arguments": {},
                },
            )
            self.assertEqual(rendered["_meta"]["ui"]["resourceUri"], uri)
            self.assertEqual(rendered["_meta"]["openai/outputTemplate"], uri)
            self.assertNotIn("screenshot_base64", str(rendered))


if __name__ == "__main__":
    unittest.main()
