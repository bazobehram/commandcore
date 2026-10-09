"""Protocol compatibility tests for the opt-in CommandCore MCP Apps viewer."""

import json
import unittest
from types import SimpleNamespace

from starlette.requests import Request

from commandcore_server.browser_gateway import BROWSER_TOOL_NAMES
from commandcore_server.mcp import BROWSER_WIDGET_URI, MCPHandler, MODERN_PROTOCOL
from commandcore_server.models import Principal
from commandcore_server.tools import TOOL_DEFINITIONS


def rpc_request(method: str, params: dict | None = None):
    args = dict(params or {})
    args.setdefault(
        "_meta",
        {
            "io.modelcontextprotocol/protocolVersion": MODERN_PROTOCOL,
            "io.modelcontextprotocol/clientCapabilities": {},
        },
    )
    headers = [
        (b"content-type", b"application/json"),
        (b"mcp-protocol-version", MODERN_PROTOCOL.encode()),
        (b"mcp-method", method.encode()),
    ]
    if method == "tools/call":
        headers.append((b"mcp-name", args["name"].encode()))
    data = json.dumps({"jsonrpc": "2.0", "id": 9, "method": method, "params": args})

    async def receive():
        return {"type": "http.request", "body": data.encode(), "more_body": False}

    return Request(
        {"type": "http", "method": "POST", "path": "/mcp/core", "headers": headers},
        receive,
    )


class FakeTools:
    async def call(self, principal, name, args):
        if name == "browser.watch":
            return {"state": "viewer_ready", "mode": "read_only"}
        raise AssertionError(f"unexpected tool call: {name}")


def mcp_handler(with_widget: bool):
    definitions = [
        tool
        for tool in TOOL_DEFINITIONS
        if tool["name"] in BROWSER_TOOL_NAMES
        and (with_widget or tool["name"] != "browser.watch")
    ]
    return MCPHandler(
        FakeTools(),
        SimpleNamespace(inc=lambda _: None),
        "preview",
        definitions=definitions,
    )


class BrowserWidgetProtocolTests(unittest.IsolatedAsyncioTestCase):
    async def invoke(self, handler, method: str, params: dict | None = None):
        response = await handler.handle(rpc_request(method, params), Principal("owner"))
        return json.loads(response.body)

    async def test_resource_not_exposed_on_unconfigured_surface(self):
        old = mcp_handler(False)
        tools = (await self.invoke(old, "tools/list"))["result"]["tools"]
        self.assertNotIn("browser.watch", {tool["name"] for tool in tools})
        resource = await self.invoke(old, "resources/read", {"uri": BROWSER_WIDGET_URI})
        self.assertEqual(resource["error"]["code"], -32601)

    async def test_mcp_resource_listing_read_and_metadata(self):
        server = mcp_handler(True)
        listed = (await self.invoke(server, "tools/list"))["result"]["tools"]
        watch = next(tool for tool in listed if tool["name"] == "browser.watch")
        self.assertEqual(watch["_meta"]["ui"]["resourceUri"], BROWSER_WIDGET_URI)
        self.assertEqual(watch["_meta"]["openai/outputTemplate"], BROWSER_WIDGET_URI)
        self.assertEqual(
            watch["_meta"]["securitySchemes"][0]["scopes"], ["commandcore:standard"]
        )

        resources = (await self.invoke(server, "resources/list"))["result"]
        self.assertEqual(resources["resources"][0]["uri"], BROWSER_WIDGET_URI)

        read = (
            await self.invoke(server, "resources/read", {"uri": BROWSER_WIDGET_URI})
        )["result"]["contents"][0]
        self.assertEqual(read["uri"], BROWSER_WIDGET_URI)
        self.assertEqual(read["mimeType"], "text/html;profile=mcp-app")
        self.assertIn("CommandCore Browser", read["text"])
        self.assertIn("tools/call", read["text"])
        self.assertIn("ui/initialize", read["text"])
        self.assertIn("ui/notifications/initialized", read["text"])
        self.assertIn("browser.observe", read["text"])
        self.assertIn("browser.handoff", read["text"])
        self.assertIn("fullscreen", read["_meta"]["openai/ui"]["availableDisplayModes"])

        bad = await self.invoke(server, "resources/read", {"uri": "ui://unexpected"})
        self.assertEqual(bad["error"]["code"], -32002)

    async def test_watch_render_tool_has_widget_meta_no_image(self):
        server = mcp_handler(True)
        resp = (
            await self.invoke(
                server, "tools/call", {"name": "browser.watch", "arguments": {}}
            )
        )["result"]
        self.assertEqual(resp["structuredContent"]["state"], "viewer_ready")
        self.assertEqual(resp["_meta"]["ui"]["resourceUri"], BROWSER_WIDGET_URI)
        self.assertEqual(resp["_meta"]["openai/outputTemplate"], BROWSER_WIDGET_URI)
        self.assertTrue(all(item["type"] == "text" for item in resp["content"]))


if __name__ == "__main__":
    unittest.main()
