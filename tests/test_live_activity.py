"""MCP Apps live activity and owner isolation acceptance."""

import asyncio
import json
import unittest
from types import SimpleNamespace

from starlette.requests import Request

from commandcore_server.live_activity import LiveActivity
from commandcore_server.mcp import MCPHandler, MODERN_PROTOCOL, ACTIVITY_UI_URI
from commandcore_server.models import Principal, JobResult
from commandcore_server.tools import ToolService


class FakeDb:
    def __init__(self):
        self.audits = []
        self.devices = {
            "alice": [self.device("box-a", "test-node-a")],
            "bob": [self.device("box-b", "bob-pc")],
        }

    @staticmethod
    def device(uid, name):
        return {
            "id": uid,
            "revoked_at": None,
            "display_name": name,
            "status": "online",
            "permission_profile": "STANDARD",
            "access_max_permission_profile": "STANDARD",
            "capabilities": {"local_max_permission_profile": "STANDARD"},
        }

    def list_accessible_devices(self, owner):
        return self.devices.get(owner, [])

    def get_accessible_device(self, owner, device_id):
        return next(
            (d for d in self.devices.get(owner, []) if d["id"] == device_id), None
        )

    def recent_audit(self, owner, limit=100):
        return [a for a in reversed(self.audits) if a["user_id"] == owner][:limit]

    def add_audit(self, **kwargs):
        self.audits.append(
            {
                "id": len(self.audits) + 1,
                "timestamp": "2026-10-08T18:00:00+00:00",
                **kwargs,
            }
        )


class FakeAgents:
    def __init__(self):
        self.started = asyncio.Event()
        self.release = asyncio.Event()

    async def dispatch(self, **kwargs):
        self.started.set()
        await self.release.wait()
        return JobResult(
            execution_id="job-1", status="ok", result={"ok": True}, exit_code=0
        )


def rpc(method, params=None):
    params = dict(params or {})
    params["_meta"] = {
        "io.modelcontextprotocol/protocolVersion": MODERN_PROTOCOL,
        "io.modelcontextprotocol/clientCapabilities": {},
    }
    headers = [
        (b"mcp-protocol-version", MODERN_PROTOCOL.encode()),
        (b"mcp-method", method.encode()),
    ]
    if method == "tools/call":
        headers.append((b"mcp-name", params["name"].encode()))
    body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    ).encode()

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    return Request(
        {"type": "http", "method": "POST", "path": "/mcp/core", "headers": headers},
        receive,
    )


class ActivityTests(unittest.IsolatedAsyncioTestCase):
    async def test_running_finished_and_other_user_not_visible(self):
        db = FakeDb()
        agents = FakeAgents()
        service = ToolService(db, agents, 300)
        alice = Principal(
            "alice", "chatgpt", "oauth2", ("commandcore:standard",), issuer="idp-1"
        )
        bob = Principal(
            "bob", "chatgpt", "oauth2", ("commandcore:read",), issuer="idp-1"
        )
        task = asyncio.create_task(
            service.call(
                alice,
                "shell.exec",
                {"device_id": "box-a", "command": "echo secret-password-never-echo"},
            )
        )
        await asyncio.wait_for(agents.started.wait(), 3)
        active = await service.call(alice, "activity.feed", {"limit": 20})
        self.assertEqual(len(active["events"]), 1)
        self.assertEqual(active["events"][0]["status"], "running")
        self.assertEqual(active["events"][0]["device"], "test-node-a")
        self.assertNotIn("secret-password", str(active))
        foreign = await service.call(bob, "activity.feed", {"limit": 20})
        self.assertEqual(foreign["events"], [])
        agents.release.set()
        await task
        done = await service.call(alice, "activity.feed", {"limit": 20})
        self.assertEqual(len(done["events"]), 1)
        self.assertEqual(done["events"][0]["status"], "ok")
        self.assertNotIn("secret-password", str(done))
        self.assertEqual(len(db.audits), 1, "polling must not flood audit")

    async def test_only_authorized_devices_in_history(self):
        activity = LiveActivity()
        alice = Principal("alice", issuer="idp-1")
        db = FakeDb()
        items = [
            {
                "id": 1,
                "tool": "fs.read",
                "status": "ok",
                "timestamp": "2026-10-08T10:00:00+00:00",
                "device_id": "box-a",
                "duration_ms": 200,
                "args_summary": "private",
            },
            {
                "id": 2,
                "tool": "shell.exec",
                "status": "ok",
                "timestamp": "2026-10-08T11:00:00+00:00",
                "device_id": "box-b",
                "duration_ms": 200,
                "args_summary": "private",
            },
        ]
        feed = activity.snapshot(alice, items, db.list_accessible_devices("alice"), 25)
        self.assertEqual([e["tool"] for e in feed["events"]], ["fs.read"])
        self.assertNotIn("args_summary", str(feed))
        self.assertNotIn("private", str(feed))

    async def test_readonly_tools_resource_and_render(self):
        db = FakeDb()
        service = ToolService(db, FakeAgents(), 300)
        mcp = MCPHandler(
            service,
            SimpleNamespace(inc=lambda x: None),
            "test",
            definitions=[
                tool
                for tool in __import__(
                    "commandcore_server.tools", fromlist=["TOOL_DEFINITIONS"]
                ).TOOL_DEFINITIONS
                if tool["name"] in {"activity.feed", "activity.watch"}
            ],
        )
        user = Principal(
            "alice", "chatgpt", "oauth2", ("commandcore:read",), issuer="idp-1"
        )

        async def invoke(method, args=None):
            response = await mcp.handle(rpc(method, args), user)
            return json.loads(response.body)["result"]

        tools = (await invoke("tools/list"))["tools"]
        watch = next(x for x in tools if x["name"] == "activity.watch")
        self.assertEqual(watch["_meta"]["ui"]["resourceUri"], ACTIVITY_UI_URI)
        self.assertEqual(watch["securitySchemes"][0]["scopes"], ["commandcore:read"])
        resources = await invoke("resources/list")
        self.assertEqual(resources["resources"][0]["uri"], ACTIVITY_UI_URI)
        widget = (await invoke("resources/read", {"uri": ACTIVITY_UI_URI}))["contents"][
            0
        ]
        self.assertIn("CommandCore", widget["text"])
        self.assertIn("activity.feed", widget["text"])
        out = await invoke("tools/call", {"name": "activity.watch", "arguments": {}})
        self.assertEqual(out["structuredContent"]["state"], "monitor_ready")
        self.assertEqual(out["_meta"]["ui"]["resourceUri"], ACTIVITY_UI_URI)


if __name__ == "__main__":
    unittest.main()
