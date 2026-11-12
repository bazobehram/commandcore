import importlib
import json
import types
import unittest
from unittest.mock import AsyncMock

m=importlib.import_module("commandcore_server.mcp")
names=["devices.list","devices.select","devices.info","system.info","system.metrics","fs.list",
       "fs.read","fs.write","git.status","process.start","docker.ps","browser.open","browser.watch",
       "browser.frame","shell.exec","activity.feed"]
defs=[x for x in m.TOOL_DEFINITIONS if x["name"] in names]
class Request:
    def __init__(self,method,params,modern=True):
        self.headers={"mcp-protocol-version":m.MODERN_PROTOCOL,"mcp-method":method} if modern else {}
        if method=="tools/call":self.headers["mcp-name"]=params.get("name","")
        self.method=method;self.params=dict(params)
        if modern:
            self.params["_meta"]=dict(self.params.get("_meta") or {})
            self.params["_meta"]["io.modelcontextprotocol/protocolVersion"]=m.MODERN_PROTOCOL
            self.params["_meta"]["io.modelcontextprotocol/clientCapabilities"]={}
    async def json(self):
        return {"jsonrpc":"2.0","id":52,"method":self.method,"params":self.params}
class ReceiptTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.payload={"devices":[{"display_name":"test-node","status":"online","platform":"Linux","public_key_b64":"SECRET"}]}
        self.tool=types.SimpleNamespace(live_activity=types.SimpleNamespace(issue_viewer=lambda *args:{"session_available":False}))
        self.h=m.MCPHandler(self.tool,types.SimpleNamespace(inc=lambda *a:None),"smoke",definitions=defs)
        self.h._call_tools=AsyncMock(return_value=self.payload)
        self.p=types.SimpleNamespace(auth_kind="oauth2",subject="subject",issuer="issuer",client_id="client")
    def test_spec_and_exclusions(self):
        for name in ("devices.list","devices.select","system.info","system.metrics","fs.read","fs.write","git.status","process.start","docker.ps","browser.open"):
            self.assertEqual(self.h.ui_specs[name][0],m.RECEIPT_UI_URI,name)
        self.assertNotIn("shell.exec",m.RECEIPT_TOOLS)
        self.assertNotEqual(self.h.ui_specs["browser.watch"][0],m.RECEIPT_UI_URI)
        self.assertNotIn("browser.frame",self.h.ui_specs)
        self.assertNotIn("activity.feed",self.h.ui_specs)
        for name in ("devices.list","system.metrics"):
            d=next(d for d in self.h.definitions if d["name"]==name)
            self.assertEqual(d["_meta"]["ui"]["resourceUri"],m.RECEIPT_UI_URI)
        self.assertIn(m.RECEIPT_UI_URI,self.h.ui_resources)
    async def test_modern_resource(self):
        r=await self.h.handle(Request("resources/read",{"uri":m.RECEIPT_UI_URI}),self.p)
        body=json.loads(r.body)
        c=body["result"]["contents"][0]
        self.assertEqual(c["mimeType"],"text/html;profile=mcp-app")
        self.assertLess(len(c["text"]),12000)
        self.assertIn("MCP request",c["text"])
    async def test_list_receipt_and_no_output_duplication(self):
        self.h._call_tools=AsyncMock(return_value=self.payload)
        r=await self.h.handle(Request("tools/call",{"name":"devices.list","arguments":{},"_meta":{"openai/session":"valid-test-session"}}),self.p)
        body=json.loads(r.body)["result"]
        self.assertEqual(body["structuredContent"]["_ui_receipt"]["tool"],"devices.list")
        self.assertEqual(body["_meta"]["ui"]["resourceUri"],m.RECEIPT_UI_URI)
        self.assertEqual(body["_meta"]["commandcore/receipt"]["tool"],"devices.list")
        self.assertNotIn("SECRET",json.dumps(body["_meta"]))
        self.assertIn("SECRET",json.dumps(body["structuredContent"]["devices"]))  # model retains original authorized payload
    async def test_metrics_receipt_and_exact_caller(self):
        self.h._call_tools=AsyncMock(return_value={"result":{"cpu_percent":11.3,"memory":{"percent":22.1}},"activity_step":{"device":"test-node","duration_ms":13}})
        r=await self.h.handle(Request("tools/call",{"name":"system.metrics","arguments":{"selection_id":"sensitive-reference"}}),self.p)
        b=json.loads(r.body)["result"]
        receipt=b["structuredContent"]["_ui_receipt"]
        self.assertEqual(receipt["device"],"test-node")
        self.assertNotIn("sensitive-reference",json.dumps(receipt))
        self.assertEqual(b["_meta"]["ui"]["resourceUri"],m.RECEIPT_UI_URI)
    async def test_shell_preserves_own_ui(self):
        self.h._call_tools=AsyncMock(return_value={"stdout":"private","status":"ok"})
        r=await self.h.handle(Request("tools/call",{"name":"shell.exec","arguments":{"command":"uname -a"}}),self.p)
        b=json.loads(r.body)["result"]
        self.assertNotIn("ui",b.get("_meta",{}))
        self.assertNotIn("_ui_receipt",b["structuredContent"])
    async def test_failed_device_request_retains_receipt(self):
        self.h._call_tools = AsyncMock(side_effect=m.ToolError("device_offline", "Device is offline"))
        r = await self.h.handle(
            Request("tools/call",{"name":"system.metrics","arguments":{"selection_id":"opaque"}}), self.p
        )
        b = json.loads(r.body)["result"]
        self.assertTrue(b["isError"])
        self.assertEqual(b["_meta"]["commandcore/receipt"]["status"],"error")
        self.assertEqual(b["_meta"]["ui"]["resourceUri"],m.RECEIPT_UI_URI)

    async def test_oauth_denial_preserves_challenge(self):
        self.h._call_tools = AsyncMock(side_effect=m.ToolError("insufficient_scope", "Consent required"))
        self.h.scope_challenge = lambda scope: "Bearer scope="+scope
        self.tool._required_scope = lambda name: "commandcore:standard"
        r = await self.h.handle(
            Request("tools/call",{"name":"system.metrics","arguments":{"selection_id":"opaque"}}), self.p
        )
        b = json.loads(r.body)["result"]
        self.assertTrue(b["isError"])
        self.assertIn("mcp/www_authenticate",b["_meta"])
        self.assertEqual(b["_meta"]["commandcore/receipt"]["status"],"error")
        self.assertNotIn("opaque",json.dumps(b["_meta"]))

    def test_device_target_from_safe_server_summary(self):
        r=m._cc_receipt("system.metrics",{"status":"ok","summary":"system.metrics on test-node: ok"})
        self.assertEqual(r["device"],"test-node")
        bad=m._cc_receipt("system.metrics",{"status":"ok","summary":"system.metrics on a/b\\secret: ok"})
        self.assertEqual(bad["device"],"")

if __name__=="__main__":unittest.main(verbosity=2)
