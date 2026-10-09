"""Opt-in loopback-only HTTP/MCP acceptance for a disposable browser staging instance."""

import base64, json, os, urllib.request

url = os.environ.get("COMMANDCORE_TEST_MCP_URL", "")
token = os.environ.get("COMMANDCORE_TEST_TOKEN", "")
if (
    not url.startswith("http://127.0.0.1:")
    or not url.endswith("/mcp/core")
    or not token
):
    raise SystemExit("Use a disposable LOOPBACK staging URL and COMMANDCORE_TEST_TOKEN")
pmeta = {
    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
    "io.modelcontextprotocol/clientCapabilities": {},
}


def rpc(method, params=None, name=None):
    headers = {
        "Authorization": "Bearer " + token,
        "Content-Type": "application/json",
        "Mcp-Protocol-Version": "2026-07-28",
        "Mcp-Method": method,
    }
    if name:
        headers["Mcp-Name"] = name
    p = {"_meta": pmeta, **(params or {})}
    req = urllib.request.Request(
        url,
        data=json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": method, "params": p}
        ).encode(),
        headers=headers,
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=110) as resp:
        data = json.load(resp)
    if "error" in data:
        raise RuntimeError(f"RPC {method} error {data['error']}")
    return data["result"]


def tool(name, args=None):
    out = rpc("tools/call", {"name": name, "arguments": args or {}}, name=name)
    if out.get("isError"):
        raise RuntimeError(
            f"{name}: {out['structuredContent'].get('error')} / {out['structuredContent'].get('message', '')}"
        )
    return out


def showpng(out):
    images = [c for c in out.get("content", []) if c.get("type") == "image"]
    assert len(images) == 1 and images[0].get("mimeType") == "image/png", images
    raw = base64.b64decode(images[0]["data"], validate=True)
    assert raw[:8] == b"\x89PNG\r\n\x1a\n"
    assert "screenshot_base64" not in out["structuredContent"]
    return len(raw)


tools = rpc("tools/list")["tools"]
names = {t["name"] for t in tools}
assert {
    "browser.open",
    "browser.observe",
    "browser.watch",
    "browser.close",
    "activity.feed",
    "activity.watch",
    "commandcore.watch",
} <= names, names
print("STAGE_HTTP_TOOL_DISCOVERY_PASS", flush=True)
uris = {r["uri"] for r in rpc("resources/list")["resources"]}
assert {
    "ui://commandcore/browser-view-v1.html",
    "ui://commandcore/activity-view-v1.html",
    "ui://commandcore/live-views-v1.html",
} <= uris
for uri in sorted(uris):
    res = rpc("resources/read", {"uri": uri})["contents"][0]
    assert (
        "ui/initialize" in res["text"]
        and res["mimeType"] == "text/html;profile=mcp-app"
    )
    print("STAGE_RESOURCE_PASS", uri, flush=True)
activity = tool("activity.watch")
assert (
    activity["_meta"]["ui"]["resourceUri"] == "ui://commandcore/activity-view-v1.html"
)
print("STAGE_ACTIVITY_WATCH_PASS", flush=True)
dashboard = tool("commandcore.watch")
assert dashboard["structuredContent"]["browser_available"] is True
assert dashboard["_meta"]["ui"]["resourceUri"] == "ui://commandcore/live-views-v1.html"
print("STAGE_UNIFIED_DASHBOARD_WATCH_PASS", flush=True)
opened = False
try:
    result = tool("browser.open", {"url": "https://example.com/"})
    opened = True
    length = showpng(result)
    assert result["structuredContent"]["title"] == "Example Domain", result[
        "structuredContent"
    ].get("title")
    print("STAGE_BROWSER_OPEN_REAL_PNG_PASS", length, flush=True)
    watch = tool("browser.watch")
    assert (
        watch["_meta"]["ui"]["resourceUri"] == "ui://commandcore/browser-view-v1.html"
    )
    print("STAGE_BROWSER_WATCH_PASS", flush=True)
    observation = tool("browser.observe")
    length = showpng(observation)
    print("STAGE_BROWSER_OBSERVE_REAL_PNG_PASS", length, flush=True)
    feed = tool("activity.feed", {"limit": 40})["structuredContent"]["events"]
    assert any(
        x["tool"] == "browser.open" and x["status"] in ("ok", "completed") for x in feed
    ), feed
    assert all(
        "args" not in x and "command" not in x and "stdout" not in x for x in feed
    )
    print("STAGE_ACTIVITY_FEED_REAL_BROWSER_EVENT_PASS", len(feed), flush=True)
finally:
    if opened:
        closing = tool("browser.close")["structuredContent"]
        assert closing["closed"] is True
        print("STAGE_BROWSER_CLOSE_PASS", flush=True)
print("DUAL_BROWSER_AND_ACTIVITY_HTTP_MCP_ACCEPTANCE_PASS", flush=True)
