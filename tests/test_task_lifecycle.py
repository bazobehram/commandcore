import asyncio, tempfile, json, uuid, hashlib, concurrent.futures
from types import SimpleNamespace
from pathlib import Path
from commandcore_server.models import Principal
from commandcore_server.metrics import Metrics
from commandcore_server.auth import READ_SCOPE, STANDARD_SCOPE
from commandcore_server.tools import operation_ui_context, ToolError, ToolService

from commandcore_server import mcp as m

TEST_OUTPUT = Path(tempfile.mkdtemp(prefix="commandcore-task-fixture-"))


class Live:
    def finish(self, *args, **kwargs):
        pass

    def __init__(self):
        self.refs = {}
        self.events = []

    def session_tag(self, s):
        return (
            hashlib.sha256(s.encode()).hexdigest() if isinstance(s, str) and s else None
        )

    def issue_viewer(self, p, s):
        if not s:
            return {"session_available": False}
        ref = str(uuid.uuid4())
        self.refs[ref] = (p.subject, p.client_id, self.session_tag(s))
        return {"session_available": True, "session_ref": ref}

    def resolve_viewer(self, p, ref):
        value = self.refs.get(ref)
        return value[2] if value and value[:2] == (p.subject, p.client_id) else None

    def snapshot(
        self,
        p,
        _,
        devices,
        limit,
        include_details=False,
        session_tag=None,
        device_filter=None,
    ):
        return {
            "events": [
                dict(e)
                for e in self.events
                if e["_owner"] == p.subject and e["_tag"] == session_tag
            ][:limit]
        }


class DB:
    def recent_audit(self, s, limit=100):
        return []

    def list_accessible_devices(self, s):
        return []


class Tools:
    def __init__(self):
        self.live_activity = Live()
        self.timeline = SimpleNamespace(finish=lambda *args, **kwargs: None)
        self.db = DB()
        self.pause = None
        self.failure = None

    def _require_scope(self, p, name):
        pass

    async def call(self, p, name, args, host_session=None):
        if name in {"commandcore.watch", "activity.watch"}:
            return {
                "state": "dashboard_ready",
                **self.live_activity.issue_viewer(p, host_session),
                "mode": "read_only",
            }
        if name == "activity.feed":
            assert (
                type(args.get("limit", 25)) is int and 1 <= args.get("limit", 25) <= 50
            ), "Must obey production ToolService activity.feed contract"
            if self.pause:
                await self.pause()
            return await ToolService.call(
                self, p, name, args, host_session=host_session
            )
        if name in m.OPERATION_TOOLS:
            if self.failure == "raise":
                raise ToolError("fixture_denied")
            from datetime import datetime, timezone

            key = str(uuid.uuid4())
            operation_ui_context.get()["operation_id"] = key
            status = self.failure or "ok"
            self.live_activity.events.insert(
                0,
                {
                    "operation_id": key,
                    "tool": name,
                    "device": "fixture",
                    "status": status,
                    "started_at": datetime.now(timezone.utc).isoformat(),
                    "_owner": p.subject,
                    "_tag": self.live_activity.session_tag(host_session),
                },
            )
            return {
                "execution_id": str(uuid.uuid4()),
                "status": status,
                "summary": name + " on fixture: " + status,
            }
        raise ToolError("unknown_tool")


async def raises(call, code):
    try:
        await call
    except ToolError as e:
        assert e.code == code, (e.code, code)
    else:
        raise AssertionError("Expected " + code)


async def main():
    p = Principal(
        subject="owner-A",
        issuer="https://fixture",
        client_id="client-A",
        auth_kind="oauth2",
        scopes=(READ_SCOPE, STANDARD_SCOPE),
    )
    other = Principal(
        subject="owner-B",
        issuer="https://fixture",
        client_id="client-A",
        auth_kind="oauth2",
        scopes=(READ_SCOPE, STANDARD_SCOPE),
    )
    tools = Tools()
    h = m.MCPHandler(tools, Metrics(), "test")
    defs = {x["name"]: x for x in h.definitions}
    approved_inline = {
        "shell.exec": m.SHELL_UI_URI,
        "execution.timeline.watch": m.TIMELINE_UI_URI,
    }
    for name in m.OPERATION_TOOLS:
        if name in defs:
            expected_uri = approved_inline.get(name)
            assert defs[name].get("_meta", {}).get("ui", {}).get("resourceUri") == expected_uri, name
            assert defs[name].get("_meta", {}).get("openai/outputTemplate") == expected_uri, name
    assert defs["commandcore.watch"]["_meta"]["ui"]["resourceUri"] == m.TASK_UI_URI
    assert (
        defs["commandcore.workspace"]["_meta"]["ui"]["resourceUri"]
        == m.WORKSPACE_UI_URI
    )
    assert defs["commandcore.viewer"]["_meta"]["ui"]["visibility"] == ["app"]
    assert "task_id" in defs["activity.feed"]["inputSchema"]["properties"]
    watch = await h._call_tools(p, "commandcore.watch", {}, "chat-A")
    task = watch["task_id"]
    ref = watch["session_ref"]
    for i in range(20):
        raw = await h._call_tools(p, "system.metrics", {}, "chat-A")
        wire = m._tool_result(raw, False)
        assert not wire.get("_meta", {}).get("ui", {}).get("resourceUri")
    feed = await h._call_tools(
        p,
        "activity.feed",
        {"task_id": task, "session_ref": ref, "view": "conversation"},
        "chat-A",
    )
    assert feed["task"]["total"] == 20 and feed["task"]["failed"] == 0
    assert (
        len(feed["events"]) == 20
        and "owner" not in feed["task"]
        and "conversation" not in feed["task"]
    )
    await raises(
        h._call_tools(
            other, "activity.feed", {"task_id": task, "session_ref": ref}, "chat-A"
        ),
        "invalid_session_view",
    )
    await raises(
        h._call_tools(
            p, "activity.feed", {"task_id": task, "session_ref": ref}, "chat-B"
        ),
        "invalid_task_view",
    )
    await raises(
        h._call_tools(
            p,
            "activity.feed",
            {"task_id": task, "session_ref": ref, "view": "all"},
            "chat-A",
        ),
        "invalid_task_view",
    )
    # Data errors never open extra widgets and are counted honestly.
    tools.failure = "timeout"
    await h._call_tools(p, "shell.exec", {}, "chat-A")
    tools.failure = "agent_disconnected"
    await h._call_tools(p, "system.metrics", {}, "chat-A")
    tools.failure = "raise"
    await raises(h._call_tools(p, "fs.write", {}, "chat-A"), "fixture_denied")
    tools.failure = None
    summary = h.tasks.public(
        h.tasks.get(h.tasks.owner(p), tools.live_activity.session_tag("chat-A"), task)
    )
    assert summary["failed"] == 3 and summary["running"] == 0

    # A new task freezes the old boundary. Late feed responses must use the new
    # ended boundary rather than a pre-await snapshot.
    async def change():
        tools.pause = None
        await h._call_tools(p, "commandcore.watch", {}, "chat-A")
        await h._call_tools(p, "fs.read", {}, "chat-A")

    tools.pause = change
    old = await h._call_tools(
        p, "activity.feed", {"task_id": task, "session_ref": ref}, "chat-A"
    )
    assert old["task"]["ended"] is not None and all(
        x["tool"] != "fs.read" for x in old["events"]
    )
    finished = await h._call_tools(p, "commandcore.finish", {"task_id": task}, "chat-A")
    again = await h._call_tools(p, "commandcore.finish", {"task_id": task}, "chat-A")
    assert finished == again
    # Viewer renewal does not start or end tasks.
    before = h.tasks.get(
        h.tasks.owner(p), tools.live_activity.session_tag("chat-A"), task
    )
    tools.live_activity.refs.clear()
    await raises(
        h._call_tools(
            p, "activity.feed", {"task_id": task, "session_ref": ref}, "chat-A"
        ),
        "invalid_session_view",
    )
    renewed = await h._call_tools(p, "commandcore.viewer", {}, "chat-A")
    after = await h._call_tools(
        p,
        "activity.feed",
        {"task_id": task, "session_ref": renewed["session_ref"]},
        "chat-A",
    )
    assert after["task"]["ended"] == before["ended"]
    # Saved task calls survive loss/eviction of the transient Activity feed.
    memory = list(tools.live_activity.events)
    tools.live_activity.events.clear()
    historic = await h._call_tools(
        p,
        "activity.feed",
        {"task_id": task, "session_ref": renewed["session_ref"]},
        "chat-A",
    )
    assert len(historic["events"]) == 23, (
        "Saved task lost its recorded calls after Activity eviction"
    )
    assert (
        sum(
            x["status"] not in ("ok", "completed", "started", "returned")
            for x in historic["events"]
        )
        == 3
    )
    assert all(
        x["history_summary"] is True and x["detail"]["category"] == "Saved summary"
        for x in historic["events"]
    )
    assert all(
        not any(
            k in x
            for k in (
                "owner",
                "conversation",
                "_owner",
                "_tag",
                "command",
                "path",
                "session_ref",
            )
        )
        for x in historic["events"]
    )
    await raises(
        h._call_tools(other, "activity.feed", {"task_id": task}, "chat-A"),
        "invalid_task_view",
    )
    await raises(
        h._call_tools(p, "activity.feed", {"task_id": task}, "chat-B"),
        "invalid_task_view",
    )
    for i in range(55):
        await h._call_tools(p, "system.metrics", {}, "chat-A")
    bounded = await h._call_tools(
        p,
        "activity.feed",
        {"task_id": task, "session_ref": renewed["session_ref"]},
        "chat-A",
    )
    assert len(bounded["events"]) == 23 and all(
        x["history_summary"] for x in bounded["events"]
    )
    # Partial eviction preserves detailed rows and fills each missing call once.
    partial = [e for e in memory if e["tool"] == "system.metrics"][:1]
    tools.live_activity.events = partial
    mixed = await h._call_tools(
        p,
        "activity.feed",
        {"task_id": task, "session_ref": renewed["session_ref"]},
        "chat-A",
    )
    assert (
        len(mixed["events"]) == 23
        and sum(not e.get("history_summary", False) for e in mixed["events"]) == 1
    )
    assert (
        h.tasks.history(
            h.tasks.owner(other), tools.live_activity.session_tag("chat-A"), task
        )
        == []
    )
    assert (
        h.tasks.history(
            h.tasks.owner(p), tools.live_activity.session_tag("chat-B"), task
        )
        == []
    )
    tools.live_activity.events = memory
    # Private DB persists task summaries across restart, but outstanding calls
    # become interrupted, never falsely completed or automatically rerun.
    ledger = m.UITaskLedger(str(Path(tempfile.mkdtemp()) / "ledger.sqlite3"))
    id = ledger.start("owner", "conversation")
    ledger.begin_call("owner", "conversation", "shell.exec")
    try:
        ledger.finish("owner", "conversation", id)
    except ToolError as e:
        assert e.code == "task_still_running"
    else:
        raise AssertionError("Finished outstanding call")
    restarted = m.UITaskLedger(str(ledger.path))
    row = restarted.get("owner", "conversation", id)
    assert (
        row["running"] == 0
        and row["failed"] == 1
        and row["last_status"] == "interrupted"
    )
    assert restarted.history("owner", "conversation", id)[0]["status"] == "interrupted"
    assert ledger.path.stat().st_mode & 0o077 == 0
    closed = ledger.start("owner", "pending-task")
    pending = ledger.begin_call("owner", "pending-task", "fs.write")
    ledger.start("owner", "pending-task")
    oldrow = ledger.get("owner", "pending-task", closed)
    assert oldrow["ended"] and oldrow["running"] == 0 and oldrow["failed"] == 1
    ledger.end_call(pending, "ok")
    assert ledger.get("owner", "pending-task", closed)["last_status"] == "interrupted"
    # Concurrent starts retain one current task for the same conversation.
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        ids = list(pool.map(lambda _: ledger.start("owner", "concurrent"), range(12)))
    assert sum(ledger.get("owner", "concurrent", x)["ended"] is None for x in ids) == 1
    # Legacy source URIs still return operation views; current task uses one live renderer.
    m.web_asset = lambda _: (
        Path(__file__).resolve().parents[1] / "apps/web/commandcore-widget.html"
    )

    class Request:
        headers = {"mcp-protocol-version": "2025-11-25"}

        async def json(self):
            return {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "resources/read",
                "params": {"uri": self.uri},
            }

    for uri in [
        m.TASK_UI_URI,
        "ui://commandcore/task-0.12.0-b13.html",
        "ui://commandcore/task-0.12.0-b12.html",
        "ui://commandcore/task-0.12.0-b11.html",
        "ui://commandcore/task-0.12.0-b10.html",
        "ui://commandcore/task-0.12.0-b9.html",
        "ui://commandcore/task-0.12.0-b8.html",
        "ui://commandcore/task-0.12.0-b7.html",
        "ui://commandcore/task-0.12.0-b6.html",
        "ui://commandcore/task-0.12.0-b4.html",
        "ui://commandcore/task-0.12.0-b1.html",
        m.WORKSPACE_UI_URI,
        "ui://commandcore/operation-0.11.0-b3.html",
    ]:
        request = Request()
        request.uri = uri
        response = await h.handle(request, p)
        resource = json.loads(response.body)["result"]["contents"][0]
        html = resource["text"]
        assert resource["_meta"]["openai/ui"]["availableDisplayModes"] == (
            ["inline"] if uri in m.TASK_UI_URIS else ["inline", "fullscreen"]
        )
        if uri in m.TASK_UI_URIS:
            assert resource["_meta"]["openai/widgetMinFrameHeight"] == 1
            assert resource["_meta"]["openai/widgetHeightHint"] == 112
            if uri == m.TASK_UI_URI:
                (TEST_OUTPUT / "sizing-meta.json").write_text(
                    json.dumps(resource["_meta"])
                )
        else:
            assert "openai/widgetMinFrameHeight" not in resource["_meta"]
        if uri in m.TASK_UI_URIS:
            assert (
                'appCapabilities:{availableDisplayModes:["inline","fullscreen"]}'
                not in html
            )
        assert ('id="cc-task"' in html) == (uri in m.TASK_UI_URIS)
        assert ('id="cc-step"' in html) == ("operation-" in uri)
    # An auxiliary summary write failure must preserve an actual operation
    # result; a failure before dispatch must not execute a device command.
    import sqlite3

    await h._call_tools(p, "commandcore.watch", {}, "warning-chat")
    original_end = h.tasks.end_call

    def broken_end(*args):
        raise sqlite3.OperationalError("fixture disk full")

    h.tasks.end_call = broken_end
    recorded = await h._call_tools(p, "system.metrics", {}, "warning-chat")
    assert recorded["status"] == "ok" and "ui_tracking_warning" in recorded
    h.tasks.end_call = original_end
    original_begin = h.tasks.begin_call

    def broken_begin(*args):
        raise sqlite3.OperationalError("fixture disk full")

    h.tasks.begin_call = broken_begin
    count = len(tools.live_activity.events)
    await raises(
        h._call_tools(p, "fs.write", {}, "warning-chat"), "task_tracking_unavailable"
    )
    assert len(tools.live_activity.events) == count
    h.tasks.begin_call = original_begin
    # Streaming errors also stay data-only.
    tools.failure = "raise"
    stream = h._stream_call(
        p, "fs.write", {}, 99, False, "progress", host_session="chat-A"
    )
    chunks = []
    async for c in stream.body_iterator:
        chunks.append(c)
    messages = [
        json.loads(x[6:])
        for x in "".join(chunks).splitlines()
        if x.startswith("data: ")
    ]
    error = next(x["result"] for x in messages if x.get("id") == 99)
    assert error["isError"] and not error.get("_meta", {}).get("ui", {}).get(
        "resourceUri"
    )
    print(
        "PASS task ownership, foreign viewer rejection, durable boundaries, restart recovery, concurrent starts, 20 data-only calls, errors, scope limits, legacy views, streaming"
    )


def test_task_lifecycle(monkeypatch, tmp_path):
    monkeypatch.setenv("COMMANDCORE_UI_TASK_DB", str(tmp_path / "tasks.sqlite3"))
    original_asset = m.web_asset
    try:
        asyncio.run(main())
    finally:
        m.web_asset = original_asset
