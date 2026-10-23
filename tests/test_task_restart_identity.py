import runpy, asyncio, os, tempfile, pathlib

f = runpy.run_path(str(pathlib.Path(__file__).with_name("test_task_lifecycle.py")))
m, Tools, Principal, ToolError = f["m"], f["Tools"], f["Principal"], f["ToolError"]
from commandcore_server.live_activity import LiveActivity
from commandcore_server.auth import READ_SCOPE, STANDARD_SCOPE
from commandcore_server.metrics import Metrics


async def main():
    root = pathlib.Path(tempfile.mkdtemp())
    os.environ["COMMANDCORE_UI_TASK_DB"] = str(root / "tasks.sqlite3")
    p = Principal(
        subject="owner",
        issuer="https://fixture",
        client_id="client",
        auth_kind="oauth2",
        scopes=(READ_SCOPE, STANDARD_SCOPE),
    )
    t = Tools()
    t.live_activity = LiveActivity()
    h = m.MCPHandler(t, Metrics(), "test")
    watch = await h._call_tools(p, "commandcore.watch", {}, "chat-A")
    id = watch["task_id"]
    tag = t.live_activity.session_tag("chat-A")
    old_ref = watch["session_ref"]
    assert t.live_activity.resolve_viewer(p, old_ref) == tag
    # New broker + handler + ledger reproduce a real process restart. The prior
    # fixture used an unkeyed SHA-256, concealing the production key rotation.
    t2 = Tools()
    t2.live_activity = LiveActivity()
    h2 = m.MCPHandler(t2, Metrics(), "test")
    assert t2.live_activity.session_tag("chat-A") == tag, (
        "Persisted task identity changed on restart"
    )
    assert t2.live_activity.resolve_viewer(p, old_ref) is None, (
        "Viewer capabilities must remain ephemeral"
    )
    fresh = t2.live_activity.issue_viewer(p, "chat-A")
    owner, conversation = h2._task_context(
        p, {"session_ref": fresh["session_ref"]}, "chat-A"
    )
    assert h2.tasks.get(owner, conversation, id)["id"] == id
    for wrong in ["chat-B", None]:
        if wrong is None:
            # A verified viewer is sufficient when a host omits the redundant header.
            assert h2._task_context(p, {"session_ref": fresh["session_ref"]}, None) == (
                owner,
                conversation,
            )
        else:
            try:
                h2._task_context(p, {"session_ref": fresh["session_ref"]}, wrong)
            except ToolError as e:
                assert e.code == "invalid_task_view"
            else:
                raise AssertionError("Foreign conversation accepted")
    for subject, issuer, client in [
        ("other", "https://fixture", "client"),
        ("owner", "https://other", "client"),
        ("owner", "https://fixture", "other"),
    ]:
        bad = Principal(
            subject=subject,
            issuer=issuer,
            client_id=client,
            auth_kind="oauth2",
            scopes=(READ_SCOPE, STANDARD_SCOPE),
        )
        assert t2.live_activity.resolve_viewer(bad, fresh["session_ref"]) is None
        try:
            h2.tasks.get(h2.tasks.owner(bad), conversation, id)
        except ToolError as e:
            assert e.code == "invalid_task_view"
        else:
            raise AssertionError("Foreign principal accepted")
    # Legacy records with lost old process tags must not be rebound by owner+ID.
    legacy = h2.tasks.start(owner, "old-ephemeral-tag")
    try:
        h2.tasks.get(owner, conversation, legacy)
    except ToolError as e:
        assert e.code == "invalid_task_view"
    else:
        raise AssertionError("Legacy ownership bypass")
    key = root / "tasks.sqlite3.session-key"
    assert key.stat().st_mode & 0o077 == 0
    assert len(key.read_bytes()) == 32
    # Refuse to swap keys on an already-active broker.
    live = LiveActivity()
    live.issue_viewer(p, "chat-A")
    try:
        h2.tasks.bind_activity(live)
    except RuntimeError:
        pass
    else:
        raise AssertionError("Active broker key replaced")
    for mode in ["public", "short", "symlink", "hardlink", "fifo", "directory"]:
        case = root / mode
        case.mkdir()
        ledger = m.UITaskLedger(str(case / "tasks.sqlite3"))
        path = case / "tasks.sqlite3.session-key"
        if mode == "symlink":
            path.symlink_to(key)
        elif mode == "hardlink":
            os.link(key, path)
        elif mode == "fifo":
            os.mkfifo(path, 0o600)
        elif mode == "directory":
            path.mkdir()
        else:
            path.write_bytes(b"x" * (3 if mode == "short" else 32))
            path.chmod(0o644 if mode == "public" else 0o600)
        try:
            ledger.bind_activity(LiveActivity())
        except (OSError, RuntimeError):
            pass
        else:
            raise AssertionError("Invalid conversation key accepted: " + mode)
        finally:
            if mode == "hardlink":
                path.unlink()
    print(
        "PASS real broker restart identity; ephemeral viewers; foreign chat/owner/issuer/client denied; legacy denial; private key guards; active broker refuses rekey"
    )


def test_restart_identity(monkeypatch):
    with monkeypatch.context() as patch:
        patch.setenv(
            "COMMANDCORE_UI_TASK_DB",
            str(pathlib.Path(tempfile.mkdtemp()) / "tasks.sqlite3"),
        )
        asyncio.run(main())
