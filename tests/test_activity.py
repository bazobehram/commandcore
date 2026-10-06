import json
import time
from types import SimpleNamespace

from commandcore_server.activity import ActivityEvent, argument_summary
from commandcore_server.db import Database


def test_activity_never_copies_untrusted_content(tmp_path):
    secret = "fixture-sensitive-content-DO-NOT-PERSIST"
    args = {
        key: secret
        for key in (
            "command",
            "path",
            "repo",
            "query",
            "data",
            "data_base64",
            "token",
            "password",
            "private_key",
            "cookie",
        )
    }
    args.update(
        env={secret: secret},
        patches=[{"search": secret, "replace": secret}],
        args=[secret],
    )
    event = ActivityEvent(
        "execution",
        "request",
        "device",
        "disposable",
        "shell.exec",
        argument_summary(args),
        "STANDARD",
        time.time(),
    )
    event.finish(
        SimpleNamespace(
            status=secret,
            exit_code=0,
            error=secret,
            stdout=secret,
            stderr=secret,
            result={"signal": secret, "termination_reason": secret, "data": secret},
        )
    )
    serialized = json.dumps(event.wire())
    assert secret not in serialized
    assert "sha256" not in serialized
    db = Database(str(tmp_path / "activity.sqlite3"))
    db.save_activity(event.wire())
    assert secret not in json.dumps(db.list_activity("device"))
    assert db.list_activity("another-device") == []
    assert event.status == "error"
    assert event.exit_code == 0


def test_history_updates_running_event_and_retains_newest(tmp_path):
    db = Database(str(tmp_path / "activity.sqlite3"))
    event = ActivityEvent(
        "execution",
        "request",
        "device",
        "disposable",
        "process.stop",
        {},
        "STANDARD",
        time.time(),
    )
    db.save_activity(event.wire())
    assert db.list_activity("device")[0]["status"] == "running"
    event.finish(
        SimpleNamespace(
            status="ok",
            exit_code=None,
            result={"signal": "SIGTERM", "termination_reason": "stopped_by_request"},
        )
    )
    db.save_activity(event.wire())
    rows = db.list_activity("device")
    assert len(rows) == 1
    assert rows[0]["termination_reason"] == "stopped_by_request"
    assert rows[0]["duration_ms"] >= 0
    old = ActivityEvent(
        "expired",
        "request",
        "device",
        "disposable",
        "system.info",
        {},
        "STANDARD",
        time.time() - 31 * 86400,
    )
    db.save_activity(old.wire())
    assert len(db.list_activity("device")) == 1


def test_health_and_domain_activity_are_allowlisted():
    event = ActivityEvent(
        "e", "r", "d", "test", "process.start", {}, "STANDARD", time.time()
    )
    secret = "must-not-persist"
    event.finish(
        SimpleNamespace(
            status="ok",
            result={
                "health_at_start": {
                    "state": "warning",
                    "conditions": [
                        {"code": "memory_pressure", "context": secret},
                        {"code": secret},
                    ],
                    "raw": secret,
                },
                "reason": "unknown_process",
            },
        )
    )
    assert event.health_summary == {
        "state": "warning",
        "conditions": ["memory_pressure"],
    }
    assert event.domain_state == "unknown_process"
    assert secret not in json.dumps(event.wire())


def test_malformed_remote_health_cannot_break_activity_completion():
    event = ActivityEvent(
        "e", "r", "d", "test", "process.start", {}, "STANDARD", time.time()
    )
    event.finish(
        SimpleNamespace(
            status="ok",
            result={
                "health": {"state": "warning", "conditions": [{"code": {}}, None]},
                "reason": {},
                "signal": [],
                "termination_reason": {},
            },
        )
    )
    assert event.health_summary == {"state": "warning", "conditions": []}
    assert event.termination_reason is None
