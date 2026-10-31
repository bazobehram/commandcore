from __future__ import annotations

from types import SimpleNamespace

import pytest

from commandcore_server.mcp import UITaskLedger
from commandcore_server.mcp_task_ledger import UITaskLedger as LedgerImplementation
from commandcore_server.tools import ToolError


def test_mcp_handler_compatibility_import_points_to_ledger_implementation():
    assert UITaskLedger is LedgerImplementation


def test_owner_key_includes_issuer_subject_and_client_identity():
    principal = SimpleNamespace(
        issuer="https://issuer.example/",
        subject="user-1",
        client_id="client-1",
    )
    expected = UITaskLedger.owner(principal)
    assert len(expected) == 64
    assert expected == UITaskLedger.owner(principal)
    assert expected != UITaskLedger.owner(
        SimpleNamespace(
            issuer="https://other-issuer.example/",
            subject="user-1",
            client_id="client-1",
        )
    )
    assert expected != UITaskLedger.owner(
        SimpleNamespace(
            issuer="https://issuer.example/",
            subject="user-2",
            client_id="client-1",
        )
    )
    assert expected != UITaskLedger.owner(
        SimpleNamespace(
            issuer="https://issuer.example/",
            subject="user-1",
            client_id="client-2",
        )
    )


def test_public_task_projection_excludes_owner_and_conversation_metadata():
    ledger = UITaskLedger(":memory:")
    task = ledger.start("owner-digest", "conversation-tag")
    row = ledger.get("owner-digest", "conversation-tag", task)
    public = ledger.public(row)
    assert public["id"] == task
    assert "owner" not in public
    assert "conversation" not in public
    assert set(public) == {
        "id",
        "started",
        "ended",
        "total",
        "running",
        "failed",
        "last_status",
        "last_tool",
        "device",
    }


def test_task_lookup_rejects_invalid_ids_and_foreign_owner_or_conversation():
    ledger = UITaskLedger(":memory:")
    task = ledger.start("owner-A", "chat-A")
    for invalid in ["bad", None, 123]:
        with pytest.raises(ToolError) as exc:
            ledger.get("owner-A", "chat-A", invalid)
        assert exc.value.code == "invalid_task_view"
    for owner, conversation in [
        ("owner-B", "chat-A"),
        ("owner-A", "chat-B"),
        ("owner-B", "chat-B"),
    ]:
        with pytest.raises(ToolError) as exc:
            ledger.get(owner, conversation, task)
        assert exc.value.code == "invalid_task_view"


def test_history_is_owner_and_conversation_scoped_and_retains_only_safe_summary():
    ledger = UITaskLedger(":memory:")
    task = ledger.start("owner-A", "chat-A")
    call = ledger.begin_call("owner-A", "chat-A", "shell.exec")
    ledger.end_call(call, "ok", "netti")
    rows = ledger.history("owner-A", "chat-A", task)
    assert len(rows) == 1
    assert rows[0]["tool"] == "shell.exec"
    assert rows[0]["status"] == "ok"
    assert rows[0]["device"] == "Not retained"
    assert rows[0]["history_summary"] is True
    assert "command" not in rows[0]
    assert "path" not in rows[0]
    assert ledger.history("owner-B", "chat-A", task) == []
    assert ledger.history("owner-A", "chat-B", task) == []


def test_finish_waits_for_running_calls_and_is_idempotent():
    ledger = UITaskLedger(":memory:")
    task = ledger.start("owner", "chat")
    call = ledger.begin_call("owner", "chat", "fs.write")
    with pytest.raises(ToolError) as exc:
        ledger.finish("owner", "chat", task)
    assert exc.value.code == "task_still_running"

    ledger.end_call(call, "ok")
    first = ledger.finish("owner", "chat", task)
    second = ledger.finish("owner", "chat", task)
    assert first == second
    assert first["ended"] is not None
    assert first["running"] == 0
    assert ledger.begin_call("owner", "chat", "system.info") is None


def test_start_interrupts_previous_calls_and_keeps_one_current_task():
    ledger = UITaskLedger(":memory:")
    previous = ledger.start("owner", "chat")
    call = ledger.begin_call("owner", "chat", "shell.exec")
    current = ledger.start("owner", "chat")
    old = ledger.get("owner", "chat", previous)
    assert old["ended"] is not None
    assert old["last_status"] == "interrupted"
    assert ledger.history("owner", "chat", previous)[0]["status"] == "interrupted"
    assert ledger.get("owner", "chat", current)["ended"] is None
    ledger.end_call(call, "ok")
    assert ledger.get("owner", "chat", previous)["last_status"] == "interrupted"
