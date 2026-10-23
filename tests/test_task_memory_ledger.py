"""Platforms without the POSIX persistence boundary keep no task files."""

from concurrent.futures import ThreadPoolExecutor

import pytest
import os

from commandcore_server.live_activity import LiveActivity
from commandcore_server.mcp import UITaskLedger
from commandcore_server.tools import ToolError


def test_memory_ledger_tracks_calls_without_persistence(tmp_path, monkeypatch):
    monkeypatch.setenv("COMMANDCORE_UI_TASK_DB", str(tmp_path / "must-not-exist"))
    ledger = UITaskLedger(":memory:")
    broker = LiveActivity()
    key = broker._session_key
    ledger.bind_activity(broker)
    assert broker._session_key == key
    task = ledger.start("owner", "chat")
    call = ledger.begin_call("owner", "chat", "system.metrics")
    ledger.end_call(call, "ok")
    assert ledger.finish("owner", "chat", task)["total"] == 1
    assert not list(tmp_path.iterdir())
    with pytest.raises(ToolError):
        UITaskLedger(":memory:").get("owner", "chat", task)
    with pytest.raises(ToolError):
        ledger.get("other-owner", "chat", task)
    with pytest.raises(ToolError):
        ledger.get("owner", "other-chat", task)


def test_memory_ledger_serializes_concurrent_starts():
    ledger = UITaskLedger(":memory:")
    with ThreadPoolExecutor(max_workers=6) as pool:
        tasks = list(pool.map(lambda _: ledger.start("owner", "chat"), range(12)))
    assert (
        sum(ledger.get("owner", "chat", task)["ended"] is None for task in tasks) == 1
    )


def test_windows_default_never_opens_a_task_file(monkeypatch, tmp_path):
    monkeypatch.setenv("COMMANDCORE_UI_TASK_DB", str(tmp_path / "must-not-exist"))
    with monkeypatch.context() as patch:
        patch.setattr(os, "name", "nt")
        ledger = UITaskLedger()
    assert ledger.path is None
    assert ledger._memory_db is not None
    assert not list(tmp_path.iterdir())
