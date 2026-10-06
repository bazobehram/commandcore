from __future__ import annotations

import asyncio

import pytest

from commandcore_agent.executor import Executor


@pytest.mark.asyncio
async def test_shell_exec_streams_output():
    ex = Executor()
    chunks = []

    async def out(stream, data):
        chunks.append((stream, data))

    result = await ex.execute(
        "e1",
        "STANDARD",
        "shell.exec",
        {"command": "printf hello", "timeout_ms": 5000},
        out,
    )
    assert result["status"] == "ok"
    assert result["result"]["exit_code"] == 0
    assert "hello" in "".join(x[1] for x in chunks)


@pytest.mark.asyncio
async def test_read_only_denies_shell():
    ex = Executor()

    async def out(stream, data):
        pass

    result = await ex.execute(
        "e1", "READ_ONLY", "shell.exec", {"command": "echo nope"}, out
    )
    assert result["status"] == "error"
    assert "permission_denied" in result["error"]


@pytest.mark.asyncio
async def test_file_write_read(tmp_path):
    ex = Executor()

    async def out(stream, data):
        pass

    p = tmp_path / "hello.txt"
    w = await ex.execute(
        "e1", "STANDARD", "fs.write", {"path": str(p), "data": "hello"}, out
    )
    assert w["status"] == "ok"
    r = await ex.execute(
        "e2", "READ_ONLY", "fs.read", {"path": str(p), "encoding": "text"}, out
    )
    assert r["result"]["data"] == "hello"


@pytest.mark.asyncio
async def test_stdout_stderr_and_exit_code():
    ex = Executor()
    chunks = []

    async def out(stream, data):
        chunks.append((stream, data))

    result = await ex.execute(
        "e-stream",
        "STANDARD",
        "shell.exec",
        {"command": "sh -c 'printf out; printf err >&2; exit 7'", "timeout_ms": 5000},
        out,
    )
    assert result["status"] == "ok"
    assert result["result"]["exit_code"] == 7
    assert any(s == "stdout" and "out" in d for s, d in chunks)
    assert any(s == "stderr" and "err" in d for s, d in chunks)


@pytest.mark.asyncio
async def test_shell_cancellation_terminates_process():
    ex = Executor()
    chunks = []

    async def out(stream, data):
        chunks.append((stream, data))

    task = asyncio.create_task(
        ex.execute(
            "cancel-me",
            "STANDARD",
            "shell.exec",
            {"command": "sleep 30", "timeout_ms": 60000},
            out,
        )
    )
    for _ in range(50):
        if "cancel-me" in ex.running_jobs:
            break
        await asyncio.sleep(0.02)
    assert "cancel-me" in ex.running_jobs
    await ex.cancel("cancel-me")
    result = await asyncio.wait_for(task, timeout=3)
    assert result["status"] == "ok"
    assert result["result"]["exit_code"] != 0


@pytest.mark.asyncio
async def test_process_start_and_output():
    ex = Executor()

    async def out(stream, data):
        pass

    started = await ex.execute(
        "e1", "STANDARD", "process.start", {"command": "printf managed-output"}, out
    )
    pid = started["result"]["process_id"]
    for _ in range(50):
        data = await ex.execute(
            "e2", "READ_ONLY", "process.output", {"process_id": pid}, out
        )
        if "managed-output" in data["result"].get("stdout", ""):
            break
        await asyncio.sleep(0.02)
    assert "managed-output" in data["result"]["stdout"]


@pytest.mark.asyncio
async def test_path_with_spaces(tmp_path):
    ex = Executor()

    async def out(stream, data):
        pass

    p = tmp_path / "dir with spaces" / "file name.txt"
    w = await ex.execute(
        "e1",
        "STANDARD",
        "fs.write",
        {"path": str(p), "data": "spaces", "create_parents": True},
        out,
    )
    assert w["status"] == "ok"
    r = await ex.execute("e2", "READ_ONLY", "fs.read", {"path": str(p)}, out)
    assert r["result"]["data"] == "spaces"


@pytest.mark.asyncio
async def test_shell_task_cancellation_kills_process_tree():
    ex = Executor()

    async def out(stream, data):
        pass

    task = asyncio.create_task(
        ex.execute(
            "disconnect-job",
            "STANDARD",
            "shell.exec",
            {"command": "sleep 30", "timeout_ms": 60000},
            out,
        )
    )
    for _ in range(100):
        if "disconnect-job" in ex.running_jobs:
            break
        await asyncio.sleep(0.01)
    proc = ex.running_jobs["disconnect-job"]
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert proc.returncode is not None
    assert "disconnect-job" not in ex.running_jobs


@pytest.mark.asyncio
async def test_fs_patch_is_atomic_preserves_mode_and_rejects_symlink_by_default(
    tmp_path,
):
    async def sink(stream, data):
        pass

    p = tmp_path / "config.txt"
    p.write_text("old value\n")
    p.chmod(0o640)
    e = Executor(delegate_full_control=False, enforce_local_ceiling=False)
    out = await e.execute(
        "patch",
        "STANDARD",
        "fs.patch",
        {"path": str(p), "patches": [{"search": "old", "replace": "new"}]},
        sink,
    )
    assert out["status"] == "ok"
    assert out["result"]["atomic"] is True
    assert p.read_text() == "new value\n"
    assert (p.stat().st_mode & 0o777) == 0o640
    link = tmp_path / "link.txt"
    link.symlink_to(p)
    denied = await e.execute(
        "patch2",
        "STANDARD",
        "fs.patch",
        {"path": str(link), "patches": [{"search": "new", "replace": "x"}]},
        sink,
    )
    assert denied["status"] == "error"
    assert "refuses symlinks" in denied["error"]
