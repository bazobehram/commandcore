from __future__ import annotations

import shutil
import subprocess

import pytest

from commandcore_agent.executor import Executor
from commandcore_server.permissions import allowed
from commandcore_server.tools import TOOL_DEFINITIONS


async def sink(stream: str, data: str):
    return None


@pytest.mark.asyncio
async def test_native_git_status_log_and_run(tmp_path):
    if not shutil.which("git"):
        pytest.skip("git not installed")
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(
        ["git", "-C", str(repo), "init"], check=True, stdout=subprocess.DEVNULL
    )
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.email", "test@example.test"],
        check=True,
    )
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test"], check=True)
    (repo / "a.txt").write_text("one\n")
    subprocess.run(["git", "-C", str(repo), "add", "a.txt"], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "commit", "-m", "first"],
        check=True,
        stdout=subprocess.DEVNULL,
    )

    ex = Executor(delegate_full_control=False, enforce_local_ceiling=False)
    status = await ex.execute(
        "g1", "READ_ONLY", "git.status", {"repo": str(repo)}, sink
    )
    assert status["status"] == "ok"
    assert status["result"]["clean"] is True
    log = await ex.execute(
        "g2", "READ_ONLY", "git.log", {"repo": str(repo), "limit": 5}, sink
    )
    assert log["result"]["commits"][0]["subject"] == "first"
    run = await ex.execute(
        "g3",
        "STANDARD",
        "git.run",
        {"repo": str(repo), "args": ["rev-parse", "--is-inside-work-tree"]},
        sink,
    )
    assert run["status"] == "ok"


def test_docker_is_full_control_and_advertised_as_oauth_full():
    for tool in [
        "docker.ps",
        "docker.inspect",
        "docker.logs",
        "docker.exec",
        "docker.run",
    ]:
        assert not allowed("STANDARD", tool)
        assert allowed("FULL_CONTROL", tool)
        spec = next(x for x in TOOL_DEFINITIONS if x["name"] == tool)
        assert spec["securitySchemes"][0]["scopes"] == ["commandcore:full"]


@pytest.mark.asyncio
async def test_docker_exec_uses_argv_without_shell(monkeypatch):
    ex = Executor(delegate_full_control=False, enforce_local_ceiling=False)
    seen = {}

    async def fake_run(execution_id, argv, output, timeout=3600.0, cwd=None, env=None):
        seen["argv"] = argv
        return {"exit_code": 0, "pid": 123, "argv": argv}

    monkeypatch.setattr(ex, "_run_argv", fake_run)
    monkeypatch.setattr(ex, "_tool_binary", lambda name: "/usr/bin/docker")
    result = await ex.execute(
        "d1",
        "FULL_CONTROL",
        "docker.exec",
        {
            "container": "web",
            "argv": ["sh", "-c", "printf safe; touch /tmp/x"],
            "timeout_ms": 1000,
        },
        sink,
    )
    assert result["status"] == "ok"
    assert seen["argv"] == [
        "/usr/bin/docker",
        "exec",
        "--",
        "web",
        "sh",
        "-c",
        "printf safe; touch /tmp/x",
    ]
