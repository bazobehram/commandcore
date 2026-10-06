import asyncio
import json
import os

import pytest

from commandcore_agent.helper_client import HelperClient, build_runtime_capabilities
from commandcore_agent.privileged_helper import HelperServer
from commandcore_agent.capabilities import CAPABILITIES


@pytest.mark.asyncio
async def test_helper_authenticated_execute_stream_and_dry_run(tmp_path, monkeypatch):
    secret = tmp_path / "helper.key"
    secret.write_bytes(b"x" * 48)
    secret.chmod(0o640)
    policy = tmp_path / "policy.json"
    policy.write_text(
        json.dumps(
            {
                "configured_max_permission_profile": "FULL_CONTROL",
                "allowed_helper_uids": [os.getuid()],
            }
        )
    )
    sock = tmp_path / "helper.sock"
    audit = tmp_path / "audit.jsonl"
    helper = HelperServer(str(sock), str(secret), str(policy), str(audit))
    server = await asyncio.start_unix_server(
        helper.handle, path=str(sock), limit=32 * 1024 * 1024
    )
    client = HelperClient(str(sock), str(secret), timeout=2)
    try:
        probe = await client.probe()
        # CI/package builds run as root; a non-root helper must never claim FULL_CONTROL.
        assert probe["available"] is (os.geteuid() == 0)
        if os.geteuid() != 0:
            return

        chunks = []

        async def output(stream, data):
            chunks.append((stream, data))

        result = await client.execute(
            "exec-1", "shell.exec", {"command": "printf helper-ok"}, output
        )
        assert result["status"] == "ok"
        assert result["result"]["exit_code"] == 0
        assert "helper-ok" in "".join(x[1] for x in chunks)

        target = tmp_path / "full-control-file.txt"
        wrote = await client.execute(
            "exec-2",
            "fs.write",
            {"path": str(target), "data": "root-path", "mode": "rewrite"},
            output,
        )
        assert wrote["status"] == "ok"
        read = await client.execute("exec-3", "fs.read", {"path": str(target)}, output)
        assert read["status"] == "ok"
        assert read["result"]["data"] == "root-path"

        reboot = await client.execute(
            "exec-4", "system.reboot", {"confirm": True, "dry_run": True}, output
        )
        assert reboot["status"] == "ok"
        assert reboot["result"]["dry_run"] is True
    finally:
        server.close()
        await server.wait_closed()

    records = [
        json.loads(line) for line in audit.read_text().splitlines() if line.strip()
    ]
    assert any(r["tool"] == "shell.exec" for r in records)
    assert all("mac" not in json.dumps(r) for r in records)
    assert "printf helper-ok" not in audit.read_text()


@pytest.mark.asyncio
async def test_wrong_helper_secret_is_rejected(tmp_path):
    secret = tmp_path / "helper.key"
    secret.write_bytes(b"a" * 48)
    secret.chmod(0o640)
    wrong = tmp_path / "wrong.key"
    wrong.write_bytes(b"b" * 48)
    policy = tmp_path / "policy.json"
    policy.write_text(
        json.dumps(
            {
                "configured_max_permission_profile": "FULL_CONTROL",
                "allowed_helper_uids": [os.getuid()],
            }
        )
    )
    sock = tmp_path / "helper.sock"
    helper = HelperServer(str(sock), str(secret), str(policy), None)
    server = await asyncio.start_unix_server(
        helper.handle, path=str(sock), limit=32 * 1024 * 1024
    )
    try:
        probe = await HelperClient(str(sock), str(wrong), timeout=1).probe()
        assert probe["available"] is False
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_runtime_capabilities_fail_closed_without_helper(tmp_path, monkeypatch):
    policy = tmp_path / "policy.json"
    policy.write_text(
        json.dumps(
            {
                "configured_max_permission_profile": "FULL_CONTROL",
                "allowed_helper_uids": [os.getuid()],
            }
        )
    )
    monkeypatch.setenv("COMMANDCORE_AGENT_POLICY", str(policy))
    monkeypatch.setenv("COMMANDCORE_HELPER_SOCKET", str(tmp_path / "missing.sock"))
    monkeypatch.setenv("COMMANDCORE_HELPER_SECRET", str(tmp_path / "missing.key"))
    caps = await build_runtime_capabilities(CAPABILITIES)
    if os.getuid() != 0:
        assert caps["configured_max_permission_profile"] == "READ_ONLY"
        assert caps["local_max_permission_profile"] == "READ_ONLY"
        assert caps["policy_error"]
        assert caps["privileged_helper"] is False
        return
    assert caps["configured_max_permission_profile"] == "FULL_CONTROL"
    assert caps["privileged_helper"] is False
    assert caps["local_max_permission_profile"] == "STANDARD"
