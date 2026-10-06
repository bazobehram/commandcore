#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
HOST = "127.0.0.1"


def free_port() -> int:
    with socket.socket() as s:
        s.bind((HOST, 0))
        return int(s.getsockname()[1])


def wait_http(url: str, timeout=20.0):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            r = httpx.get(url, timeout=1)
            if r.status_code < 500:
                return
            last = f"status {r.status_code}"
        except Exception as exc:
            last = exc
        time.sleep(0.2)
    raise RuntimeError(f"server not ready: {last}")


def wait_online(base: str, token: str, device_id: str, timeout=20.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = httpx.get(
            base + "/api/devices",
            headers={"Authorization": f"Bearer {token}"},
            timeout=2,
        )
        r.raise_for_status()
        for d in r.json()["devices"]:
            if d["id"] == device_id and d["status"] == "online":
                return d
        time.sleep(0.25)
    raise RuntimeError("agent did not become online")


def meta():
    return {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientInfo": {
            "name": "commandcore-smoke",
            "version": "0.8.0",
        },
        "io.modelcontextprotocol/clientCapabilities": {},
    }


def mcp(base: str, token: str, method: str, params: dict, request_id: int):
    body = {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": method,
        "params": {**params, "_meta": meta()},
    }
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": "2026-07-28",
        "Mcp-Method": method,
    }
    if method == "tools/call":
        headers["Mcp-Name"] = str(params["name"])
    r = httpx.post(base + "/mcp", json=body, headers=headers, timeout=40)
    r.raise_for_status()
    data = r.json()
    if "error" in data:
        raise RuntimeError(data["error"])
    return data["result"]


def stop_process(p: subprocess.Popen):
    if p.poll() is not None:
        return
    p.terminate()
    try:
        p.wait(timeout=5)
    except subprocess.TimeoutExpired:
        p.kill()
        p.wait(timeout=5)


def main() -> int:
    port = free_port()
    base = f"http://{HOST}:{port}"
    agent_url = f"ws://{HOST}:{port}/agent"
    token = "integration-test-bootstrap-token-0123456789abcdef"
    with tempfile.TemporaryDirectory(prefix="commandcore-smoke-") as td:
        td = Path(td)
        env = os.environ.copy()
        env.update(
            {
                "PYTHONPATH": os.pathsep.join(
                    [
                        str(ROOT / "apps/server"),
                        str(ROOT / "agent"),
                        env.get("PYTHONPATH", ""),
                    ]
                ),
                "COMMANDCORE_HOST": HOST,
                "COMMANDCORE_PORT": str(port),
                "COMMANDCORE_DB": str(td / "commandcore.sqlite3"),
                "COMMANDCORE_API_TOKEN": token,
                "COMMANDCORE_PUBLIC_BOOTSTRAP_ENABLED": "true",
                "COMMANDCORE_BOOTSTRAP_SUBJECT": "smoke-owner",
                "COMMANDCORE_PUBLIC_BASE_URL": base,
                "COMMANDCORE_AGENT_BASE_URL": agent_url,
                "COMMANDCORE_AGENT_STATE": str(td / "agent.json"),
            }
        )
        server_log = (td / "server.log").open("w+")
        agent_log = (td / "agent.log").open("w+")
        server = subprocess.Popen(
            [sys.executable, "-m", "commandcore_server.main"],
            cwd=ROOT,
            env=env,
            stdout=server_log,
            stderr=subprocess.STDOUT,
            text=True,
        )
        agent = None
        try:
            wait_http(base + "/healthz")
            auth = {"Authorization": f"Bearer {token}"}
            e = httpx.post(base + "/api/enrollment-tokens", headers=auth, timeout=5)
            e.raise_for_status()
            enroll_token = e.json()["token"]

            enroll = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "commandcore_agent.cli",
                    "enroll",
                    enroll_token,
                    "--control-url",
                    base,
                    "--agent-url",
                    agent_url,
                    "--name",
                    "smoke-device",
                    "--state",
                    str(td / "agent.json"),
                ],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                timeout=20,
            )
            if enroll.returncode != 0:
                raise RuntimeError("enroll failed: " + enroll.stdout + enroll.stderr)
            enroll_json = json.loads(enroll.stdout.split("Device is pending", 1)[0])
            device_id = enroll_json["device_id"]

            a = httpx.post(
                base + f"/api/devices/{device_id}/approve", headers=auth, timeout=5
            )
            a.raise_for_status()
            agent = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "commandcore_agent.cli",
                    "run",
                    "--state",
                    str(td / "agent.json"),
                ],
                cwd=ROOT,
                env=env,
                stdout=agent_log,
                stderr=subprocess.STDOUT,
                text=True,
            )
            device = wait_online(base, token, device_id)
            health_path = td / "health.json"
            for _ in range(50):
                if health_path.exists():
                    break
                time.sleep(0.05)
            health = json.loads(health_path.read_text())
            assert (
                health["connected"] is True
                and health["version"] == (ROOT / "VERSION").read_text().strip()
            ), health

            discover = mcp(base, token, "server/discover", {}, 1)
            assert "2026-07-28" in discover["supportedVersions"]

            tools = mcp(base, token, "tools/list", {}, 2)
            names = {x["name"] for x in tools["tools"]}
            assert {
                "devices.list",
                "devices.select",
                "shell.exec",
                "process.list",
                "fs.read",
                "git.status",
                "git.run",
                "docker.ps",
            }.issubset(names)

            listed = mcp(
                base, token, "tools/call", {"name": "devices.list", "arguments": {}}, 3
            )
            listed_payload = listed["structuredContent"]
            assert any(d["id"] == device_id for d in listed_payload["devices"])

            selected = mcp(
                base,
                token,
                "tools/call",
                {"name": "devices.select", "arguments": {"device": device_id}},
                4,
            )
            selection_id = selected["structuredContent"]["selection_id"]

            executed = mcp(
                base,
                token,
                "tools/call",
                {
                    "name": "shell.exec",
                    "arguments": {
                        "selection_id": selection_id,
                        "command": "hostname",
                        "timeout_ms": 5000,
                    },
                },
                5,
            )
            payload = executed["structuredContent"]
            expected = socket.gethostname()
            got = payload["stdout"].strip()
            assert payload["exit_code"] == 0, payload
            assert got == expected, (got, expected, payload)

            git_status_ok = None
            git_run_ok = None
            import shutil

            if shutil.which("git"):
                repo = td / "git-smoke"
                repo.mkdir()
                subprocess.run(
                    ["git", "-C", str(repo), "init"],
                    check=True,
                    stdout=subprocess.DEVNULL,
                )
                subprocess.run(
                    [
                        "git",
                        "-C",
                        str(repo),
                        "config",
                        "user.email",
                        "smoke@example.test",
                    ],
                    check=True,
                )
                subprocess.run(
                    ["git", "-C", str(repo), "config", "user.name", "Smoke"], check=True
                )
                (repo / "proof.txt").write_text("commandcore-v0.7\n")
                subprocess.run(["git", "-C", str(repo), "add", "proof.txt"], check=True)
                subprocess.run(
                    ["git", "-C", str(repo), "commit", "-m", "smoke"],
                    check=True,
                    stdout=subprocess.DEVNULL,
                )
                gstatus = mcp(
                    base,
                    token,
                    "tools/call",
                    {
                        "name": "git.status",
                        "arguments": {"selection_id": selection_id, "repo": str(repo)},
                    },
                    6,
                )["structuredContent"]
                assert gstatus["result"]["clean"] is True, gstatus
                git_status_ok = True
                grun = mcp(
                    base,
                    token,
                    "tools/call",
                    {
                        "name": "git.run",
                        "arguments": {
                            "selection_id": selection_id,
                            "repo": str(repo),
                            "args": ["rev-parse", "--is-inside-work-tree"],
                        },
                    },
                    7,
                )["structuredContent"]
                assert grun["stdout"].strip() == "true", grun
                git_run_ok = True

            print(
                json.dumps(
                    {
                        "status": "PASS",
                        "protocol": "2026-07-28",
                        "device_id": device_id,
                        "device_status": device["status"],
                        "selection_id": selection_id,
                        "command": "hostname",
                        "expected_hostname": expected,
                        "returned_hostname": got,
                        "git_status": git_status_ok,
                        "git_run": git_run_ok,
                        "fresh_connected_health": health["connected"],
                        "agent_version": health["version"],
                        "round_trip": "MCP -> CommandCore -> Agent -> shell/git -> Agent -> CommandCore -> MCP",
                    },
                    indent=2,
                )
            )
            return 0
        except Exception:
            server_log.flush()
            agent_log.flush()
            server_log.seek(0)
            agent_log.seek(0)
            print("--- server log ---", file=sys.stderr)
            print(server_log.read(), file=sys.stderr)
            print("--- agent log ---", file=sys.stderr)
            print(agent_log.read(), file=sys.stderr)
            raise
        finally:
            if agent is not None:
                stop_process(agent)
            stop_process(server)
            server_log.close()
            agent_log.close()


if __name__ == "__main__":
    raise SystemExit(main())
