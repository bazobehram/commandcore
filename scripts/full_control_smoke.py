#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import pwd
import grp
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import uuid
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
    while time.time() < deadline:
        try:
            r = httpx.get(url, timeout=1)
            if r.status_code < 500:
                return
        except Exception:
            pass
        time.sleep(0.2)
    raise RuntimeError("server not ready")


def wait_path(path: Path, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if path.exists():
            return
        time.sleep(0.1)
    raise RuntimeError(f"path not ready: {path}")


def wait_online(base, token, did, timeout=20.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = httpx.get(
            base + "/api/devices",
            headers={"Authorization": f"Bearer {token}"},
            timeout=2,
        )
        r.raise_for_status()
        for d in r.json()["devices"]:
            if d["id"] == did and d["status"] == "online":
                return d
        time.sleep(0.2)
    raise RuntimeError("agent did not become online")


def meta():
    return {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientInfo": {
            "name": "commandcore-full-smoke",
            "version": "0.8.0",
        },
        "io.modelcontextprotocol/clientCapabilities": {},
    }


def mcp(base, token, method, params, rid, timeout=45):
    body = {
        "jsonrpc": "2.0",
        "id": rid,
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
    r = httpx.post(base + "/mcp", json=body, headers=headers, timeout=timeout)
    r.raise_for_status()
    data = r.json()
    if "error" in data:
        raise RuntimeError(data["error"])
    return data["result"]


def stop(p):
    if p is None or p.poll() is not None:
        return
    p.terminate()
    try:
        p.wait(timeout=5)
    except subprocess.TimeoutExpired:
        p.kill()
        p.wait(timeout=5)


def main() -> int:
    if os.geteuid() != 0:
        print(
            json.dumps(
                {
                    "status": "SKIP",
                    "reason": "full-control privilege-separation smoke requires root build environment",
                },
                indent=2,
            )
        )
        return 0
    nobody = pwd.getpwnam("nobody")
    nogroup = grp.getgrnam("nogroup")
    port = free_port()
    base = f"http://{HOST}:{port}"
    agent_url = f"ws://{HOST}:{port}/agent"
    token = "full-control-integration-token-0123456789abcdef"
    root_private = Path(tempfile.mkdtemp(prefix="commandcore-root-private-"))
    os.chmod(root_private, 0o700)
    with tempfile.TemporaryDirectory(prefix="commandcore-full-smoke-") as tmp:
        td = Path(tmp)
        os.chmod(td, 0o755)
        agent_state = td / "agent-state"
        agent_state.mkdir(mode=0o700)
        os.chown(agent_state, nobody.pw_uid, nogroup.gr_gid)
        policy = td / "agent-policy.json"
        secret = td / "helper.key"
        sock = td / "helper.sock"
        audit = td / "helper-audit.jsonl"
        state = agent_state / "agent.json"
        policy.write_text(
            json.dumps(
                {
                    "configured_max_permission_profile": "FULL_CONTROL",
                    "allowed_helper_uids": [nobody.pw_uid],
                }
            )
        )
        os.chmod(policy, 0o644)
        secret.write_bytes(os.urandom(48))
        os.chown(secret, 0, nogroup.gr_gid)
        os.chmod(secret, 0o640)
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
                "COMMANDCORE_BOOTSTRAP_SUBJECT": "full-owner",
                "COMMANDCORE_PUBLIC_BASE_URL": base,
                "COMMANDCORE_AGENT_BASE_URL": agent_url,
                "COMMANDCORE_AGENT_STATE": str(state),
                "COMMANDCORE_AGENT_POLICY": str(policy),
                "COMMANDCORE_HELPER_SECRET": str(secret),
                "COMMANDCORE_HELPER_SOCKET": str(sock),
                "COMMANDCORE_HELPER_SOCKET_GROUP": "nogroup",
                "COMMANDCORE_HELPER_AUDIT": str(audit),
            }
        )
        server_log = (td / "server.log").open("w+")
        helper_log = (td / "helper.log").open("w+")
        agent_log = (td / "agent.log").open("w+")
        server = helper = agent = None
        try:
            helper = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "commandcore_agent.privileged_helper",
                    "serve",
                    "--socket",
                    str(sock),
                    "--secret-file",
                    str(secret),
                    "--policy-file",
                    str(policy),
                    "--audit-file",
                    str(audit),
                ],
                cwd=ROOT,
                env=env,
                stdout=helper_log,
                stderr=subprocess.STDOUT,
                text=True,
            )
            wait_path(sock)
            server = subprocess.Popen(
                [sys.executable, "-m", "commandcore_server.main"],
                cwd=ROOT,
                env=env,
                stdout=server_log,
                stderr=subprocess.STDOUT,
                text=True,
            )
            wait_http(base + "/healthz")
            auth = {"Authorization": f"Bearer {token}"}
            e = httpx.post(base + "/api/enrollment-tokens", headers=auth, timeout=5)
            e.raise_for_status()
            enroll_token = e.json()["token"]
            setpriv = [
                "setpriv",
                f"--reuid={nobody.pw_uid}",
                f"--regid={nogroup.gr_gid}",
                "--clear-groups",
            ]
            enroll = subprocess.run(
                [
                    *setpriv,
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
                    "full-smoke-device",
                    "--state",
                    str(state),
                ],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                timeout=20,
            )
            if enroll.returncode != 0:
                raise RuntimeError("enroll failed: " + enroll.stdout + enroll.stderr)
            did = json.loads(enroll.stdout.split("Device is pending", 1)[0])[
                "device_id"
            ]
            httpx.post(
                base + f"/api/devices/{did}/approve", headers=auth, timeout=5
            ).raise_for_status()
            p = httpx.post(
                base + f"/api/devices/{did}/permissions",
                headers=auth,
                json={"profile": "FULL_CONTROL"},
                timeout=5,
            )
            p.raise_for_status()
            agent = subprocess.Popen(
                [
                    *setpriv,
                    sys.executable,
                    "-m",
                    "commandcore_agent.cli",
                    "run",
                    "--state",
                    str(state),
                ],
                cwd=ROOT,
                env=env,
                stdout=agent_log,
                stderr=subprocess.STDOUT,
                text=True,
            )
            device = wait_online(base, token, did)
            assert device["permission_profile"] == "FULL_CONTROL", device
            assert device["capabilities"]["privileged_helper"] is True, device
            selected = mcp(
                base,
                token,
                "tools/call",
                {"name": "devices.select", "arguments": {"device": did}},
                1,
            )["structuredContent"]
            sid = selected["selection_id"]
            who = mcp(
                base,
                token,
                "tools/call",
                {
                    "name": "shell.exec",
                    "arguments": {
                        "selection_id": sid,
                        "command": "id -u",
                        "timeout_ms": 5000,
                    },
                },
                2,
            )["structuredContent"]
            assert who["stdout"].strip() == "0", who
            target = root_private / f"proof-{uuid.uuid4().hex}.txt"
            wrote = mcp(
                base,
                token,
                "tools/call",
                {
                    "name": "fs.write",
                    "arguments": {
                        "selection_id": sid,
                        "path": str(target),
                        "data": "privilege-separated-full-control",
                    },
                },
                3,
            )["structuredContent"]
            assert wrote["status"] == "ok", wrote
            assert (
                target.exists()
                and target.read_text() == "privilege-separated-full-control"
            )
            read = mcp(
                base,
                token,
                "tools/call",
                {
                    "name": "fs.read",
                    "arguments": {"selection_id": sid, "path": str(target)},
                },
                4,
            )["structuredContent"]
            assert read["result"]["data"] == "privilege-separated-full-control", read
            dry = mcp(
                base,
                token,
                "tools/call",
                {
                    "name": "system.reboot",
                    "arguments": {
                        "selection_id": sid,
                        "confirm": True,
                        "dry_run": True,
                    },
                },
                5,
            )["structuredContent"]
            assert dry["result"]["dry_run"] is True, dry
            docker_daemon = None
            if shutil.which("docker"):
                probe = subprocess.run(
                    ["docker", "info"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=10,
                )
                if probe.returncode == 0:
                    docker_result = mcp(
                        base,
                        token,
                        "tools/call",
                        {
                            "name": "docker.ps",
                            "arguments": {"selection_id": sid, "all": True},
                        },
                        6,
                    )["structuredContent"]
                    assert "result" in docker_result, docker_result
                    docker_daemon = True
            print(
                json.dumps(
                    {
                        "status": "PASS",
                        "agent_uid": nobody.pw_uid,
                        "helper_uid": 0,
                        "device_id": did,
                        "permission_profile": device["permission_profile"],
                        "privileged_helper": device["capabilities"][
                            "privileged_helper"
                        ],
                        "shell_exec_id_u": who["stdout"].strip(),
                        "root_only_file": str(target),
                        "root_only_file_round_trip": True,
                        "reboot_dry_run": True,
                        "docker_daemon_smoke": docker_daemon,
                        "round_trip": "MCP -> CommandCore -> unprivileged Agent -> authenticated Unix IPC -> root helper -> OS -> MCP",
                    },
                    indent=2,
                )
            )
            return 0
        except Exception:
            for f in (server_log, helper_log, agent_log):
                f.flush()
                f.seek(0)
            print("--- server log ---\n" + server_log.read(), file=sys.stderr)
            print("--- helper log ---\n" + helper_log.read(), file=sys.stderr)
            print("--- agent log ---\n" + agent_log.read(), file=sys.stderr)
            raise
        finally:
            stop(agent)
            stop(server)
            stop(helper)
            server_log.close()
            helper_log.close()
            agent_log.close()
            shutil.rmtree(root_private, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
