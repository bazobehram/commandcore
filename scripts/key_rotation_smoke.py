#!/usr/bin/env python3
from __future__ import annotations

import json, os, socket, subprocess, sys, tempfile, time
from pathlib import Path
import httpx

ROOT = Path(__file__).resolve().parents[1]
HOST = "127.0.0.1"


def free_port():
    with socket.socket() as s:
        s.bind((HOST, 0))
        return s.getsockname()[1]


def wait_http(url, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        try:
            if httpx.get(url, timeout=1).status_code < 500:
                return
        except Exception:
            pass
        time.sleep(0.2)
    raise RuntimeError("server not ready")


def wait_online(base, token, did, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        data = httpx.get(
            base + "/api/devices",
            headers={"Authorization": f"Bearer {token}"},
            timeout=2,
        ).json()["devices"]
        for d in data:
            if d["id"] == did and d["status"] == "online":
                return d
        time.sleep(0.2)
    raise RuntimeError("agent not online")


def stop(p):
    if p is None or p.poll() is not None:
        return
    p.terminate()
    try:
        p.wait(5)
    except subprocess.TimeoutExpired:
        p.kill()
        p.wait(5)


def meta():
    return {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientInfo": {
            "name": "key-rotation-smoke",
            "version": "0.8.0",
        },
        "io.modelcontextprotocol/clientCapabilities": {},
    }


def mcp(base, token, name, arguments, rid):
    body = {
        "jsonrpc": "2.0",
        "id": rid,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments, "_meta": meta()},
    }
    h = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": "2026-07-28",
        "Mcp-Method": "tools/call",
        "Mcp-Name": name,
    }
    r = httpx.post(base + "/mcp", json=body, headers=h, timeout=30)
    r.raise_for_status()
    d = r.json()
    if "error" in d:
        raise RuntimeError(d["error"])
    return d["result"]["structuredContent"]


def main():
    port = free_port()
    base = f"http://{HOST}:{port}"
    agent_url = f"ws://{HOST}:{port}/agent"
    token = "key-rotation-smoke-token-0123456789abcdef"
    with tempfile.TemporaryDirectory(prefix="cc-key-rotate-") as raw:
        td = Path(raw)
        state = td / "agent.json"
        db = td / "db.sqlite3"
        server_log = (td / "server.log").open("w+")
        env = os.environ.copy()
        env.update(
            {
                "PYTHONPATH": os.pathsep.join(
                    [str(ROOT / "apps/server"), str(ROOT / "agent")]
                ),
                "COMMANDCORE_HOST": HOST,
                "COMMANDCORE_PORT": str(port),
                "COMMANDCORE_DB": str(db),
                "COMMANDCORE_API_TOKEN": token,
                "COMMANDCORE_PUBLIC_BOOTSTRAP_ENABLED": "true",
                "COMMANDCORE_BOOTSTRAP_SUBJECT": "owner",
                "COMMANDCORE_PUBLIC_BASE_URL": base,
                "COMMANDCORE_AGENT_BASE_URL": agent_url,
            }
        )
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
            er = httpx.post(base + "/api/enrollment-tokens", headers=auth, timeout=5)
            er.raise_for_status()
            e = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "commandcore_agent.cli",
                    "enroll",
                    er.json()["token"],
                    "--control-url",
                    base,
                    "--agent-url",
                    agent_url,
                    "--state",
                    str(state),
                ],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                timeout=20,
            )
            if e.returncode:
                raise RuntimeError(e.stdout + e.stderr)
            did = json.loads(e.stdout.split("Device is pending", 1)[0])["device_id"]
            httpx.post(
                base + f"/api/devices/{did}/approve", headers=auth, timeout=5
            ).raise_for_status()
            before = json.loads(state.read_text())
            old_pub = before["public_key_b64"]
            rotate = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "commandcore_agent.cli",
                    "rotate-key",
                    "--state",
                    str(state),
                ],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                timeout=25,
            )
            if rotate.returncode:
                raise RuntimeError("rotate failed: " + rotate.stdout + rotate.stderr)
            rotated = json.loads(rotate.stdout)
            after = json.loads(state.read_text())
            assert rotated["key_generation"] == 2 and after["key_generation"] == 2
            assert (
                after["public_key_b64"] != old_pub
                and after["pending_private_key_b64"] is None
            )
            agent_log = (td / "agent.log").open("w+")
            agent = subprocess.Popen(
                [
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
            dev = wait_online(base, token, did)
            assert dev["key_generation"] == 2
            sel = mcp(base, token, "devices.select", {"device": did}, 1)["selection_id"]
            out = mcp(
                base,
                token,
                "shell.exec",
                {"selection_id": sel, "command": "hostname", "timeout_ms": 5000},
                2,
            )
            assert out["stdout"].strip() == socket.gethostname()
            print(
                json.dumps(
                    {
                        "status": "PASS",
                        "device_id": did,
                        "old_key_replaced": True,
                        "key_generation": 2,
                        "post_rotation_reconnect": True,
                        "post_rotation_hostname": out["stdout"].strip(),
                    },
                    indent=2,
                )
            )
            return 0
        except Exception:
            server_log.flush()
            server_log.seek(0)
            print(server_log.read(), file=sys.stderr)
            raise
        finally:
            stop(agent)
            stop(server)
            server_log.close()


if __name__ == "__main__":
    raise SystemExit(main())
