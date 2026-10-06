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


def wait_http(url):
    for _ in range(100):
        try:
            if httpx.get(url, timeout=1).status_code < 500:
                return
        except Exception:
            pass
        time.sleep(0.1)
    raise RuntimeError("server not ready")


def stop(p):
    if p and p.poll() is None:
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
            "name": "restricted-smoke",
            "version": "0.8.0",
        },
        "io.modelcontextprotocol/clientCapabilities": {},
    }


def mcp(base, token, name, args, rid):
    body = {
        "jsonrpc": "2.0",
        "id": rid,
        "method": "tools/call",
        "params": {"name": name, "arguments": args, "_meta": meta()},
    }
    h = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": "2026-07-28",
        "Mcp-Method": "tools/call",
        "Mcp-Name": name,
    }
    r = httpx.post(base + "/mcp", json=body, headers=h, timeout=20)
    r.raise_for_status()
    return r.json()


def main():
    port = free_port()
    base = f"http://{HOST}:{port}"
    agent_url = f"ws://{HOST}:{port}/agent"
    token = "restricted-mode-token-0123456789abcdef"
    with tempfile.TemporaryDirectory(prefix="cc-restricted-") as raw:
        td = Path(raw)
        policy = td / "policy.json"
        policy.write_text(
            json.dumps(
                {
                    "configured_max_permission_profile": "READ_ONLY",
                    "allowed_helper_uids": [],
                }
            )
        )
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
                "COMMANDCORE_DB": str(td / "db.sqlite3"),
                "COMMANDCORE_API_TOKEN": token,
                "COMMANDCORE_PUBLIC_BOOTSTRAP_ENABLED": "true",
                "COMMANDCORE_BOOTSTRAP_SUBJECT": "restricted-owner",
                "COMMANDCORE_AGENT_STATE": str(td / "agent.json"),
                "COMMANDCORE_AGENT_POLICY": str(policy),
                "COMMANDCORE_HELPER_SOCKET": str(td / "missing.sock"),
                "COMMANDCORE_HELPER_SECRET": str(td / "missing.key"),
            }
        )
        sl = (td / "server.log").open("w+")
        al = (td / "agent.log").open("w+")
        server = subprocess.Popen(
            [sys.executable, "-m", "commandcore_server.main"],
            cwd=ROOT,
            env=env,
            stdout=sl,
            stderr=subprocess.STDOUT,
            text=True,
        )
        agent = None
        try:
            wait_http(base + "/healthz")
            auth = {"Authorization": f"Bearer {token}"}
            e = httpx.post(base + "/api/enrollment-tokens", headers=auth)
            e.raise_for_status()
            en = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "commandcore_agent.cli",
                    "enroll",
                    e.json()["token"],
                    "--control-url",
                    base,
                    "--agent-url",
                    agent_url,
                    "--state",
                    str(td / "agent.json"),
                    "--name",
                    "restricted-device",
                ],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                timeout=15,
            )
            assert en.returncode == 0, en.stderr
            did = json.loads(en.stdout.split("Device is pending", 1)[0])["device_id"]
            httpx.post(
                base + f"/api/devices/{did}/approve", headers=auth
            ).raise_for_status()
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
                stdout=al,
                stderr=subprocess.STDOUT,
                text=True,
            )
            device = None
            for _ in range(100):
                ds = httpx.get(base + "/api/devices", headers=auth).json()["devices"]
                device = next(
                    (d for d in ds if d["id"] == did and d["status"] == "online"), None
                )
                if device:
                    break
                time.sleep(0.1)
            assert device and device["permission_profile"] == "READ_ONLY", device
            elevate = httpx.post(
                base + f"/api/devices/{did}/permissions",
                headers=auth,
                json={"profile": "STANDARD"},
            )
            assert elevate.status_code == 409, elevate.text
            sel = mcp(base, token, "devices.select", {"device": did}, 1)["result"][
                "structuredContent"
            ]["selection_id"]
            read = mcp(
                base,
                token,
                "fs.read",
                {"selection_id": sel, "path": "/etc/hostname"},
                2,
            )
            assert "result" in read, read
            shell = mcp(
                base, token, "shell.exec", {"selection_id": sel, "command": "id"}, 3
            )
            assert "error" in shell or shell.get("result", {}).get("isError"), shell
            print(
                json.dumps(
                    {
                        "status": "PASS",
                        "device_id": did,
                        "local_max": "READ_ONLY",
                        "server_profile": device["permission_profile"],
                        "read_allowed": True,
                        "shell_denied": True,
                        "server_elevation_denied": True,
                    },
                    indent=2,
                )
            )
            return 0
        finally:
            stop(agent)
            stop(server)
            sl.close()
            al.close()


if __name__ == "__main__":
    raise SystemExit(main())
