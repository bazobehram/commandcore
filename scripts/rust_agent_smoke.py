#!/usr/bin/env python3
from __future__ import annotations
import json, os, socket, subprocess, sys, tempfile, time, tomllib
from pathlib import Path
import httpx

ROOT = Path(__file__).resolve().parents[1]
HOST = "127.0.0.1"
BIN = Path(
    os.environ.get(
        "COMMANDCORE_RUST_AGENT_BIN",
        ROOT / "agent/rust/target/debug/commandcore-agent-rust",
    )
)
VERSION = tomllib.loads((ROOT / "agent/rust/Cargo.toml").read_text())["package"][
    "version"
]


def free_port():
    with socket.socket() as s:
        s.bind((HOST, 0))
        return int(s.getsockname()[1])


def wait_http(url, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        try:
            r = httpx.get(url, timeout=1)
            if r.status_code < 500:
                return
        except Exception:
            pass
        time.sleep(0.2)
    raise RuntimeError("server not ready")


def stop(p):
    if p is None or p.poll() is not None:
        return
    p.terminate()
    try:
        p.wait(5)
    except subprocess.TimeoutExpired:
        p.kill()
        p.wait(5)


def wait_online(base, token, did, implementation="rust", timeout=25):
    end = time.time() + timeout
    while time.time() < end:
        r = httpx.get(
            base + "/api/devices",
            headers={"Authorization": f"Bearer {token}"},
            timeout=2,
        )
        r.raise_for_status()
        for d in r.json()["devices"]:
            if (
                d["id"] == did
                and d["status"] == "online"
                and d.get("capabilities", {}).get("agent_implementation")
                == implementation
            ):
                return d
        time.sleep(0.2)
    raise RuntimeError("Rust Agent did not become online")


def meta():
    return {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientInfo": {
            "name": "commandcore-rust-smoke",
            "version": "0.8.0",
        },
        "io.modelcontextprotocol/clientCapabilities": {},
    }


def mcp(base, token, name, args, rid, timeout=45):
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
    r = httpx.post(base + "/mcp", json=body, headers=h, timeout=timeout)
    r.raise_for_status()
    data = r.json()
    if "error" in data:
        raise RuntimeError(data["error"])
    return data["result"]["structuredContent"]


def main():
    if not BIN.exists():
        raise RuntimeError(f"Rust Agent binary not found: {BIN}")
    port = free_port()
    base = f"http://{HOST}:{port}"
    agent_url = f"ws://{HOST}:{port}/agent"
    token = "rust-agent-smoke-token-0123456789abcdef"
    with tempfile.TemporaryDirectory(prefix="commandcore-rust-smoke-") as tmp:
        td = Path(tmp)
        state = td / "agent.json"
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
                "COMMANDCORE_DB": str(td / "cc.sqlite3"),
                "COMMANDCORE_API_TOKEN": token,
                "COMMANDCORE_PUBLIC_BOOTSTRAP_ENABLED": "true",
                "COMMANDCORE_BOOTSTRAP_SUBJECT": "rust-owner",
                "COMMANDCORE_PUBLIC_BASE_URL": base,
                "COMMANDCORE_AGENT_BASE_URL": agent_url,
                "COMMANDCORE_AGENT_STATE": str(state),
                "COMMANDCORE_AGENT_POLICY": str(td / "policy.json"),
            }
        )
        (td / "policy.json").write_text(
            json.dumps({"configured_max_permission_profile": "STANDARD"})
        )
        slog = (td / "server.log").open("w+")
        alog = (td / "agent.log").open("w+")
        server = agent = None
        try:
            server = subprocess.Popen(
                [sys.executable, "-m", "commandcore_server.main"],
                cwd=ROOT,
                env=env,
                stdout=slog,
                stderr=subprocess.STDOUT,
                text=True,
            )
            wait_http(base + "/healthz")
            auth = {"Authorization": f"Bearer {token}"}
            e = httpx.post(base + "/api/enrollment-tokens", headers=auth, timeout=5)
            e.raise_for_status()
            enroll_token = e.json()["token"]
            er = subprocess.run(
                [
                    str(BIN),
                    "enroll",
                    enroll_token,
                    "--control-url",
                    base,
                    "--agent-url",
                    agent_url,
                    "--name",
                    "rust-smoke",
                    "--state",
                    str(state),
                ],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                timeout=20,
            )
            if er.returncode != 0:
                raise RuntimeError("Rust enroll failed: " + er.stdout + er.stderr)
            did = json.loads(er.stdout)["device_id"]
            sr = subprocess.run(
                [str(BIN), "status", "--json", "--state", str(state)],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                timeout=10,
            )
            assert sr.returncode == 0, sr.stdout + sr.stderr
            status = json.loads(sr.stdout)
            assert (
                status["device_id"] == did and status["agent_implementation"] == "rust"
            ), status
            httpx.post(
                base + f"/api/devices/{did}/approve", headers=auth, timeout=5
            ).raise_for_status()
            agent = subprocess.Popen(
                [str(BIN), "run", "--state", str(state)],
                cwd=ROOT,
                env=env,
                stdout=alog,
                stderr=subprocess.STDOUT,
                text=True,
            )
            wait_online(base, token, did)
            health = td / "health.json"
            for _ in range(100):
                if health.exists():
                    break
                time.sleep(0.05)
            hp = json.loads(health.read_text())
            assert (
                hp["connected"] is True
                and hp["implementation"] == "rust"
                and hp["version"] == VERSION
            ), hp
            sid = mcp(base, token, "devices.select", {"device": did}, 1)["selection_id"]
            who = mcp(
                base,
                token,
                "shell.exec",
                {"selection_id": sid, "command": "hostname", "timeout_ms": 5000},
                2,
            )
            assert who["stdout"].strip() == socket.gethostname(), who
            info = mcp(base, token, "system.info", {"selection_id": sid}, 3)
            assert info["result"]["agent_implementation"] == "rust", info
            probe = td / "rust.txt"
            mcp(
                base,
                token,
                "fs.write",
                {"selection_id": sid, "path": str(probe), "data": "rust-parity"},
                4,
            )
            read = mcp(
                base, token, "fs.read", {"selection_id": sid, "path": str(probe)}, 5
            )
            assert read["result"]["data"] == "rust-parity", read
            procs = mcp(
                base, token, "process.list", {"selection_id": sid, "limit": 25}, 6
            )
            assert "processes" in procs["result"], procs
            started = mcp(
                base,
                token,
                "process.start",
                {"selection_id": sid, "command": "printf alpha; sleep 30"},
                7,
            )
            pid = started["result"]["process_id"]
            captured = False
            for _ in range(50):
                out = mcp(
                    base,
                    token,
                    "process.output",
                    {"selection_id": sid, "process_id": pid},
                    8,
                )
                if "alpha" in out["result"].get("stdout", ""):
                    captured = True
                    break
                time.sleep(0.05)
            assert captured, out
            stopped = mcp(
                base, token, "process.stop", {"selection_id": sid, "process_id": pid}, 9
            )
            assert stopped["status"] in {"ok", "completed"}, stopped
            for _ in range(50):
                ps = mcp(
                    base,
                    token,
                    "process.status",
                    {"selection_id": sid, "process_id": pid},
                    10,
                )
                if not ps["result"].get("running", True):
                    break
                time.sleep(0.05)
            assert ps["result"].get("running") is False, ps
            stop(agent)
            agent = None
            rr = subprocess.run(
                [str(BIN), "rotate-key", "--state", str(state)],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                timeout=25,
            )
            assert rr.returncode == 0, rr.stdout + rr.stderr
            rotated = json.loads(rr.stdout)
            assert rotated["key_generation"] >= 2, rotated
            agent = subprocess.Popen(
                [str(BIN), "run", "--state", str(state)],
                cwd=ROOT,
                env=env,
                stdout=alog,
                stderr=subprocess.STDOUT,
                text=True,
            )
            wait_online(base, token, did)
            sid = mcp(base, token, "devices.select", {"device": did}, 11)[
                "selection_id"
            ]
            again = mcp(
                base,
                token,
                "shell.exec",
                {"selection_id": sid, "command": "hostname"},
                12,
            )
            assert again["stdout"].strip() == socket.gethostname(), again
            (td / "policy.json").write_text(
                json.dumps({"configured_max_permission_profile": "READ_ONLY"})
            )
            denied = mcp(
                base, token, "shell.exec", {"selection_id": sid, "command": "id"}, 13
            )
            assert "error" in denied, denied
            readonly = mcp(
                base, token, "fs.read", {"selection_id": sid, "path": str(probe)}, 14
            )
            assert readonly["result"]["data"] == "rust-parity", readonly
            print(
                json.dumps(
                    {
                        "status": "PASS",
                        "agent_implementation": "rust",
                        "device_id": did,
                        "key_generation": rotated["key_generation"],
                        "hostname": again["stdout"].strip(),
                        "fresh_health": True,
                        "fs_round_trip": True,
                        "process_list": True,
                        "managed_process_stream_and_cancel": True,
                        "local_read_only_ceiling": True,
                        "round_trip": "MCP -> CommandCore -> Rust Agent -> OS -> MCP",
                    },
                    indent=2,
                )
            )
            return 0
        except Exception:
            slog.flush()
            alog.flush()
            slog.seek(0)
            alog.seek(0)
            print("--- server ---\n" + slog.read(), file=sys.stderr)
            print("--- rust agent ---\n" + alog.read(), file=sys.stderr)
            raise
        finally:
            stop(agent)
            stop(server)
            slog.close()
            alog.close()


if __name__ == "__main__":
    raise SystemExit(main())
