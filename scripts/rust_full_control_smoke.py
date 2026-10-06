#!/usr/bin/env python3
from __future__ import annotations
import json, os, pwd, grp, shutil, socket, subprocess, sys, tempfile, time, uuid
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


def free_port():
    with socket.socket() as s:
        s.bind((HOST, 0))
        return int(s.getsockname()[1])


def wait_http(u, t=20):
    e = time.time() + t
    while time.time() < e:
        try:
            if httpx.get(u, timeout=1).status_code < 500:
                return
        except Exception:
            pass
        time.sleep(0.2)
    raise RuntimeError("server not ready")


def wait_path(p, t=10):
    e = time.time() + t
    while time.time() < e:
        if p.exists():
            return
        time.sleep(0.1)
    raise RuntimeError(f"not ready: {p}")


def wait_online(base, token, did, t=20):
    e = time.time() + t
    while time.time() < e:
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
                and d.get("capabilities", {}).get("agent_implementation") == "rust"
            ):
                return d
        time.sleep(0.2)
    raise RuntimeError("Rust Agent offline")


def stop(p):
    if p is None or p.poll() is not None:
        return
    p.terminate()
    try:
        p.wait(5)
    except subprocess.TimeoutExpired:
        p.kill()
        p.wait(5)


def mcp(base, token, name, args, rid):
    meta = {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientInfo": {
            "name": "rust-full-smoke",
            "version": "0.8.0",
        },
        "io.modelcontextprotocol/clientCapabilities": {},
    }
    body = {
        "jsonrpc": "2.0",
        "id": rid,
        "method": "tools/call",
        "params": {"name": name, "arguments": args, "_meta": meta},
    }
    h = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": "2026-07-28",
        "Mcp-Method": "tools/call",
        "Mcp-Name": name,
    }
    r = httpx.post(base + "/mcp", json=body, headers=h, timeout=45)
    r.raise_for_status()
    d = r.json()
    if "error" in d:
        raise RuntimeError(d["error"])
    return d["result"]["structuredContent"]


def main():
    if os.geteuid() != 0:
        return 0
    if not BIN.exists():
        raise RuntimeError(f"Rust Agent binary not found: {BIN}")
    nobody = pwd.getpwnam("nobody")
    nogroup = grp.getgrnam("nogroup")
    port = free_port()
    base = f"http://{HOST}:{port}"
    agent_url = f"ws://{HOST}:{port}/agent"
    token = "rust-full-token-0123456789abcdef"
    root_private = Path(tempfile.mkdtemp(prefix="cc-rust-root-"))
    os.chmod(root_private, 0o700)
    with tempfile.TemporaryDirectory(prefix="cc-rust-full-") as tmp:
        td = Path(tmp)
        os.chmod(td, 0o755)
        agent_state = td / "agent-state"
        agent_state.mkdir(mode=0o700)
        os.chown(agent_state, nobody.pw_uid, nogroup.gr_gid)
        policy = td / "policy.json"
        secret = td / "helper.key"
        sock = td / "helper.sock"
        audit = td / "audit.jsonl"
        state = agent_state / "agent.json"
        policy.write_text(
            json.dumps(
                {
                    "configured_max_permission_profile": "FULL_CONTROL",
                    "allowed_helper_uids": [nobody.pw_uid],
                }
            )
        )
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
                "COMMANDCORE_DB": str(td / "cc.sqlite3"),
                "COMMANDCORE_API_TOKEN": token,
                "COMMANDCORE_PUBLIC_BOOTSTRAP_ENABLED": "true",
                "COMMANDCORE_BOOTSTRAP_SUBJECT": "rust-full-owner",
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
        sl = (td / "s.log").open("w+")
        hl = (td / "h.log").open("w+")
        al = (td / "a.log").open("w+")
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
                stdout=hl,
                stderr=subprocess.STDOUT,
                text=True,
            )
            wait_path(sock)
            server = subprocess.Popen(
                [sys.executable, "-m", "commandcore_server.main"],
                cwd=ROOT,
                env=env,
                stdout=sl,
                stderr=subprocess.STDOUT,
                text=True,
            )
            wait_http(base + "/healthz")
            auth = {"Authorization": f"Bearer {token}"}
            e = httpx.post(base + "/api/enrollment-tokens", headers=auth, timeout=5)
            e.raise_for_status()
            et = e.json()["token"]
            setpriv = [
                "setpriv",
                f"--reuid={nobody.pw_uid}",
                f"--regid={nogroup.gr_gid}",
                "--clear-groups",
            ]
            er = subprocess.run(
                [
                    *setpriv,
                    str(BIN),
                    "enroll",
                    et,
                    "--control-url",
                    base,
                    "--agent-url",
                    agent_url,
                    "--name",
                    "rust-full",
                    "--state",
                    str(state),
                ],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                timeout=20,
            )
            assert er.returncode == 0, er.stdout + er.stderr
            did = json.loads(er.stdout)["device_id"]
            httpx.post(
                base + f"/api/devices/{did}/approve", headers=auth, timeout=5
            ).raise_for_status()
            httpx.post(
                base + f"/api/devices/{did}/permissions",
                headers=auth,
                json={"profile": "FULL_CONTROL"},
                timeout=5,
            ).raise_for_status()
            agent = subprocess.Popen(
                [*setpriv, str(BIN), "run", "--state", str(state)],
                cwd=ROOT,
                env=env,
                stdout=al,
                stderr=subprocess.STDOUT,
                text=True,
            )
            dev = wait_online(base, token, did)
            assert dev["capabilities"]["privileged_helper"] is True, dev
            sid = mcp(base, token, "devices.select", {"device": did}, 1)["selection_id"]
            who = mcp(
                base, token, "shell.exec", {"selection_id": sid, "command": "id -u"}, 2
            )
            assert who["stdout"].strip() == "0", who
            target = root_private / (uuid.uuid4().hex + ".txt")
            mcp(
                base,
                token,
                "fs.write",
                {"selection_id": sid, "path": str(target), "data": "rust-root"},
                3,
            )
            rd = mcp(
                base, token, "fs.read", {"selection_id": sid, "path": str(target)}, 4
            )
            assert rd["result"]["data"] == "rust-root", rd
            print(
                json.dumps(
                    {
                        "status": "PASS",
                        "implementation": "rust",
                        "agent_uid": nobody.pw_uid,
                        "helper_uid": 0,
                        "id_u": who["stdout"].strip(),
                        "root_fs": True,
                    },
                    indent=2,
                )
            )
            return 0
        except Exception:
            for f in (sl, hl, al):
                f.flush()
                f.seek(0)
            print(sl.read(), hl.read(), al.read(), file=sys.stderr)
            raise
        finally:
            stop(agent)
            stop(server)
            stop(helper)
            sl.close()
            hl.close()
            al.close()
            shutil.rmtree(root_private, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
