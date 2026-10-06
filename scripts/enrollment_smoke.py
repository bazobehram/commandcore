"""Disposable server + real Agent CLI/WSS enrollment acceptance (no live data)."""

from __future__ import annotations

import base64
import hashlib
import http.server
import json
import os
import re
import secrets
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import httpx
import jwt
import psutil
from commandcore_server.security import issue_panel_session
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parents[1]


class SystemdAgent:
    """A disposable user service handle; never used against a production device."""

    def __init__(self, unit):
        self.unit = unit
        self.pid = int(
            subprocess.check_output(
                ["systemctl", "--user", "show", "--property=MainPID", "--value", unit],
                text=True,
            ).strip()
        )

    def poll(self):
        return (
            None
            if subprocess.run(
                ["systemctl", "--user", "is-active", "--quiet", self.unit]
            ).returncode
            == 0
            else 0
        )

    def terminate(self):
        subprocess.run(["systemctl", "--user", "stop", self.unit], check=True)

    def wait(self, timeout=5):
        deadline = time.time() + timeout
        while self.poll() is None:
            if time.time() > deadline:
                raise subprocess.TimeoutExpired(self.unit, timeout)
            time.sleep(0.05)
        return 0


def stop(process):
    if process and process.poll() is None:
        # Windows venv launchers may spawn the actual interpreter. Terminating
        # only the launcher would leave the Agent alive and fake restart success.
        try:
            children = psutil.Process(process.pid).children(recursive=True)
        except psutil.NoSuchProcess:
            children = []
        for child in reversed(children):
            try:
                child.terminate()
            except psutil.NoSuchProcess:
                pass
        process.terminate()
        try:
            process.wait(5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(5)
        _, alive = psutil.wait_procs(children, timeout=5)
        for child in alive:
            try:
                child.kill()
            except psutil.NoSuchProcess:
                pass


def eventually(check, timeout=25):
    end = time.time() + timeout
    while time.time() < end:
        try:
            result = check()
            if result:
                return result
        except (httpx.HTTPError, OSError, ValueError):
            pass
        time.sleep(0.2)
    raise RuntimeError("Acceptance condition timed out")


def main():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    base = f"http://127.0.0.1:{port}"
    secret = secrets.token_urlsafe(48)
    native = os.getenv("COMMANDCORE_ENROLLMENT_AGENT_BIN")
    systemd = os.getenv("COMMANDCORE_ENROLLMENT_SYSTEMD") == "true"
    if systemd and (not native or sys.platform != "linux" or os.getuid() == 0):
        raise RuntimeError(
            "Systemd acceptance requires a disposable non-root Linux user and native Agent"
        )
    systemd_unit = None
    installer = os.getenv("COMMANDCORE_ENROLLMENT_INSTALLER")
    artifact_binary = Path(native).read_bytes() if installer and native else None
    signed_manifest = None
    release_public = ""
    if installer and (os.name != "posix" or os.getuid() == 0 or not artifact_binary):
        raise RuntimeError(
            "Installer acceptance requires a disposable non-root Linux user and native binary"
        )
    agent_command = (
        [native] if native else [sys.executable, "-m", "commandcore_agent.cli"]
    )
    signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = jwt.algorithms.RSAAlgorithm.to_jwk(signing_key.public_key(), as_dict=True)
    jwk.update(kid="disposable-test", use="sig", alg="RS256")

    class PublicKeys(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if installer and self.path in {"/manifest.json", "/agent"}:
                content = (
                    signed_manifest
                    if self.path == "/manifest.json"
                    else artifact_binary
                )
                self.send_response(200)
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"keys": [jwk]}).encode())

        def log_message(self, *args):
            pass

    keys_server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), PublicKeys)
    keys_thread = threading.Thread(target=keys_server.serve_forever, daemon=True)
    keys_thread.start()
    issuer = f"http://127.0.0.1:{keys_server.server_port}/"
    if installer:
        native_version = (
            subprocess.check_output([native, "--version"], text=True)
            .strip()
            .rsplit(" ", 1)[-1]
        )
        release_key = Ed25519PrivateKey.generate()
        release_public = base64.b64encode(
            release_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        ).decode()
        manifest_data = {
            "schema_version": 1,
            "product": "commandcore-agent",
            "version": native_version,
            "artifacts": [
                {
                    "platform": "linux",
                    "architecture": "x86_64",
                    "kind": "executable",
                    "url": issuer + "agent",
                    "sha256": hashlib.sha256(artifact_binary).hexdigest(),
                    "size": len(artifact_binary),
                }
            ],
        }
        canonical = json.dumps(
            manifest_data, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()
        manifest_data["signature"] = base64.b64encode(
            release_key.sign(canonical)
        ).decode()
        signed_manifest = json.dumps(manifest_data).encode()
    access_token = jwt.encode(
        {
            "sub": "smoke-operator",
            "iss": issuer,
            "aud": base + "/mcp",
            "iat": int(time.time()),
            "exp": int(time.time()) + 600,
            "scope": "commandcore:read commandcore:standard",
            "client_id": "disposable-test",
        },
        signing_key,
        algorithm="RS256",
        headers={"kid": "disposable-test"},
    )
    with tempfile.TemporaryDirectory(prefix="commandcore-enrollment-") as temp:
        root = Path(temp)
        state = root / "agent.json"
        if installer:
            home = root / "home"
            home.mkdir(mode=0o700)
            state = home / ".config/commandcore/agent.json"
            agent_command = [str(home / ".local/bin/commandcore-agent")]
        env = {
            **os.environ,
            "PYTHONPATH": os.pathsep.join(
                [str(ROOT / "apps/server"), str(ROOT / "agent")]
            ),
            "COMMANDCORE_HOST": "127.0.0.1",
            "COMMANDCORE_PORT": str(port),
            "COMMANDCORE_API_TOKEN": secret,
            "COMMANDCORE_PUBLIC_BOOTSTRAP_ENABLED": "true",
            "COMMANDCORE_DB": str(root / "db.sqlite3"),
            "COMMANDCORE_PUBLIC_BASE_URL": base,
            "COMMANDCORE_OAUTH_ENABLED": "true",
            "COMMANDCORE_OAUTH_ISSUER": issuer,
            "COMMANDCORE_OAUTH_AUDIENCE": base + "/mcp",
            "COMMANDCORE_OAUTH_JWKS_URL": issuer + "jwks.json",
            "COMMANDCORE_PANEL_COOKIE_SECURE": "false",
            "COMMANDCORE_AGENT_POLICY": str(root / "policy.json"),
            "COMMANDCORE_AGENT_STATE": str(state),
            "PYTHONIOENCODING": "utf-8",
        }
        (root / "policy.json").write_text(
            json.dumps({"configured_max_permission_profile": "STANDARD"})
        )
        (root / "policy.json").chmod(0o600)
        if installer:
            env.update(
                HOME=str(home),
                XDG_CONFIG_HOME=str(home / ".config"),
                XDG_DATA_HOME=str(home / ".local/share"),
                COMMANDCORE_RELEASE_PUBLIC_KEY_B64=release_public,
            )
        server = agent = enrolling = None
        with (
            (root / "server.log").open("w+") as server_log,
            (root / "agent.log").open("w+") as agent_log,
            (root / "enrollment.log").open("w+") as enroll_log,
        ):
            try:

                def start_server():
                    return subprocess.Popen(
                        [sys.executable, "-m", "commandcore_server.main"],
                        cwd=ROOT,
                        env=env,
                        stdout=server_log,
                        stderr=subprocess.STDOUT,
                    )

                server = start_server()
                eventually(lambda: httpx.get(base + "/healthz").status_code == 200)
                enrollment_command = [
                    *agent_command,
                    "enroll",
                    base,
                    "--insecure",
                    "--no-connect",
                    "--name",
                    "disposable-enrollment-δοκιμή",
                    "--state",
                    str(state),
                ]
                if installer:
                    enrollment_command = [
                        "sh",
                        installer,
                        "--server",
                        base,
                        "--manifest",
                        issuer + "manifest.json",
                        "--test-loopback",
                        "--no-service",
                    ]
                enrolling = subprocess.Popen(
                    enrollment_command,
                    cwd=ROOT,
                    env=env,
                    stdout=enroll_log,
                    stderr=subprocess.STDOUT,
                )

                def pending():
                    enroll_log.flush()
                    return (root / "enrollment.log").read_text(
                        encoding="utf-8", errors="replace"
                    )

                transcript = eventually(
                    lambda: (
                        text if "Waiting for approval" in (text := pending()) else None
                    )
                )
                view = re.search(r"/enroll/#([\w-]+)", transcript).group(1)
                code = re.search(
                    r"Verification code:\s*([A-Z2-9]{4}-[A-Z2-9]{4})", transcript
                ).group(1)
                cookie = issue_panel_session(
                    secret=secret,
                    subject="smoke-operator",
                    ttl_seconds=600,
                    scopes=("commandcore:read", "commandcore:standard"),
                    auth_kind="oauth2-panel",
                )
                with httpx.Client(
                    base_url=base,
                    headers={"Origin": base},
                    cookies={"commandcore_session": cookie},
                    timeout=15,
                ) as client:
                    review = client.post(
                        "/api/enrollment/review", json={"view_token": view}
                    )
                    review.raise_for_status()
                    assert review.json()["metadata"]["local_ceiling"] == "STANDARD"
                    # Stop before approval, commit the signed claim through the
                    # transport fixture, and discard its response. The actual CLI
                    # must resume solely from its durable local pending identity.
                    stop(enrolling)
                    enrolling = None
                    local_pending = json.loads(
                        (state.parent / "enrollment.pending.json").read_text(
                            encoding="utf-8"
                        )
                    )
                    decision = client.post(
                        "/api/enrollment/decision",
                        json={
                            "view_token": view,
                            "code": code,
                            "approve": True,
                            "grant_to_me": True,
                        },
                    )
                    decision.raise_for_status()
                    claim_key = Ed25519PrivateKey.from_private_bytes(
                        base64.b64decode(local_pending["private_key_b64"])
                    )
                    claim_message = (
                        "commandcore-enroll-claim-v1\n"
                        + local_pending["enrollment_id"]
                        + "\n"
                        + local_pending["enrollment_poll_token"]
                    ).encode()
                    claim_body = {
                        "poll_token": local_pending["enrollment_poll_token"],
                        "proof": base64.b64encode(
                            claim_key.sign(claim_message)
                        ).decode(),
                    }
                    consumed = client.post("/api/enrollment/poll", json=claim_body)
                    consumed.raise_for_status()
                    assert consumed.json()["credential_source"] == "agent"
                    assert "device_token" not in consumed.json()
                    assert (
                        client.post("/api/enrollment/poll", json=claim_body).status_code
                        == 400
                    )
                    enrolling = subprocess.Popen(
                        enrollment_command,
                        cwd=ROOT,
                        env=env,
                        stdout=enroll_log,
                        stderr=subprocess.STDOUT,
                    )
                    assert enrolling.wait(20) == 0
                    enrolling = None
                    assert state.is_file()
                    if os.name != "nt":
                        assert state.stat().st_mode & 0o077 == 0
                    assert not (state.parent / "enrollment.pending.json").exists()
                    assert (
                        client.post(
                            "/api/enrollment/review", json={"view_token": view}
                        ).status_code
                        == 400
                    )
                    identity = json.loads(state.read_text())
                    device_id = identity["device_id"]

                    def start_agent():
                        nonlocal systemd_unit
                        if systemd:
                            if systemd_unit is None:
                                name = (
                                    "commandcore-agent-acceptance-"
                                    + secrets.token_hex(8)
                                    + ".service"
                                )
                                systemd_unit = (
                                    Path.home() / ".config/systemd/user" / name
                                )
                                systemd_unit.parent.mkdir(parents=True, exist_ok=True)
                                systemd_unit.write_text(
                                    "[Unit]\nDescription=Disposable CommandCore candidate acceptance\n"
                                    '[Service]\nExecStart="'
                                    + str(native)
                                    + '" run --state "'
                                    + str(state)
                                    + '"\n'
                                    'Environment="COMMANDCORE_AGENT_POLICY='
                                    + str(root / "policy.json")
                                    + '"\n'
                                    "Restart=on-failure\nRestartSec=1\nKillMode=process\nNoNewPrivileges=true\n"
                                    "[Install]\nWantedBy=default.target\n"
                                )
                                subprocess.run(
                                    ["systemctl", "--user", "daemon-reload"], check=True
                                )
                                subprocess.run(
                                    ["systemctl", "--user", "enable", name],
                                    check=True,
                                    capture_output=True,
                                )
                            subprocess.run(
                                ["systemctl", "--user", "start", systemd_unit.name],
                                check=True,
                            )
                            return SystemdAgent(systemd_unit.name)
                        return subprocess.Popen(
                            [
                                *agent_command,
                                "run",
                                "--state",
                                str(state),
                            ],
                            cwd=ROOT,
                            env=env,
                            stdout=agent_log,
                            stderr=subprocess.STDOUT,
                        )

                    agent = start_agent()

                    def online():
                        return any(
                            d["id"] == device_id and d["connected"]
                            for d in client.get("/api/devices").json()["devices"]
                        )

                    eventually(online)

                    def call(name, args):
                        response = client.post(
                            "/mcp",
                            headers={
                                "Authorization": "Bearer " + access_token,
                                "Accept": "application/json, text/event-stream",
                                "MCP-Protocol-Version": "2026-07-28",
                                "Mcp-Method": "tools/call",
                                "Mcp-Name": name,
                            },
                            json={
                                "jsonrpc": "2.0",
                                "id": 1,
                                "method": "tools/call",
                                "params": {
                                    "name": name,
                                    "arguments": args,
                                    "_meta": {
                                        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                                        "io.modelcontextprotocol/clientInfo": {
                                            "name": "enrollment-smoke",
                                            "version": "1",
                                        },
                                        "io.modelcontextprotocol/clientCapabilities": {},
                                    },
                                },
                            },
                        )
                        response.raise_for_status()
                        result = response.json()["result"]
                        assert not result.get("isError"), result
                        return result["structuredContent"]

                    assert any(
                        d["id"] == device_id
                        for d in call("devices.list", {})["devices"]
                    )
                    selection = call("devices.select", {"device": device_id})[
                        "selection_id"
                    ]
                    probe = root / "probe.txt"
                    probe.write_text("enrollment-read-ok")
                    assert (
                        call(
                            "fs.read", {"selection_id": selection, "path": str(probe)}
                        )["result"]["data"]
                        == "enrollment-read-ok"
                    )
                    assert (
                        call(
                            "shell.exec",
                            {"selection_id": selection, "command": "hostname"},
                        )["stdout"].strip()
                        == socket.gethostname()
                    )
                    write_probe = root / "write-probe.txt"
                    call(
                        "fs.write",
                        {
                            "selection_id": selection,
                            "path": str(write_probe),
                            "data": "unicode-roundtrip-δοκιμή",
                        },
                    )
                    assert (
                        call(
                            "fs.read",
                            {"selection_id": selection, "path": str(write_probe)},
                        )["result"]["data"]
                        == "unicode-roundtrip-δοκιμή"
                    )
                    call(
                        "fs.delete",
                        {"selection_id": selection, "path": str(write_probe)},
                    )
                    assert not write_probe.exists()
                    assert (
                        call("system.info", {"selection_id": selection})["result"][
                            "hostname"
                        ]
                        == socket.gethostname()
                    )
                    assert (
                        call("system.metrics", {"selection_id": selection})["result"][
                            "memory"
                        ]["total"]
                        > 0
                    )
                    transfer_probe = root / "transfer-probe.bin"
                    transfer_data = base64.b64encode(
                        b"\x00\xfftransfer-roundtrip"
                    ).decode()
                    call(
                        "transfer.upload",
                        {
                            "selection_id": selection,
                            "path": str(transfer_probe),
                            "data_base64": transfer_data,
                        },
                    )
                    assert (
                        call(
                            "transfer.download",
                            {"selection_id": selection, "path": str(transfer_probe)},
                        )["result"]["data_base64"]
                        == transfer_data
                    )
                    command_args = [
                        sys.executable,
                        "-c",
                        "import time;print('managed-core-probe',flush=True);time.sleep(60)",
                    ]
                    command = (
                        subprocess.list2cmdline(command_args)
                        if os.name == "nt"
                        else shlex.join(command_args)
                    )
                    process = call(
                        "process.start",
                        {
                            "selection_id": selection,
                            "command": command,
                            "cwd": str(root),
                        },
                    )["result"]["process_id"]
                    assert (
                        call(
                            "process.status",
                            {"selection_id": selection, "process_id": process},
                        )["result"]["running"]
                        is True
                    )
                    assert call(
                        "process.list", {"selection_id": selection, "limit": 50}
                    )["result"]
                    eventually(
                        lambda: (
                            "managed-core-probe"
                            in call(
                                "process.output",
                                {"selection_id": selection, "process_id": process},
                            )["result"]["stdout"]
                        )
                    )
                    assert (
                        call(
                            "process.stop",
                            {"selection_id": selection, "process_id": process},
                        )["result"]["stopped"]
                        is True
                    )
                    git_tested = bool(shutil.which("git"))
                    if git_tested:
                        repository = root / "test-git"
                        repository.mkdir()
                        subprocess.run(
                            ["git", "init", "-q", str(repository)],
                            check=True,
                            capture_output=True,
                        )
                        (repository / "probe.txt").write_text("git-roundtrip")
                        assert (
                            "probe.txt"
                            in call(
                                "git.status",
                                {"selection_id": selection, "repo": str(repository)},
                            )["result"]["porcelain_v2"]
                        )
                        assert (
                            call(
                                "git.run",
                                {
                                    "selection_id": selection,
                                    "repo": str(repository),
                                    "args": ["add", "probe.txt"],
                                },
                            )["result"]["exit_code"]
                            == 0
                        )
                    stop(agent)
                    agent = start_agent()
                    eventually(online)
                    disconnect_probe = call(
                        "process.start",
                        {
                            "selection_id": selection,
                            "command": command,
                            "cwd": str(root),
                        },
                    )["result"]
                    disconnect_pid = disconnect_probe["pid"]
                    assert psutil.pid_exists(disconnect_pid)
                    if native and sys.platform == "linux":
                        # Kill only the Agent: its independently supervised job
                        # must survive, matching systemd KillMode=process.
                        agent.terminate()
                        agent.wait(5)
                        agent = start_agent()
                        eventually(online)
                        assert psutil.pid_exists(disconnect_pid)
                    stop(server)
                    server = start_server()
                    eventually(online)
                    assert psutil.pid_exists(disconnect_pid)
                    assert (
                        call(
                            "process.status",
                            {
                                "selection_id": selection,
                                "process_id": disconnect_probe["process_id"],
                            },
                        )["result"]["running"]
                        is True
                    )
                    assert (
                        "managed-core-probe"
                        in call(
                            "process.output",
                            {
                                "selection_id": selection,
                                "process_id": disconnect_probe["process_id"],
                            },
                        )["result"]["stdout"]
                    )
                    assert (
                        call(
                            "shell.exec",
                            {"selection_id": selection, "command": "hostname"},
                        )["stdout"].strip()
                        == socket.gethostname()
                    )
                    stopped = call(
                        "process.stop",
                        {
                            "selection_id": selection,
                            "process_id": disconnect_probe["process_id"],
                        },
                    )["result"]
                    assert stopped["stopped"] is True
                    if native and sys.platform == "linux":
                        assert stopped["termination_reason"] == "stopped_by_request"
                        assert stopped["signal"] in {"SIGTERM", "SIGKILL"}
                        job_directory = (
                            state.parent
                            / "managed-jobs"
                            / device_id
                            / disconnect_probe["process_id"]
                        )
                        for file in job_directory.iterdir():
                            if file.is_file():
                                assert file.stat().st_mode & 0o777 == 0o600
                        assert command not in (job_directory / "job.json").read_text()
                    disconnect_probe = call(
                        "process.start",
                        {
                            "selection_id": selection,
                            "command": command,
                            "cwd": str(root),
                        },
                    )["result"]
                    disconnect_pid = disconnect_probe["pid"]
                    response = client.post(
                        "/api/managed-devices/" + device_id + "/revoke"
                    )
                    response.raise_for_status()
                    # Revocation denies control, preserving authorized local work.
                    time.sleep(1)
                    assert psutil.pid_exists(disconnect_pid)
                    eventually(
                        lambda: (
                            not any(
                                d["id"] == device_id
                                for d in client.get("/api/devices").json()["devices"]
                            )
                        )
                    )
                    assert not any(
                        d["id"] == device_id
                        for d in call("devices.list", {})["devices"]
                    )
                    assert call("auth.whoami", {})["subject"] == "smoke-operator"
                    # Explicit local cleanup of the fixture-owned workload only.
                    process = psutil.Process(disconnect_pid)
                    children = process.children(recursive=True)
                    for child in children:
                        child.terminate()
                    process.terminate()
                    psutil.wait_procs([process, *children], timeout=5)
                print(
                    json.dumps(
                        {
                            "status": "PASS",
                            "real_agent_cli": True,
                            "signed_installer": bool(installer),
                            "identity_provider": "disposable JWT/JWKS fixture; not Auth0/ChatGPT",
                            "local_key": True,
                            "explicit_grant": True,
                            "single_use": True,
                            "lost_claim_response_recovery": True,
                            "outbound_websocket": True,
                            "read": True,
                            "standard_shell": True,
                            "filesystem_write_read_delete": True,
                            "system_info_metrics": True,
                            "managed_process_lifecycle": True,
                            "binary_transfer": True,
                            "git": git_tested,
                            "agent_restart": True,
                            "real_systemd_restart": systemd,
                            "server_restart": True,
                            "managed_process_survives_transport_reconnect": True,
                            "managed_process_survives_agent_restart": bool(
                                native and sys.platform == "linux"
                            ),
                            "revocation_preserves_local_workload": True,
                            "revoke_visibility": True,
                            "platform": sys.platform,
                        },
                        indent=2,
                    )
                )
            finally:
                stop(enrolling)
                stop(agent)
                stop(server)
                if systemd_unit is not None:
                    subprocess.run(
                        ["systemctl", "--user", "disable", "--now", systemd_unit.name],
                        check=True,
                        capture_output=True,
                    )
                    systemd_unit.unlink()
                    subprocess.run(["systemctl", "--user", "daemon-reload"], check=True)
                keys_server.shutdown()
                keys_server.server_close()


if __name__ == "__main__":
    main()
