#!/usr/bin/env python3
from __future__ import annotations

import json, os, socket, subprocess, sys, tempfile, threading, time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import httpx, jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

ROOT = Path(__file__).resolve().parents[1]
HOST = "127.0.0.1"


def free_port():
    with socket.socket() as s:
        s.bind((HOST, 0))
        return s.getsockname()[1]


def wait(url, timeout=15):
    end = time.time() + timeout
    while time.time() < end:
        try:
            if httpx.get(url, timeout=1).status_code < 500:
                return
        except Exception:
            pass
        time.sleep(0.15)
    raise RuntimeError("not ready")


def stop(p):
    if not p or p.poll() is not None:
        return
    p.terminate()
    try:
        p.wait(4)
    except subprocess.TimeoutExpired:
        p.kill()
        p.wait(4)


def meta():
    return {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientInfo": {
            "name": "oauth-smoke",
            "version": "0.8.0",
        },
        "io.modelcontextprotocol/clientCapabilities": {},
    }


def mcp(base, token, name, arguments, rid):
    method = "tools/call"
    body = {
        "jsonrpc": "2.0",
        "id": rid,
        "method": method,
        "params": {"name": name, "arguments": arguments, "_meta": meta()},
    }
    h = {
        "Authorization": f"Bearer {token}",
        "MCP-Protocol-Version": "2026-07-28",
        "Mcp-Method": method,
        "Mcp-Name": name,
    }
    r = httpx.post(base + "/mcp", json=body, headers=h, timeout=20)
    return r


def main():
    port = free_port()
    jwks_port = free_port()
    base = f"http://{HOST}:{port}"
    issuer = f"http://{HOST}:{jwks_port}"
    bootstrap = "oauth-smoke-bootstrap-0123456789abcdef0123456789"
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = private.public_key()
    jwk = json.loads(RSAAlgorithm.to_jwk(public))
    jwk.update({"kid": "smoke-key", "use": "sig", "alg": "RS256"})

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/jwks":
                data = json.dumps({"keys": [jwk]}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, *a):
            pass

    jwks_server = HTTPServer((HOST, jwks_port), H)
    thread = threading.Thread(target=jwks_server.serve_forever, daemon=True)
    thread.start()
    with tempfile.TemporaryDirectory(prefix="cc-oauth-smoke-") as td:
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
                "COMMANDCORE_DB": str(td / "db.sqlite3"),
                "COMMANDCORE_API_TOKEN": bootstrap,
                "COMMANDCORE_PUBLIC_BOOTSTRAP_ENABLED": "true",
                "COMMANDCORE_BOOTSTRAP_SUBJECT": "owner",
                "COMMANDCORE_PUBLIC_BASE_URL": base,
                "COMMANDCORE_MCP_BASE_URL": base + "/mcp",
                "COMMANDCORE_AGENT_BASE_URL": f"ws://{HOST}:{port}/agent",
                "COMMANDCORE_OAUTH_ENABLED": "true",
                "COMMANDCORE_OAUTH_ISSUER": issuer,
                "COMMANDCORE_OAUTH_AUDIENCE": base + "/mcp",
                "COMMANDCORE_OAUTH_JWKS_URL": issuer + "/jwks",
                "COMMANDCORE_OAUTH_AUTHORIZATION_SERVERS": issuer,
            }
        )
        slog = (td / "server.log").open("w+")
        alog = (td / "agent.log").open("w+")
        server = subprocess.Popen(
            [sys.executable, "-m", "commandcore_server.main"],
            cwd=ROOT,
            env=env,
            stdout=slog,
            stderr=subprocess.STDOUT,
            text=True,
        )
        agent = None
        try:
            wait(base + "/healthz")
            auth = {"Authorization": f"Bearer {bootstrap}"}
            md = httpx.get(base + "/.well-known/oauth-protected-resource")
            md.raise_for_status()
            assert md.json()["resource"] == base + "/mcp"
            unauthenticated = httpx.post(
                base + "/mcp",
                json={"jsonrpc": "2.0", "id": 0, "method": "tools/list", "params": {}},
            )
            assert unauthenticated.status_code == 401
            assert (
                f'resource_metadata="{base}/.well-known/oauth-protected-resource"'
                in unauthenticated.headers["WWW-Authenticate"]
            )
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
                    f"ws://{HOST}:{port}/agent",
                    "--state",
                    str(td / "agent.json"),
                ],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                timeout=15,
            )
            if en.returncode:
                raise RuntimeError(en.stderr)
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
                stdout=alog,
                stderr=subprocess.STDOUT,
                text=True,
            )
            end = time.time() + 15
            while time.time() < end:
                ds = httpx.get(base + "/api/devices", headers=auth).json()["devices"]
                if any(d["id"] == did and d["status"] == "online" for d in ds):
                    break
                time.sleep(0.2)
            httpx.put(
                base + f"/api/devices/{did}/grants",
                headers=auth,
                json={"subject": "oauth-user", "max_permission_profile": "READ_ONLY"},
            ).raise_for_status()
            now = int(time.time())
            token = jwt.encode(
                {
                    "sub": "oauth-user",
                    "iss": issuer,
                    "aud": base + "/mcp",
                    "iat": now,
                    "exp": now + 300,
                    "scope": "commandcore:read commandcore:standard",
                    "client_id": "oauth-smoke-client",
                },
                private,
                algorithm="RS256",
                headers={"kid": "smoke-key"},
            )
            read_token = jwt.encode(
                {
                    "sub": "oauth-user",
                    "iss": issuer,
                    "aud": base + "/mcp",
                    "iat": now,
                    "exp": now + 300,
                    "scope": "commandcore:read",
                },
                private,
                algorithm="RS256",
                headers={"kid": "smoke-key"},
            )
            scope_denied = mcp(
                base,
                read_token,
                "shell.exec",
                {"device_id": did, "command": "hostname"},
                0,
            )
            scope_denied.raise_for_status()
            scope_result = scope_denied.json()["result"]
            assert scope_result["structuredContent"]["error"] == "insufficient_scope"
            assert (
                'scope="commandcore:standard"'
                in scope_result["_meta"]["mcp/www_authenticate"][0]
            )
            listed = mcp(base, token, "devices.list", {}, 1)
            listed.raise_for_status()
            assert (
                listed.json()["result"]["structuredContent"]["devices"][0]["id"] == did
            )
            info = mcp(base, token, "system.info", {"device_id": did}, 2)
            info.raise_for_status()
            assert info.json()["result"]["isError"] is False
            denied = mcp(
                base, token, "shell.exec", {"device_id": did, "command": "hostname"}, 3
            )
            denied.raise_for_status()
            assert denied.json()["result"]["isError"] is True
            assert (
                denied.json()["result"]["structuredContent"]["error"]
                == "permission_denied"
            )
            httpx.put(
                base + f"/api/devices/{did}/grants",
                headers=auth,
                json={"subject": "oauth-user", "max_permission_profile": "STANDARD"},
            ).raise_for_status()
            allowed = mcp(
                base, token, "shell.exec", {"device_id": did, "command": "hostname"}, 4
            )
            allowed.raise_for_status()
            payload = allowed.json()["result"]["structuredContent"]
            assert payload["exit_code"] == 0
            bad = jwt.encode(
                {
                    "sub": "oauth-user",
                    "iss": issuer,
                    "aud": "wrong",
                    "iat": now,
                    "exp": now + 300,
                    "scope": "commandcore:read",
                },
                private,
                algorithm="RS256",
                headers={"kid": "smoke-key"},
            )
            badr = mcp(base, bad, "devices.list", {}, 5)
            assert badr.status_code == 401
            assert 'error="invalid_token"' in badr.headers["WWW-Authenticate"]
            for claims in ({"iss": issuer + "/wrong"}, {"exp": now - 120}):
                invalid = jwt.encode(
                    {
                        "sub": "oauth-user",
                        "iss": issuer,
                        "aud": base + "/mcp",
                        "iat": now - 120,
                        "exp": now + 300,
                        "scope": "commandcore:read",
                        **claims,
                    },
                    private,
                    algorithm="RS256",
                    headers={"kid": "smoke-key"},
                )
                assert mcp(base, invalid, "devices.list", {}, 6).status_code == 401
            print(
                json.dumps(
                    {
                        "status": "PASS",
                        "oauth_jwt_verified": True,
                        "protected_resource_metadata": True,
                        "unauthenticated_challenge": True,
                        "insufficient_scope_challenge": True,
                        "read_grant_enforced": True,
                        "standard_grant_shell_exec": payload["stdout"].strip(),
                        "invalid_audience_rejected": True,
                        "wrong_issuer_rejected": True,
                        "expired_token_rejected": True,
                    },
                    indent=2,
                )
            )
            return 0
        except Exception:
            for f in (slog, alog):
                f.flush()
                f.seek(0)
            print("--- server ---\n" + slog.read(), file=sys.stderr)
            print("--- agent ---\n" + alog.read(), file=sys.stderr)
            raise
        finally:
            stop(agent)
            stop(server)
            slog.close()
            alog.close()
            jwks_server.shutdown()
            thread.join(timeout=2)


if __name__ == "__main__":
    raise SystemExit(main())
