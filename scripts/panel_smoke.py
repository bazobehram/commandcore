#!/usr/bin/env python3
from __future__ import annotations

import base64
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
    with socket.socket() as sock:
        sock.bind((HOST, 0))
        return int(sock.getsockname()[1])


def wait_http(url: str, timeout: float = 20.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if httpx.get(url, timeout=1).status_code < 500:
                return
        except Exception:
            pass
        time.sleep(0.2)
    raise RuntimeError("server did not become ready")


def stop(proc: subprocess.Popen[str]) -> None:
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


def main() -> int:
    port = free_port()
    base = f"http://{HOST}:{port}"
    token = "panel-smoke-bootstrap-token-0123456789abcdef"
    with tempfile.TemporaryDirectory(prefix="commandcore-panel-") as td:
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
                "COMMANDCORE_DB": str(Path(td) / "commandcore.sqlite3"),
                "COMMANDCORE_API_TOKEN": token,
                "COMMANDCORE_PUBLIC_BOOTSTRAP_ENABLED": "true",
                "COMMANDCORE_BOOTSTRAP_SUBJECT": "panel-smoke-owner",
                "COMMANDCORE_PUBLIC_BASE_URL": base,
                "COMMANDCORE_MCP_BASE_URL": base + "/mcp",
                "COMMANDCORE_AGENT_BASE_URL": f"ws://{HOST}:{port}/agent",
                "COMMANDCORE_PANEL_COOKIE_SECURE": "false",
                "COMMANDCORE_RECOMMENDED_AGENT_VERSION": "0.8.0",
            }
        )
        log = (Path(td) / "server.log").open("w+")
        server = subprocess.Popen(
            [sys.executable, "-m", "commandcore_server.main"],
            cwd=ROOT,
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
            text=True,
        )
        try:
            wait_http(base + "/healthz")
            with httpx.Client(
                base_url=base, headers={"Origin": base}, timeout=10
            ) as client:
                assert client.get("/api/session").status_code == 401
                login = client.post("/api/session", json={"token": token})
                login.raise_for_status()
                cookie = login.headers.get("set-cookie", "").lower()
                assert "httponly" in cookie and "samesite=strict" in cookie
                assert "commandcore_session" in client.cookies
                session = client.get("/api/session")
                session.raise_for_status()
                assert session.json()["auth_kind"] == "panel-cookie"
                overview = client.get("/api/overview")
                overview.raise_for_status()

                # Cross-origin browser mutation is rejected even with a valid panel cookie.
                blocked = client.post(
                    "/api/enrollment-tokens", headers={"Origin": "https://evil.example"}
                )
                assert blocked.status_code == 403

                # Create/list/cancel an unused enrollment token.
                created = client.post("/api/enrollment-tokens")
                created.raise_for_status()
                token_id = created.json()["id"]
                listed = client.get("/api/enrollment-tokens")
                listed.raise_for_status()
                assert any(
                    x["id"] == token_id and x["status"] == "active"
                    for x in listed.json()["tokens"]
                )
                canceled = client.delete(f"/api/enrollment-tokens/{token_id}")
                canceled.raise_for_status()
                listed2 = client.get("/api/enrollment-tokens")
                listed2.raise_for_status()
                assert any(
                    x["id"] == token_id and x["status"] == "canceled"
                    for x in listed2.json()["tokens"]
                )

                # Exercise panel-facing device management API end-to-end.
                enroll_token = client.post("/api/enrollment-tokens").json()["token"]
                agent_payload = {
                    "token": enroll_token,
                    "display_name": "panel-smoke-device",
                    "hostname": "panel-smoke-host",
                    "platform": "Linux",
                    "architecture": "x86_64",
                    "agent_version": "0.8.0",
                    "protocol_version": "1",
                    "public_key_b64": base64.b64encode(bytes(32)).decode(),
                    "capabilities": {
                        "filesystem": True,
                        "shell": True,
                        "privileged_helper": False,
                    },
                }
                enrolled = client.post("/api/agent/enroll", json=agent_payload)
                enrolled.raise_for_status()
                device_id = enrolled.json()["device_id"]
                assert enrolled.json()["status"] == "pending"
                updated = client.patch(
                    f"/api/devices/{device_id}",
                    json={"display_name": "renamed-smoke", "tags": ["test", "linux"]},
                )
                updated.raise_for_status()
                assert updated.json()["device"]["tags"] == ["test", "linux"]
                perm = client.post(
                    f"/api/devices/{device_id}/permissions",
                    json={"profile": "READ_ONLY"},
                )
                perm.raise_for_status()
                assert perm.json()["device"]["permission_profile"] == "READ_ONLY"
                full = client.post(
                    f"/api/devices/{device_id}/permissions",
                    json={"profile": "FULL_CONTROL"},
                )
                assert full.status_code == 409
                approved = client.post(f"/api/devices/{device_id}/approve")
                approved.raise_for_status()
                detail = client.get(f"/api/devices/{device_id}")
                detail.raise_for_status()
                assert detail.json()["device"]["display_name"] == "renamed-smoke"
                assert detail.json()["device"]["agent_update_available"] is False
                grant = client.put(
                    f"/api/devices/{device_id}/grants",
                    json={
                        "subject": "oauth-panel-user",
                        "max_permission_profile": "READ_ONLY",
                    },
                )
                grant.raise_for_status()
                assert grant.json()["grants"][0]["subject"] == "oauth-panel-user"
                detail2 = client.get(f"/api/devices/{device_id}")
                detail2.raise_for_status()
                assert (
                    detail2.json()["device"]["grants"][0]["max_permission_profile"]
                    == "READ_ONLY"
                )
                ungrant = client.delete(
                    f"/api/devices/{device_id}/grants",
                    params={"subject": "oauth-panel-user"},
                )
                ungrant.raise_for_status()

                # Fleet rollout CRUD is panel-manageable, but only for devices
                # whose local authority ceiling genuinely permits FULL_CONTROL.
                fleet_token = client.post("/api/enrollment-tokens").json()["token"]
                fleet_payload = {
                    "token": fleet_token,
                    "display_name": "fleet-smoke-device",
                    "hostname": "fleet-smoke-host",
                    "platform": "Linux",
                    "architecture": "x86_64",
                    "agent_version": "0.8.0",
                    "protocol_version": "1",
                    "public_key_b64": base64.b64encode(bytes(32)).decode(),
                    "capabilities": {
                        "filesystem": True,
                        "shell": True,
                        "privileged_helper": True,
                        "local_max_permission_profile": "FULL_CONTROL",
                        "configured_max_permission_profile": "FULL_CONTROL",
                        "agent_update": True,
                        "agent_update_trust_configured": True,
                    },
                }
                fleet_dev = client.post("/api/agent/enroll", json=fleet_payload)
                fleet_dev.raise_for_status()
                fleet_id = fleet_dev.json()["device_id"]
                fp = client.post(
                    f"/api/devices/{fleet_id}/permissions",
                    json={"profile": "FULL_CONTROL"},
                )
                fp.raise_for_status()
                client.post(f"/api/devices/{fleet_id}/approve").raise_for_status()
                rollout = client.post(
                    "/api/fleet-rollouts",
                    json={
                        "target_version": "0.8.0",
                        "manifest_url": "https://updates.example/manifest.json",
                        "device_ids": [fleet_id],
                        "canary_count": 1,
                        "ring_size": 5,
                        "stop_on_failure": True,
                    },
                )
                rollout.raise_for_status()
                rollout_id = rollout.json()["rollout"]["id"]
                assert (
                    client.get("/api/fleet-rollouts").json()["rollouts"][0]["id"]
                    == rollout_id
                )
                detail_rollout = client.get(f"/api/fleet-rollouts/{rollout_id}")
                detail_rollout.raise_for_status()
                assert detail_rollout.json()["rollout"]["devices"][0]["ring"] == 0
                canceled_rollout = client.delete(f"/api/fleet-rollouts/{rollout_id}")
                canceled_rollout.raise_for_status()
                assert canceled_rollout.json()["rollout"]["status"] == "canceled"

                revoked = client.post(f"/api/devices/{device_id}/revoke")
                revoked.raise_for_status()

                audit = client.get("/api/audit?limit=100")
                audit.raise_for_status()
                tools = {x["tool"] for x in audit.json()["events"]}
                assert {
                    "admin.device.enroll",
                    "admin.device.update",
                    "admin.device.permissions",
                    "admin.device.approve",
                    "admin.device.revoke",
                }.issubset(tools)

                logout = client.delete("/api/session")
                logout.raise_for_status()
                assert client.get("/api/overview").status_code == 401
            print(
                json.dumps(
                    {
                        "status": "PASS",
                        "panel_session_cookie": "PASS",
                        "same_origin_mutation_guard": "PASS",
                        "overview": "PASS",
                        "enrollment_create_list_cancel": "PASS",
                        "device_management": "PASS",
                        "oauth_device_grants": "PASS",
                        "agent_version_drift": "PASS",
                        "admin_audit": "PASS",
                        "fleet_rollout_crud": "PASS",
                        "full_control_helper_gate": "PASS",
                        "logout": "PASS",
                    },
                    indent=2,
                )
            )
            return 0
        except Exception:
            log.flush()
            log.seek(0)
            print(log.read(), file=sys.stderr)
            raise
        finally:
            stop(server)
            log.close()


if __name__ == "__main__":
    raise SystemExit(main())
