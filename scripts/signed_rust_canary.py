"""Activate a real signed Rust binary, then restore the live Python test Agent."""

import base64
import hashlib
import json
import os
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from commandcore_agent import __version__
from commandcore_agent.update_lifecycle import (
    activate_staged,
    canonical_manifest_bytes,
    rollback_last_update,
    select_artifact,
    stage_artifact,
)
from rust_agent_smoke import BIN, ROOT, free_port, mcp, stop, wait_http, wait_online
from update_rollout_smoke import static_server


def main():
    if sys.platform != "linux":
        raise RuntimeError("This signed canary requires disposable Linux")
    with tempfile.TemporaryDirectory(prefix="commandcore-signed-canary-") as temp:
        root = Path(temp)
        install = root / "install"
        old = install / "releases" / "python-fallback"
        old.mkdir(parents=True)
        launcher = old / "commandcore-agent"
        launcher.write_text(
            "#!/bin/sh\nexec "
            + shlex.quote(sys.executable)
            + ' -m commandcore_agent.cli "$@"\n'
        )
        launcher.chmod(0o755)
        (old / "release.json").write_text(
            json.dumps({"version": __version__, "implementation": "python"})
        )
        (install / "current").symlink_to("releases/python-fallback")
        state = root / "agent.json"
        health = root / "health.json"
        policy = root / "policy.json"
        policy.write_text(json.dumps({"configured_max_permission_profile": "STANDARD"}))
        port = free_port()
        base = f"http://127.0.0.1:{port}"
        token = "disposable-signed-canary-test-0123456789abcdef"
        env = {
            **os.environ,
            "PYTHONPATH": os.pathsep.join(
                [str(ROOT / "apps/server"), str(ROOT / "agent")]
            ),
            "COMMANDCORE_HOST": "127.0.0.1",
            "COMMANDCORE_PORT": str(port),
            "COMMANDCORE_DB": str(root / "db.sqlite3"),
            "COMMANDCORE_API_TOKEN": token,
            "COMMANDCORE_PUBLIC_BOOTSTRAP_ENABLED": "true",
            "COMMANDCORE_BOOTSTRAP_SUBJECT": "canary-owner",
            "COMMANDCORE_PUBLIC_BASE_URL": base,
            "COMMANDCORE_OAUTH_ENABLED": "false",
            "COMMANDCORE_AGENT_POLICY": str(policy),
            "COMMANDCORE_AGENT_HEALTH_FILE": str(health),
            "COMMANDCORE_AGENT_STATE": str(state),
        }
        server = agent = None
        with (
            (root / "server.log").open("w+") as server_log,
            (root / "agent.log").open("w+") as agent_log,
        ):
            try:
                server = subprocess.Popen(
                    [sys.executable, "-m", "commandcore_server.main"],
                    cwd=ROOT,
                    env=env,
                    stdout=server_log,
                    stderr=subprocess.STDOUT,
                )
                wait_http(base + "/healthz")
                auth = {"Authorization": "Bearer " + token}
                enrollment = httpx.post(
                    base + "/api/enrollment-tokens", headers=auth
                ).json()["token"]
                enrolled = subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "commandcore_agent.cli",
                        "enroll",
                        enrollment,
                        "--control-url",
                        base,
                        "--agent-url",
                        f"ws://127.0.0.1:{port}/agent",
                        "--state",
                        str(state),
                    ],
                    cwd=ROOT,
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=20,
                )
                assert enrolled.returncode == 0
                device_id = json.loads(state.read_text())["device_id"]
                httpx.post(
                    base + f"/api/devices/{device_id}/approve", headers=auth
                ).raise_for_status()

                def restart():
                    nonlocal agent
                    stop(agent)
                    agent = subprocess.Popen(
                        [
                            str(install / "current" / "commandcore-agent"),
                            "run",
                            "--state",
                            str(state),
                        ],
                        cwd=ROOT,
                        env=env,
                        stdout=agent_log,
                        stderr=subprocess.STDOUT,
                    )

                restart()
                wait_online(base, token, device_id, "python")
                artifacts = root / "artifacts"
                artifacts.mkdir()
                payload = BIN.read_bytes()
                (artifacts / "agent.bin").write_bytes(payload)
                signing = Ed25519PrivateKey.generate()
                public = base64.b64encode(
                    signing.public_key().public_bytes(
                        serialization.Encoding.Raw, serialization.PublicFormat.Raw
                    )
                ).decode()
                with static_server(artifacts) as artifact_port:
                    manifest = {
                        "schema_version": 1,
                        "product": "commandcore-agent",
                        "version": __version__,
                        "signing_key_id": "disposable-canary",
                        "artifacts": [
                            {
                                "platform": "linux",
                                "architecture": "x86_64",
                                "kind": "executable",
                                "url": f"http://127.0.0.1:{artifact_port}/agent.bin",
                                "filename": "commandcore-agent",
                                "size": len(payload),
                                "sha256": hashlib.sha256(payload).hexdigest(),
                            }
                        ],
                    }
                    manifest["signature"] = base64.b64encode(
                        signing.sign(canonical_manifest_bytes(manifest))
                    ).decode()
                    staged = stage_artifact(
                        manifest,
                        select_artifact(
                            manifest, target_platform="linux", architecture="x86_64"
                        ),
                        root=root / "stage",
                        allow_insecure_http=True,
                        current_version=__version__,
                        allow_downgrade=True,
                    )
                committed = activate_staged(
                    Path(staged["metadata_path"]),
                    public,
                    install_root=install,
                    health_file=health,
                    restart_fn=restart,
                    health_timeout=20,
                    target_platform="linux",
                    architecture="x86_64",
                    allow_downgrade=True,
                )
                assert committed["status"] == "committed"
                wait_online(base, token, device_id, "rust")
                selection = mcp(
                    base, token, "devices.select", {"device": device_id}, 1
                )["selection_id"]
                assert mcp(
                    base,
                    token,
                    "shell.exec",
                    {"selection_id": selection, "command": "hostname"},
                    2,
                )["stdout"].strip()
                rolled = rollback_last_update(
                    install_root=install,
                    health_file=health,
                    restart_fn=restart,
                    health_timeout=20,
                )
                assert rolled["status"] == "manual_rollback"
                wait_online(base, token, device_id, "python")
                assert (install / "current").resolve() == old.resolve()
                assert mcp(
                    base,
                    token,
                    "shell.exec",
                    {"selection_id": selection, "command": "hostname"},
                    3,
                )["stdout"].strip()
                print(
                    json.dumps(
                        {
                            "status": "PASS",
                            "real_signed_rust_artifact": True,
                            "same_version_migration_explicit": True,
                            "authenticated_rust_health_commit": True,
                            "same_identity_preserved": True,
                            "python_rollback_reconnected": True,
                            "python_shell_after_rollback": True,
                        },
                        indent=2,
                    )
                )
            finally:
                stop(agent)
                stop(server)


if __name__ == "__main__":
    main()
