#!/usr/bin/env python3
from __future__ import annotations
import base64, hashlib, http.server, json, socketserver, tempfile, threading, time
from contextlib import contextmanager
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from commandcore_agent.update_lifecycle import (
    activate_staged,
    canonical_manifest_bytes,
    rollback_last_update,
    select_artifact,
    stage_artifact,
)


@contextmanager
def static_server(root: Path):
    class H(http.server.SimpleHTTPRequestHandler):
        def log_message(self, *args):
            pass

    handler = lambda *a, **kw: H(*a, directory=str(root), **kw)
    with socketserver.TCPServer(("127.0.0.1", 0), handler) as srv:
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            yield srv.server_address[1]
        finally:
            srv.shutdown()
            t.join(timeout=2)


def health(path: Path, version: str):
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "version": version,
                "connected": True,
                "observed_at_unix": time.time() + 0.02,
            }
        )
    )


def main():
    with tempfile.TemporaryDirectory(prefix="cc-rollout-") as td:
        root = Path(td)
        install = root / "install"
        releases = install / "releases"
        old = releases / "0.7.0-python"
        old.mkdir(parents=True)
        (old / "release.json").write_text(
            json.dumps({"version": "0.7.0", "implementation": "python"})
        )
        (install / "current").symlink_to(Path("releases") / old.name)
        payload = b"#!/bin/sh\nexit 0\n"
        (root / "agent.bin").write_bytes(payload)
        key = Ed25519PrivateKey.generate()
        public = base64.b64encode(
            key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
        ).decode()
        with static_server(root) as port:
            manifest = {
                "schema_version": 1,
                "product": "commandcore-agent",
                "version": "0.8.0",
                "signing_key_id": "smoke",
                "artifacts": [
                    {
                        "platform": "linux",
                        "architecture": "x86_64",
                        "kind": "executable",
                        "url": f"http://127.0.0.1:{port}/agent.bin",
                        "filename": "commandcore-agent",
                        "size": len(payload),
                        "sha256": hashlib.sha256(payload).hexdigest(),
                    }
                ],
            }
            manifest["signature"] = base64.b64encode(
                key.sign(canonical_manifest_bytes(manifest))
            ).decode()
            staged = stage_artifact(
                manifest,
                select_artifact(
                    manifest, target_platform="linux", architecture="x86_64"
                ),
                root=root / "stage",
                allow_insecure_http=True,
                current_version="0.7.0",
            )
        hp = root / "health.json"

        def restart():
            meta = json.loads(
                ((install / "current").resolve() / "release.json").read_text()
            )
            health(hp, meta["version"])

        committed = activate_staged(
            Path(staged["metadata_path"]),
            public,
            install_root=install,
            health_file=hp,
            restart_fn=restart,
            health_timeout=1,
            target_platform="linux",
            architecture="x86_64",
        )
        rolled = rollback_last_update(
            install_root=install, health_file=hp, restart_fn=restart, health_timeout=1
        )
        assert (
            committed["status"] == "committed" and rolled["status"] == "manual_rollback"
        )
        assert (install / "current").resolve() == old.resolve()
        print(
            json.dumps(
                {
                    "status": "PASS",
                    "signed_stage": True,
                    "atomic_activate": True,
                    "fresh_health_commit": True,
                    "manual_rollback": True,
                    "restored_version": "0.7.0",
                },
                indent=2,
            )
        )


if __name__ == "__main__":
    main()
