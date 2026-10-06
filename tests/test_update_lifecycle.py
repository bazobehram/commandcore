from __future__ import annotations

import base64
import hashlib
import http.server
import json
import socketserver
import threading
from contextlib import contextmanager
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from commandcore_agent.update_lifecycle import (
    canonical_manifest_bytes,
    select_artifact,
    stage_artifact,
    verify_manifest,
)


def signing_pair():
    private = Ed25519PrivateKey.generate()
    public_b64 = base64.b64encode(
        private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    ).decode()
    return private, public_b64


def signed_manifest(private, artifact_url, payload: bytes):
    data = {
        "schema_version": 1,
        "product": "commandcore-agent",
        "version": "0.5.1",
        "published_at": "2026-09-29T00:00:00Z",
        "signing_key_id": "test-release-key",
        "artifacts": [
            {
                "platform": "linux",
                "architecture": "x86_64",
                "url": artifact_url,
                "filename": "commandcore-agent",
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        ],
    }
    data["signature"] = base64.b64encode(
        private.sign(canonical_manifest_bytes(data))
    ).decode()
    return data


@contextmanager
def static_server(root: Path):
    class Handler(http.server.SimpleHTTPRequestHandler):
        def log_message(self, *args):
            pass

    handler = lambda *args, **kwargs: Handler(*args, directory=str(root), **kwargs)
    with socketserver.TCPServer(("127.0.0.1", 0), handler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server.server_address[1]
        finally:
            server.shutdown()
            thread.join(timeout=2)


def test_signed_update_manifest_and_staging(tmp_path):
    private, public_b64 = signing_pair()
    payload = b"commandcore-test-binary-v0.5.1\n"
    (tmp_path / "agent.bin").write_bytes(payload)
    with static_server(tmp_path) as port:
        manifest = signed_manifest(
            private, f"http://127.0.0.1:{port}/agent.bin", payload
        )
        verify_manifest(manifest, public_b64)
        artifact = select_artifact(
            manifest, target_platform="linux", architecture="x86_64"
        )
        staged = stage_artifact(
            manifest,
            artifact,
            root=tmp_path / "staged",
            allow_insecure_http=True,
            current_version="0.5.0",
        )
    assert Path(staged["path"]).read_bytes() == payload
    metadata = json.loads(Path(staged["metadata_path"]).read_text())
    assert metadata["status"] == "staged"
    assert metadata["previous_version"] == "0.5.0"
    assert metadata["sha256"] == hashlib.sha256(payload).hexdigest()


def test_manifest_tampering_is_rejected():
    private, public_b64 = signing_pair()
    manifest = signed_manifest(private, "https://example.invalid/agent", b"x")
    manifest["version"] = "9.9.9"
    with pytest.raises(ValueError, match="invalid_update_manifest_signature"):
        verify_manifest(manifest, public_b64)


def test_arm_release_alias_selects_signed_artifact(monkeypatch):
    from commandcore_agent import update_lifecycle

    monkeypatch.setattr(update_lifecycle.platform, "machine", lambda: "aarch64")
    artifact = {
        "platform": "linux",
        "architecture": "arm64",
        "kind": "executable",
        "url": "https://example.com/arm64",
        "sha256": "a" * 64,
    }
    assert (
        select_artifact({"artifacts": [artifact]}, target_platform="linux") == artifact
    )
    assert (
        select_artifact(
            {"artifacts": [artifact]}, target_platform="linux", architecture="aarch64"
        )
        == artifact
    )


def test_update_http_is_rejected_outside_loopback():
    private, public_b64 = signing_pair()
    manifest = signed_manifest(private, "http://example.com/agent", b"x")
    verify_manifest(manifest, public_b64)
    artifact = select_artifact(manifest, target_platform="linux", architecture="x86_64")
    with pytest.raises(ValueError, match="update_url_must_use_https"):
        stage_artifact(
            manifest, artifact, root=Path("/tmp/unused"), allow_insecure_http=True
        )


def _prepare_staged_executable(
    tmp_path, *, version="0.6.1", payload=b"#!/bin/sh\nexit 0\n"
):
    private, public_b64 = signing_pair()
    (tmp_path / "agent.bin").write_bytes(payload)
    with static_server(tmp_path) as port:
        manifest = signed_manifest(
            private, f"http://127.0.0.1:{port}/agent.bin", payload
        )
        manifest["version"] = version
        manifest["signature"] = base64.b64encode(
            private.sign(canonical_manifest_bytes(manifest))
        ).decode()
        artifact = select_artifact(
            manifest, target_platform="linux", architecture="x86_64"
        )
        staged = stage_artifact(
            manifest,
            artifact,
            root=tmp_path / "staged",
            allow_insecure_http=True,
            current_version="0.6.0",
        )
    return private, public_b64, staged


def _install_previous(install_root: Path, version="0.6.0"):
    release = install_root / "releases" / f"{version}-python"
    release.mkdir(parents=True)
    (release / "release.json").write_text(
        json.dumps({"version": version, "implementation": "python"})
    )
    (release / "commandcore-agent").write_text("#!/bin/sh\nexit 0\n")
    (install_root / "current").symlink_to(Path("releases") / release.name)
    return release


def _write_health(path: Path, version: str):
    import time

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "version": version,
                "connected": True,
                "observed_at_unix": time.time() + 0.01,
            }
        )
    )


def test_activation_commits_after_fresh_health(tmp_path):
    from commandcore_agent.update_lifecycle import activate_staged

    _, public_b64, staged = _prepare_staged_executable(tmp_path)
    install_root = tmp_path / "install"
    _install_previous(install_root)
    health = tmp_path / "health.json"

    def restart():
        target = (install_root / "current").resolve()
        meta = json.loads((target / "release.json").read_text())
        _write_health(health, meta["version"])

    result = activate_staged(
        Path(staged["metadata_path"]),
        public_b64,
        install_root=install_root,
        health_file=health,
        restart_fn=restart,
        health_timeout=1,
        target_platform="linux",
        architecture="x86_64",
    )
    assert result["status"] == "committed"
    assert result["candidate_version"] == "0.6.1"
    assert "0.6.1-native-" in str((install_root / "current").resolve())
    assert (install_root / "current" / "commandcore-agent").stat().st_mode & 0o111


def test_activation_health_failure_rolls_back(tmp_path):
    from commandcore_agent.update_lifecycle import activate_staged

    _, public_b64, staged = _prepare_staged_executable(tmp_path)
    install_root = tmp_path / "install"
    previous = _install_previous(install_root)
    health = tmp_path / "health.json"
    calls = 0

    def restart():
        nonlocal calls
        calls += 1
        # Candidate never becomes healthy. The rollback restart does.
        if calls >= 2:
            _write_health(health, "0.6.0")

    with pytest.raises(RuntimeError, match="update_activation_failed:rolled_back"):
        activate_staged(
            Path(staged["metadata_path"]),
            public_b64,
            install_root=install_root,
            health_file=health,
            restart_fn=restart,
            health_timeout=0.05,
            target_platform="linux",
            architecture="x86_64",
        )
    assert (install_root / "current").resolve() == previous.resolve()
    rollout = json.loads((install_root / "rollout.json").read_text())
    assert rollout["status"] == "rolled_back"


def test_activation_reverifies_signed_manifest_and_artifact(tmp_path):
    from commandcore_agent.update_lifecycle import activate_staged

    _, public_b64, staged = _prepare_staged_executable(tmp_path)
    meta_path = Path(staged["metadata_path"])
    meta = json.loads(meta_path.read_text())
    meta["manifest"]["version"] = "9.9.9"
    meta_path.write_text(json.dumps(meta))
    install_root = tmp_path / "install"
    _install_previous(install_root)
    with pytest.raises(ValueError, match="invalid_update_manifest_signature"):
        activate_staged(
            meta_path,
            public_b64,
            install_root=install_root,
            health_file=tmp_path / "health.json",
            restart_fn=lambda: None,
            target_platform="linux",
            architecture="x86_64",
        )


def test_manual_rollback_restores_previous_release(tmp_path):
    from commandcore_agent.update_lifecycle import activate_staged, rollback_last_update

    _, public_b64, staged = _prepare_staged_executable(tmp_path)
    install_root = tmp_path / "install"
    previous = _install_previous(install_root)
    health = tmp_path / "health.json"

    def restart_current():
        target = (install_root / "current").resolve()
        meta = json.loads((target / "release.json").read_text())
        _write_health(health, meta["version"])

    activate_staged(
        Path(staged["metadata_path"]),
        public_b64,
        install_root=install_root,
        health_file=health,
        restart_fn=restart_current,
        health_timeout=1,
        target_platform="linux",
        architecture="x86_64",
    )
    result = rollback_last_update(
        install_root=install_root,
        health_file=health,
        restart_fn=restart_current,
        health_timeout=1,
    )
    assert result["status"] == "manual_rollback"
    assert (install_root / "current").resolve() == previous.resolve()


def test_signed_downgrade_is_rejected_by_default(tmp_path):
    private, _ = signing_pair()
    payload = b"old-but-signed"
    (tmp_path / "agent.bin").write_bytes(payload)
    with static_server(tmp_path) as port:
        manifest = signed_manifest(
            private, f"http://127.0.0.1:{port}/agent.bin", payload
        )
        manifest["version"] = "0.5.9"
        manifest["signature"] = base64.b64encode(
            private.sign(canonical_manifest_bytes(manifest))
        ).decode()
        artifact = select_artifact(
            manifest, target_platform="linux", architecture="x86_64"
        )
        with pytest.raises(ValueError, match="update_not_newer_than_current"):
            stage_artifact(
                manifest,
                artifact,
                root=tmp_path / "staged",
                allow_insecure_http=True,
                current_version="0.6.0",
            )
