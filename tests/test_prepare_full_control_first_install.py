"""A signed helper may be prepared in one installer invocation, never silently."""

import base64
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


path = (
    Path(__file__).resolve().parents[1]
    / "scripts/prepare_full_control_first_install.py"
)
spec = importlib.util.spec_from_file_location("cc_first_install", path)
setup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(setup)


def _signed_fixtures():
    artifact = b"disposable helper archive"
    wheel = b"disposable pip wheel"
    records = [
        {
            "filename": "commandcore-helper-linux-x86_64.tar.gz",
            "platform": "linux",
            "architecture": "x86_64",
            "kind": "privileged-helper",
            "sha256": hashlib.sha256(artifact).hexdigest(),
            "size": len(artifact),
        }
    ]
    wheel_item = {
        "name": "pip-25.3-py3-none-any.whl",
        "sha256": hashlib.sha256(wheel).hexdigest(),
        "size": len(wheel),
    }
    doc = {
        "schema_version": 1,
        "product": "commandcore-agent",
        "version": "0.9.0-rc8",
        "python_minor": "3.12",
        "source_commit_sha": "a" * 40,
        "artifacts": records,
        "offline_wheelhouse": {
            "schema_version": 1,
            "product": "commandcore-helper-wheelhouse",
            "wheels": [wheel_item],
        },
    }
    priv = Ed25519PrivateKey.generate()
    key = base64.b64encode(
        priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    ).decode()
    canonical = json.dumps(
        doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    doc["signature"] = base64.b64encode(priv.sign(canonical)).decode()
    assets = {
        "manifest.signed.json": json.dumps(doc).encode(),
        "commandcore-helper-linux-x86_64.tar.gz": artifact,
        "pip-25.3-py3-none-any.whl": wheel,
    }
    assets.update({name: b"approved source" for name in setup.SCRIPTS})
    return key, assets, doc


def test_download_verifies_signature_every_asset_and_never_invokes_sudo(monkeypatch):
    key, assets, _ = _signed_fixtures()
    visited = []

    def fetch(url, output, size):
        visited.append(url)
        output.write_bytes(assets[url.rsplit("/", 1)[-1]])

    monkeypatch.setattr(setup, "_fetch", fetch)
    monkeypatch.setattr(setup.os, "geteuid", lambda: 1000)
    result = setup.prepare(
        "https://github.com/example/release",
        key,
        "0.9.0-rc8",
        "x86_64",
        "3.12",
        "agent",
        verify_only=True,
    )
    assert result["result"] == "SIGNED_RELEASE_DOWNLOADED_NOT_INSTALLED"
    assert len(visited) == 3 + len(setup.SCRIPTS)
    assert all(url.startswith("https://") for url in visited)


def test_signature_failure_aborts_before_scripts_or_sudo(monkeypatch):
    key, assets, doc = _signed_fixtures()
    doc["version"] = "0.9.0-rc9"
    assets["manifest.signed.json"] = json.dumps(doc).encode()
    visited = []

    def fetch(url, output, size):
        visited.append(url)
        output.write_bytes(assets[url.rsplit("/", 1)[-1]])

    monkeypatch.setattr(setup, "_fetch", fetch)
    monkeypatch.setattr(setup.os, "geteuid", lambda: 1000)
    with pytest.raises(ValueError, match="signature"):
        setup.prepare(
            "https://github.com/example/release",
            key,
            "0.9.0-rc8",
            "x86_64",
            "3.12",
            "agent",
            verify_only=True,
        )
    assert len(visited) == 1


def test_signed_digest_mismatch_stops_before_privileged_scripts(monkeypatch):
    key, assets, _ = _signed_fixtures()
    assets["pip-25.3-py3-none-any.whl"] = b"tampered wheel"
    visited = []

    def fetch(url, output, size):
        visited.append(url)
        output.write_bytes(assets[url.rsplit("/", 1)[-1]])

    monkeypatch.setattr(setup, "_fetch", fetch)
    monkeypatch.setattr(setup.os, "geteuid", lambda: 1000)
    with pytest.raises(ValueError, match="size mismatch|digest mismatch"):
        setup.prepare(
            "https://github.com/example/release",
            key,
            "0.9.0-rc8",
            "x86_64",
            "3.12",
            "agent",
            verify_only=True,
        )
    assert len(visited) == 3


def test_invalid_release_url_and_unsafe_wheel_inventory_fail_closed():
    for url in (
        "http://example.com/release",
        "https://user:password@example.com/releases",
        "https://example.com/releases?token=a",
    ):
        with pytest.raises(ValueError, match="HTTPS"):
            setup._url(url)
    key, assets, doc = _signed_fixtures()
    doc["offline_wheelhouse"]["wheels"][0]["name"] = "../pip.whl"
    with pytest.raises(ValueError, match="signed pip bootstrap"):
        setup._validate_document(doc, "0.9.0-rc8", "x86_64", "3.12")


def test_duplicate_manifest_fields_rejected():
    with pytest.raises(ValueError, match="duplicate"):
        json.loads('{"a":1,"a":2}', object_pairs_hook=setup._no_duplicate_keys)


def test_local_sudo_is_reached_only_after_all_signed_release_assets(monkeypatch):
    key, assets, _ = _signed_fixtures()
    from types import SimpleNamespace

    events = []

    def fetch(url, output, size):
        events.append(("download", url.rsplit("/", 1)[-1]))
        output.write_bytes(assets[url.rsplit("/", 1)[-1]])

    real_run = setup.subprocess.run

    def run(argv, **kwargs):
        if argv[0] == "sudo":
            events.append(("approval", "sudo"))
            assert all(("download", name) in events for name in setup.SCRIPTS)
            assert kwargs.get("check") is True
            assert kwargs["env"]["PYTHONDONTWRITEBYTECODE"] == "1"
            assert argv[3] == "-B"  # sudo -- python -B
            return SimpleNamespace(returncode=0)
        return real_run(argv, **kwargs)

    monkeypatch.setattr(setup, "_fetch", fetch)
    monkeypatch.setattr(setup.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(setup.subprocess, "run", run)
    result = setup.prepare(
        "https://github.com/example/release",
        key,
        "0.9.0-rc8",
        "x86_64",
        "3.12",
        "agent",
    )
    assert result["result"] == "LOCAL_HELPER_SETUP_REQUESTED"
    assert events[-1] == ("approval", "sudo")
