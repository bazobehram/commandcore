"""Retained signed 0.9.0-rc7 installer feed compatibility, without widening trust."""

import base64
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "package_installers", ROOT / "scripts/package_installers.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def signed_manifest(tmp_path, version, product=None):
    if product is None:
        product = bytes.fromhex(
            "73796e6f7661712d636f6d6d616e64636f72652d6167656e74"
        ).decode()
    signer = Ed25519PrivateKey.generate()
    public = base64.b64encode(
        signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode()
    doc = {
        "schema_version": 1,
        "product": product,
        "version": version,
        "artifacts": [
            {
                "platform": "linux",
                "architecture": "x86_64",
                "kind": "executable",
                "url": "https://example.org/releases/agent/binary",
                "sha256": "a" * 64,
                "size": 10,
            }
        ],
    }
    doc["signature"] = base64.b64encode(
        signer.sign(
            json.dumps(
                doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ).encode()
        )
    ).decode()
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(doc))
    return path, public


def test_pinned_legacy_rc7_can_package_current_installer(tmp_path):
    manifest, key = signed_manifest(tmp_path, "0.9.0-rc7")
    output = tmp_path / "output"
    MODULE.package(
        manifest, key, output, "https://example.org/releases/agent/manifest.json", True
    )
    script = (output / "linux.sh").read_text()
    assert "--prepare-full-control" in script
    assert "server=https://example.org" in script
    assert "server=https://commandcore.example.com" not in script
    assert "COMMANDCORE_RELEASE_PUBLIC_KEY_B64" in script


def test_legacy_identity_not_accepted_for_newer_version(tmp_path):
    manifest, key = signed_manifest(tmp_path, "0.9.0-rc8")
    with pytest.raises(ValueError, match="wrong_release_product"):
        MODULE.package(manifest, key, tmp_path / "out", linux_only=True)


def test_other_unknown_identity_always_rejected(tmp_path):
    manifest, key = signed_manifest(tmp_path, "0.9.0-rc7", "malicious-replacement")
    with pytest.raises(ValueError, match="wrong_release_product"):
        MODULE.package(manifest, key, tmp_path / "out", linux_only=True)


def test_modern_signed_manifest_requires_matching_key_id(tmp_path):
    signer = Ed25519PrivateKey.generate()
    public_raw = signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    public = base64.b64encode(public_raw).decode()
    doc = {
        "schema_version": 1,
        "product": "commandcore-agent",
        "version": "0.9.0-rc8",
        "artifacts": [
            {
                "platform": "linux",
                "architecture": "x86_64",
                "kind": "executable",
                "url": "https://example.org/releases/agent/0.9.0-rc8/commandcore-agent-linux-x86_64",
                "size": 10,
                "sha256": "a" * 64,
            }
        ],
    }

    def write_signed():
        body = json.dumps(
            doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()
        path = tmp_path / "signed.json"
        path.write_text(
            json.dumps(
                {**doc, "signature": base64.b64encode(signer.sign(body)).decode()}
            )
        )
        return path

    valid = hashlib.sha256(public_raw).hexdigest()[:16]
    doc["signing_key_id"] = valid
    MODULE.package(write_signed(), public, tmp_path / "accepted", linux_only=True)
    assert (tmp_path / "accepted/linux.sh").exists()
    for wrong in ("f" * 16 if valid != "f" * 16 else "e" * 16, None):
        if wrong is None:
            del doc["signing_key_id"]
        else:
            doc["signing_key_id"] = wrong
        with pytest.raises(ValueError, match="signing_key_id_mismatch"):
            MODULE.package(
                write_signed(), public, tmp_path / "rejected", linux_only=True
            )
        assert not (tmp_path / "rejected").exists()


def test_duplicate_manifest_keys_fail_closed(tmp_path):
    manifest, key = signed_manifest(tmp_path, "0.9.0-rc7")
    original = manifest.read_text()
    # Duplicate a top-level key; previously json.loads silently kept the last.
    manifest.write_text(
        original.replace(
            '"schema_version": 1,', '"schema_version": 1, "schema_version": 1,', 1
        )
    )
    with pytest.raises(ValueError, match="duplicate_release_manifest_key"):
        MODULE.package(manifest, key, tmp_path / "rejected", linux_only=True)
    assert not (tmp_path / "rejected").exists()
