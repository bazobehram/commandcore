"""Signed helper verifier rejects unsigned or tampered privileged code."""

import base64
import hashlib
import json
import runpy
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

verify = runpy.run_path(
    str(Path(__file__).resolve().parents[1] / "scripts" / "verify_signed_helper.py")
)["verify"]


def make_release(tmp_path):
    private = Ed25519PrivateKey.generate()
    public = base64.b64encode(
        private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode()
    artifact = tmp_path / "helper.tar.gz"
    artifact.write_bytes(b"fixture not executable")
    doc = {
        "schema_version": 1,
        "product": "commandcore-agent",
        "version": "test",
        "artifacts": [
            {
                "platform": "linux",
                "architecture": "x86_64",
                "kind": "privileged-helper",
                "size": artifact.stat().st_size,
                "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            }
        ],
    }
    data = json.dumps(
        doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    doc["signature"] = base64.b64encode(private.sign(data)).decode()
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps(doc))
    return manifest, artifact, public


def test_signed_helper_passes(tmp_path):
    manifest, artifact, key = make_release(tmp_path)
    assert verify(manifest, artifact, key, architecture="x86_64")["version"] == "test"


def test_tampered_helper_rejected(tmp_path):
    manifest, artifact, key = make_release(tmp_path)
    artifact.write_bytes(b"fixture tampered code")
    with pytest.raises(ValueError):
        verify(manifest, artifact, key, architecture="x86_64")


def test_wrong_architecture_rejected(tmp_path):
    manifest, artifact, key = make_release(tmp_path)
    with pytest.raises(ValueError):
        verify(manifest, artifact, key, architecture="arm64")


def test_unsigned_change_rejected(tmp_path):
    manifest, artifact, key = make_release(tmp_path)
    document = json.loads(manifest.read_text())
    document["artifacts"][0]["kind"] = "executable"
    manifest.write_text(json.dumps(document))
    with pytest.raises(Exception):
        verify(manifest, artifact, key, architecture="x86_64")
