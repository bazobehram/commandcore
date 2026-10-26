import base64
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

p = Path(__file__).resolve().parents[1] / "scripts/verify_signed_helper_wheelhouse.py"
s = importlib.util.spec_from_file_location("signed_wheels", p)
module = importlib.util.module_from_spec(s)
s.loader.exec_module(module)


def fixture(tmp_path, include_inventory=True):
    private = Ed25519PrivateKey.generate()
    public = base64.b64encode(
        private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    ).decode()
    artifact = tmp_path / "helper.tar.gz"
    artifact.write_bytes(b"helper")
    wheelhouse = tmp_path / "wheels"
    wheelhouse.mkdir()
    wheel = wheelhouse / "commandcore_agent-1.0-py3-none-any.whl"
    wheel.write_bytes(b"offline dependency bytes")
    doc = {
        "schema_version": 1,
        "product": "commandcore-agent",
        "version": "1.0",
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
    if include_inventory:
        doc["offline_wheelhouse"] = {
            "schema_version": 1,
            "product": "commandcore-helper-wheelhouse",
            "wheels": [
                {
                    "name": wheel.name,
                    "size": wheel.stat().st_size,
                    "sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
                }
            ],
        }
    data = json.dumps(
        doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    doc["signature"] = base64.b64encode(private.sign(data)).decode()
    manifest = tmp_path / "signed.json"
    manifest.write_text(json.dumps(doc))
    return manifest, artifact, wheelhouse, public, wheel


def test_signed_inventory_success(tmp_path):
    manifest, artifact, wheels, key, _ = fixture(tmp_path)
    assert module.verify(manifest, artifact, wheels, key, "x86_64")["wheel_count"] == 1


def test_changed_dependency_rejected(tmp_path):
    manifest, artifact, wheels, key, wheel = fixture(tmp_path)
    wheel.write_bytes(b"tampered")
    with pytest.raises(ValueError):
        module.verify(manifest, artifact, wheels, key, "x86_64")


def test_missing_signed_inventory_rejected(tmp_path):
    manifest, artifact, wheels, key, _ = fixture(tmp_path, include_inventory=False)
    with pytest.raises(ValueError, match="offline_wheelhouse"):
        module.verify(manifest, artifact, wheels, key, "x86_64")


def test_modified_inventory_rejected_by_signature(tmp_path):
    manifest, artifact, wheels, key, _ = fixture(tmp_path)
    doc = json.loads(manifest.read_text())
    doc["offline_wheelhouse"]["wheels"][0]["size"] += 1
    manifest.write_text(json.dumps(doc))
    with pytest.raises(Exception):
        module.verify(manifest, artifact, wheels, key, "x86_64")
