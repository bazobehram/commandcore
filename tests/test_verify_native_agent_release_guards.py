"""Fail-closed tests for the native signed-release publication verifier."""

import base64
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "native_release_verifier", ROOT / "scripts/verify_native_agent_release.py"
)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

VERSION = "0.9.0-rc9"
REPO = "bazobehram/commandcore"


def signed_fixture(tmp_path: Path, architectures=("x86_64",)):
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    artifacts = []
    for arch in architectures:
        filename = module.NAMES[arch]
        payload = f"fake test executable for {arch}".encode()
        (tmp_path / filename).write_bytes(payload)
        artifacts.append(
            {
                "architecture": arch,
                "platform": "linux",
                "kind": "executable",
                "filename": filename,
                "url": f"https://github.com/{REPO}/releases/download/agent-v{VERSION}/{filename}",
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
    manifest = {
        "schema_version": 1,
        "product": "commandcore-agent",
        "version": VERSION,
        "signing_key_id": hashlib.sha256(public).hexdigest()[:16],
        "artifacts": artifacts,
    }
    canonical = json.dumps(
        manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    manifest["signature"] = base64.b64encode(key.sign(canonical)).decode()
    (tmp_path / "manifest.signed.json").write_text(json.dumps(manifest))
    return base64.b64encode(public).decode()


@pytest.mark.parametrize(
    "architectures,requested",
    [
        (("x86_64",), "x86_64"),
        (("x86_64", "aarch64"), "aarch64"),
    ],
)
def test_valid_signed_release_accepted(tmp_path, architectures, requested):
    key = signed_fixture(tmp_path, architectures)
    module.verify(tmp_path, key, VERSION, REPO, requested)


def test_reject_extra_release_file(tmp_path):
    key = signed_fixture(tmp_path)
    (tmp_path / "private-release-key").write_text("untrusted")
    with pytest.raises(ValueError, match="unexpected_release_file"):
        module.verify(tmp_path, key, VERSION, REPO)


def test_reject_binary_symlink(tmp_path):
    key = signed_fixture(tmp_path)
    binary = tmp_path / module.NAMES["x86_64"]
    target = tmp_path / "outside"
    binary.rename(target)
    binary.symlink_to(target)
    with pytest.raises(OSError):
        module.verify(tmp_path, key, VERSION, REPO)


def test_reject_manifest_symlink(tmp_path):
    key = signed_fixture(tmp_path)
    manifest = tmp_path / "manifest.signed.json"
    outside = tmp_path / "manifest-copy"
    manifest.rename(outside)
    manifest.symlink_to(outside)
    with pytest.raises(OSError):
        module.verify(tmp_path, key, VERSION, REPO)


def test_reject_oversized_manifest(tmp_path):
    key = signed_fixture(tmp_path)
    with (tmp_path / "manifest.signed.json").open("ab") as stream:
        stream.truncate(module.MAX_MANIFEST_SIZE + 1)
    with pytest.raises(ValueError, match="invalid_release_file_type_or_size"):
        module.verify(tmp_path, key, VERSION, REPO)


def test_reject_modified_binary(tmp_path):
    key = signed_fixture(tmp_path)
    (tmp_path / module.NAMES["x86_64"]).write_bytes(b"tampered")
    with pytest.raises(ValueError, match="release_checksum_mismatch"):
        module.verify(tmp_path, key, VERSION, REPO)


def test_reject_tampered_signature(tmp_path):
    key = signed_fixture(tmp_path)
    path = tmp_path / "manifest.signed.json"
    manifest = json.loads(path.read_text())
    manifest["version"] = "0.9.0-rc8"
    path.write_text(json.dumps(manifest))
    with pytest.raises(Exception):
        module.verify(tmp_path, key, "0.9.0-rc8", REPO)


def test_reject_directory_symlink(tmp_path):
    feed = tmp_path / "feed"
    feed.mkdir()
    key = signed_fixture(feed)
    linked = tmp_path / "linked-feed"
    linked.symlink_to(feed, target_is_directory=True)
    with pytest.raises(ValueError, match="invalid_release_directory"):
        module.verify(linked, key, VERSION, REPO)
