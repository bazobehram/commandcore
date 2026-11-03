"""Offline public-feed rejection matrix, using fresh in-memory test signers only."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "verify_public_feed_staging", ROOT / "scripts/verify_public_feed_staging.py"
)
assert spec and spec.loader
MODULE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(MODULE)

packer_spec = importlib.util.spec_from_file_location(
    "package_installers", ROOT / "scripts/package_installers.py"
)
assert packer_spec and packer_spec.loader
PACKER = importlib.util.module_from_spec(packer_spec)
packer_spec.loader.exec_module(PACKER)

ORIGIN = "https://commandcore.example.com"
VERSION = "0.9.0-rc8"


def signed_fixture(tmp_path: Path, architectures=("x86_64",)):
    signer = Ed25519PrivateKey.generate()
    public = signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    public_b64 = base64.b64encode(public).decode()
    fingerprint = hashlib.sha256(public).hexdigest()
    outside_key = tmp_path / "operator-reviewed-key.txt"
    outside_key.write_text(public_b64 + "\n")
    release = tmp_path / "candidate"
    docs = []
    for arch in architectures:
        name = MODULE.ARCH_BINARY[arch]
        body = ("native-" + arch).encode()
        docs.append(
            {
                "platform": "linux",
                "architecture": arch,
                "filename": name,
                "kind": "executable",
                "url": f"{ORIGIN}/releases/agent/{VERSION}/{name}",
                "size": len(body),
                "sha256": hashlib.sha256(body).hexdigest(),
            }
        )
    manifest = {
        "schema_version": 1,
        "product": "commandcore-agent",
        "version": VERSION,
        "signing_key_id": fingerprint[:16],
        "artifacts": docs,
    }
    source = tmp_path / "manifest.input.json"
    def resign():
        raw = json.dumps(
            manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()
        manifest["signature"] = base64.b64encode(signer.sign(raw)).decode()
        source.write_text(json.dumps(manifest))
    resign()
    PACKER.package(
        source,
        public_b64,
        release,
        f"{ORIGIN}/releases/agent/manifest.json",
        linux_only=True,
    )
    versioned = release / VERSION
    versioned.mkdir()
    for arch in architectures:
        (versioned / MODULE.ARCH_BINARY[arch]).write_bytes(("native-" + arch).encode())
    return release, outside_key, fingerprint, manifest, signer


def validate(fixture, origin=ORIGIN):
    feed, key, fingerprint, *_ = fixture
    return MODULE.verify(feed, key, fingerprint, origin, VERSION)


def rewrite_signed(fixture, manifest):
    feed, _, _, _, signer = fixture
    body = {key: value for key, value in manifest.items() if key != "signature"}
    raw = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    manifest["signature"] = base64.b64encode(signer.sign(raw.encode())).decode()
    (feed / "manifest.json").write_text(json.dumps(manifest))


def test_single_architecture_signed_feed_passes(tmp_path):
    fixture = signed_fixture(tmp_path)
    assert validate(fixture) == {"architecture_count": 1, "version": VERSION}


def test_dual_architecture_signed_feed_passes(tmp_path):
    fixture = signed_fixture(tmp_path, ("x86_64", "arm64"))
    assert validate(fixture)["architecture_count"] == 2


def test_wrong_trusted_key_or_fingerprint_fails(tmp_path):
    fixture = signed_fixture(tmp_path)
    with pytest.raises(ValueError, match="untrusted_release_key"):
        MODULE.verify(fixture[0], fixture[1], "f" * 64, ORIGIN, VERSION)
    different = tmp_path / "different-public-key.txt"
    public = Ed25519PrivateKey.generate().public_key()
    different.write_text(
        base64.b64encode(public.public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
    )
    with pytest.raises(ValueError, match="untrusted_release_key"):
        MODULE.verify(fixture[0], different, fixture[2], ORIGIN, VERSION)


def test_trusted_key_cannot_come_from_candidate_feed(tmp_path):
    fixture = signed_fixture(tmp_path)
    inside = fixture[0] / "operator-provided-key.txt"
    inside.write_text(fixture[1].read_text())
    with pytest.raises(ValueError, match="key_must_be_independent_of_feed"):
        MODULE.verify(fixture[0], inside, fixture[2], ORIGIN, VERSION)


@pytest.mark.parametrize("mutation", ["artifact", "length"])
def test_binary_tampering_rejected(tmp_path, mutation):
    fixture = signed_fixture(tmp_path)
    binary = fixture[0] / VERSION / "commandcore-agent-linux-x86_64"
    if mutation == "artifact":
        binary.write_bytes(b"spoofed-binary")
        with pytest.raises(ValueError, match="artifact_size_mismatch"):
            validate(fixture)
    else:
        body = binary.read_bytes()
        binary.write_bytes(b"X" + body[1:])
        with pytest.raises(ValueError, match="artifact_sha256_mismatch"):
            validate(fixture)


def test_unsigned_manifest_mutation_fails_signature(tmp_path):
    fixture = signed_fixture(tmp_path)
    manifest = json.loads((fixture[0] / "manifest.json").read_text())
    manifest["version"] = "0.9.0-rc9"
    (fixture[0] / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(Exception):
        validate(fixture)


@pytest.mark.parametrize("kind", ["foreign_origin", "duplicate_arch", "wrong_id", "server"])
def test_wrong_signed_release_scope_rejected(tmp_path, kind):
    fixture = signed_fixture(tmp_path)
    manifest = json.loads((fixture[0] / "manifest.json").read_text())
    if kind == "foreign_origin":
        manifest["artifacts"][0]["url"] = (
            "https://unrelated.example.net/releases/agent/0.9.0-rc8/commandcore-agent-linux-x86_64"
        )
        expected = "unapproved_artifact_url_or_type"
    elif kind == "duplicate_arch":
        manifest["artifacts"].append(dict(manifest["artifacts"][0]))
        expected = "unsupported_or_duplicate_architecture"
    elif kind == "wrong_id":
        manifest["signing_key_id"] = "f" * 16
        expected = "invalid_signed_release_identity"
    else:
        manifest["artifacts"][0]["platform"] = "windows"
        expected = "unapproved_artifact_url_or_type"
    rewrite_signed(fixture, manifest)
    with pytest.raises(ValueError, match=expected):
        validate(fixture)


def test_installer_trust_pin_mismatch_rejected(tmp_path):
    fixture = signed_fixture(tmp_path)
    script = fixture[0] / "linux.sh"
    script.write_text(script.read_text().replace("export COMMANDCORE_RELEASE_PUBLIC_KEY_B64", "echo UNPINNED"))
    with pytest.raises(ValueError, match="installer_pins_mismatch"):
        validate(fixture)


def test_unknown_feed_files_rejected(tmp_path):
    fixture = signed_fixture(tmp_path)
    (fixture[0] / "operator-notes.txt").write_text("should not publish")
    with pytest.raises(ValueError, match="unexpected_root_file"):
        validate(fixture)


@pytest.mark.skipif(__import__("os").name == "nt", reason="unprivileged symlink Windows")
def test_symlinked_binary_rejected(tmp_path):
    fixture = signed_fixture(tmp_path)
    binary = fixture[0] / VERSION / "commandcore-agent-linux-x86_64"
    target = tmp_path / "artifact-copy"
    target.write_bytes(binary.read_bytes())
    binary.unlink()
    binary.symlink_to(target)
    with pytest.raises(ValueError, match="symlink_artifact"):
        validate(fixture)


@pytest.mark.parametrize(
    "origin",
    [
        "http://commandcore.example.com",
        "https://commandcore.example.com/release",
        "https://user:pass@commandcore.example.com",
        "https://commandcore.example.com?override=1",
        "https://commandcore.example.com:8443",
    ],
)
def test_unexpected_origins_failing_closed(tmp_path, origin):
    fixture = signed_fixture(tmp_path)
    with pytest.raises(ValueError, match="invalid_expected_origin"):
        validate(fixture, origin=origin)
