#!/usr/bin/env python3
"""Offline pre-publication validation of a deployment's Linux Agent feed.

This is a read-only integrity gate, NOT signing, publishing, provenance
attestation, an install test, or platform support approval. The operator must
supply an independently trusted public key and its independently recorded
fingerprint. No private signing key is accepted or generated.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import stat
import struct
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

MAX_MANIFEST = 1_048_576
MAX_INSTALLER = 65_536
MAX_BINARY = 134_217_728
ARCH_BINARY = {
    "x86_64": "commandcore-agent-linux-x86_64",
    "arm64": "commandcore-agent-linux-arm64",
}
ELF_MACHINE = {"x86_64": 62, "arm64": 183}
VERSION_RE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?")
FINGERPRINT_RE = re.compile(r"[a-f0-9]{64}")


def _reject(code: str) -> None:
    raise ValueError(code)


def _safe_file(path: Path, maximum: int) -> bytes:
    # No symlinks or special files in anything intended for HTTP distribution.
    if path.is_symlink():
        _reject("symlink_file")
    try:
        info = path.stat()
    except OSError:
        _reject("missing_file")
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= maximum:
        _reject("invalid_file")
    return path.read_bytes()


def _pairs_no_duplicates(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            _reject("duplicate_manifest_key")
        result[key] = value
    return result


def _origin(value: str) -> str:
    url = urlsplit(value)
    if (
        url.scheme != "https"
        or not url.hostname
        or url.username
        or url.password
        or url.path not in ("", "/")
        or url.query
        or url.fragment
        or any(ord(c) < 33 or ord(c) == 127 for c in value)
        or url.port not in (None, 443)
    ):
        _reject("invalid_expected_origin")
    return "https://" + url.hostname.lower()


def _read_binary(
    path: Path, expected_size: int, expected_sha: str, architecture: str
) -> None:
    if path.is_symlink():
        _reject("symlink_artifact")
    try:
        info = path.stat()
    except OSError:
        _reject("missing_artifact")
    if not stat.S_ISREG(info.st_mode) or info.st_size != expected_size:
        _reject("artifact_size_mismatch")
    hashed = hashlib.sha256()
    with path.open("rb") as file:
        header = file.read(20)
        # Linux native review binaries are PIE ELF64 little-endian executables.
        # Signature and SHA alone cannot detect a signer accidentally associating
        # a valid ARM64 executable with the x86_64 manifest entry (or vice versa).
        if (
            len(header) != 20
            or header[:7] != b"\x7fELF\x02\x01\x01"
            or struct.unpack_from("<H", header, 16)[0] != 3
            or struct.unpack_from("<H", header, 18)[0] != ELF_MACHINE[architecture]
        ):
            _reject("artifact_elf_architecture_mismatch")
        hashed.update(header)
        while chunk := file.read(1024 * 1024):
            hashed.update(chunk)
    if hashed.hexdigest() != expected_sha:
        _reject("artifact_sha256_mismatch")


def verify(
    feed: Path,
    trusted_public_key_file: Path,
    expected_key_sha256: str,
    expected_origin: str,
    expected_version: str,
) -> dict[str, object]:
    """Validate candidate staging bytes without executing or mutating them."""
    if not FINGERPRINT_RE.fullmatch(expected_key_sha256):
        _reject("invalid_expected_key_fingerprint")
    if not VERSION_RE.fullmatch(expected_version):
        _reject("invalid_expected_version")
    origin = _origin(expected_origin)
    if feed.is_symlink() or not feed.is_dir():
        _reject("invalid_feed_directory")
    key_text = _safe_file(trusted_public_key_file, 256).decode("ascii").strip()
    public_bytes = base64.b64decode(key_text, validate=True)
    if (
        len(public_bytes) != 32
        or hashlib.sha256(public_bytes).hexdigest() != expected_key_sha256
    ):
        _reject("untrusted_release_key")
    if (
        trusted_public_key_file.resolve() == feed.resolve()
        or feed.resolve() in trusted_public_key_file.resolve().parents
    ):
        _reject("key_must_be_independent_of_feed")

    raw = _safe_file(feed / "manifest.json", MAX_MANIFEST)
    manifest = json.loads(raw, object_pairs_hook=_pairs_no_duplicates)
    if not isinstance(manifest, dict):
        _reject("invalid_manifest_type")
    signature = base64.b64decode(manifest["signature"], validate=True)
    if len(signature) != 64:
        _reject("invalid_signature")
    canonical = json.dumps(
        {key: value for key, value in manifest.items() if key != "signature"},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()
    Ed25519PublicKey.from_public_bytes(public_bytes).verify(signature, canonical)
    if (
        manifest.get("schema_version") != 1
        or manifest.get("product") != "commandcore-agent"
        or manifest.get("version") != expected_version
        or manifest.get("signing_key_id") != expected_key_sha256[:16]
    ):
        _reject("invalid_signed_release_identity")

    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or not 1 <= len(artifacts) <= 2:
        _reject("invalid_artifact_list")
    expected_names = set()
    seen = set()
    version_root = feed / expected_version
    if version_root.is_symlink() or not version_root.is_dir():
        _reject("missing_version_directory")
    for item in artifacts:
        if not isinstance(item, dict):
            _reject("invalid_artifact_metadata")
        arch = item.get("architecture")
        if arch not in ARCH_BINARY or arch in seen:
            _reject("unsupported_or_duplicate_architecture")
        seen.add(arch)
        name = ARCH_BINARY[arch]
        expected_names.add(name)
        if (
            item.get("platform") != "linux"
            or item.get("kind") != "executable"
            or item.get("filename") != name
            or item.get("url") != f"{origin}/releases/agent/{expected_version}/{name}"
        ):
            _reject("unapproved_artifact_url_or_type")
        size = item.get("size")
        digest = item.get("sha256")
        if type(size) is not int or not 0 < size <= MAX_BINARY:
            _reject("invalid_artifact_size")
        if not isinstance(digest, str) or not FINGERPRINT_RE.fullmatch(digest):
            _reject("invalid_artifact_digest")
        _read_binary(version_root / name, size, digest, arch)
    if "x86_64" not in seen:
        _reject("missing_linux_x86_64")

    script = _safe_file(feed / "linux.sh", MAX_INSTALLER).decode("utf-8")
    if (
        not script.startswith("#!/bin/sh\n")
        or script.count(f"COMMANDCORE_RELEASE_PUBLIC_KEY_B64='{key_text}'") != 1
        or script.count("export COMMANDCORE_RELEASE_PUBLIC_KEY_B64") != 1
        or script.count(f"manifest='{origin}/releases/agent/manifest.json'") != 1
        or script.count(f"server={origin}\n") != 1
        or "__COMMANDCORE_" in script
    ):
        _reject("installer_pins_mismatch")
    # A staging candidate is intentionally minimal. No helper pins, executable
    # scripts other than the installer, hidden state, old releases or secrets.
    if {x.name for x in feed.iterdir()} != {
        "linux.sh",
        "manifest.json",
        expected_version,
    }:
        _reject("unexpected_root_file")
    if {x.name for x in version_root.iterdir()} != expected_names:
        _reject("unexpected_version_file")
    return {"architecture_count": len(seen), "version": expected_version}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("feed", type=Path)
    parser.add_argument("--trusted-public-key-file", type=Path, required=True)
    parser.add_argument("--expected-key-sha256", required=True)
    parser.add_argument("--expected-origin", required=True)
    parser.add_argument("--expected-version", required=True)
    args = parser.parse_args()
    try:
        result = verify(
            args.feed,
            args.trusted_public_key_file,
            args.expected_key_sha256,
            args.expected_origin,
            args.expected_version,
        )
    except (ValueError, OSError, TypeError, KeyError, UnicodeError) as error:
        # Cryptographic signature exceptions are classified below instead.
        print("PUBLIC_FEED_STAGING=REJECTED")
        print("REJECTION_TYPE=" + type(error).__name__)
        return 2
    except Exception:
        print("PUBLIC_FEED_STAGING=REJECTED")
        print("REJECTION_TYPE=signature_or_integrity_error")
        return 2
    print("PUBLIC_FEED_STAGING=OFFLINE_INTEGRITY_VERIFIED")
    print("ARCHITECTURE_COUNT=" + str(result["architecture_count"]))
    print("SIGNER_FINGERPRINT=INDEPENDENTLY_PINNED")
    print("PROVENANCE_AND_LIFECYCLE_APPROVAL=NOT_VERIFIED")
    print("PUBLICATION=NOT_PERFORMED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
