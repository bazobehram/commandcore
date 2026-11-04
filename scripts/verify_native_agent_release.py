#!/usr/bin/env python3
"""Verify an externally signed native Agent release before publishing.

Fail closed on linked, oversized, special, and unexpected release files.
This is not a release-signing or end-user installer acceptance step.
"""

import argparse
import base64
import hashlib
import json
import os
import stat
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

MAX_MANIFEST_SIZE = 1_048_576
MAX_BINARY_SIZE = 134_217_728
NAMES = {
    "x86_64": "commandcore-agent-linux-x86_64",
    "aarch64": "commandcore-agent-linux-arm64",
}


def _read_regular(path: Path, max_size: int) -> bytes:
    # O_NOFOLLOW and fstat guard against symlink swaps between path checks.
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= max_size:
            raise ValueError("invalid_release_file_type_or_size")
        with os.fdopen(os.dup(fd), "rb") as stream:
            content = stream.read(max_size + 1)
        if not 0 < len(content) <= max_size or len(content) != info.st_size:
            raise ValueError("release_file_changed_or_oversized")
        return content
    finally:
        os.close(fd)


def _hash_binary(path: Path, expected_size: int, expected_hash: str) -> None:
    if type(expected_size) is not int or not 0 < expected_size <= MAX_BINARY_SIZE:
        raise ValueError("invalid_release_binary_size")
    if (
        not isinstance(expected_hash, str)
        or len(expected_hash) != 64
        or any(character not in "0123456789abcdef" for character in expected_hash)
    ):
        raise ValueError("invalid_release_binary_sha256")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size != expected_size:
            raise ValueError("release_checksum_mismatch")
        digest = hashlib.sha256()
        total = 0
        with os.fdopen(os.dup(fd), "rb") as stream:
            while chunk := stream.read(1024 * 1024):
                total += len(chunk)
                if total > expected_size:
                    raise ValueError("release_binary_grew")
                digest.update(chunk)
        if total != expected_size or digest.hexdigest() != expected_hash:
            raise ValueError("release_checksum_mismatch")
    finally:
        os.close(fd)


def _unique_keys(pairs):
    data = {}
    for key, value in pairs:
        if key in data:
            raise ValueError("duplicate_release_manifest_key")
        data[key] = value
    return data


def verify(
    directory: Path,
    public_key_b64: str,
    version: str,
    repo: str,
    architecture: str = "x86_64",
) -> None:
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("invalid_release_directory")
    if architecture not in NAMES:
        raise ValueError("unsupported_release_architecture")
    manifest = json.loads(
        _read_regular(directory / "manifest.signed.json", MAX_MANIFEST_SIZE),
        object_pairs_hook=_unique_keys,
    )
    if not isinstance(manifest, dict):
        raise ValueError("invalid_release_manifest")
    if (
        manifest.get("schema_version") != 1
        or manifest.get("product") != "commandcore-agent"
    ):
        raise ValueError("invalid_manifest_identity")
    if manifest.get("version") != version:
        raise ValueError("release_version_mismatch")
    assets = manifest.get("artifacts")
    if not isinstance(assets, list) or not (1 <= len(assets) <= 2):
        raise ValueError("release_artifact_count")

    public = base64.b64decode(public_key_b64, validate=True)
    if len(public) != 32:
        raise ValueError("invalid_public_key")
    signature = base64.b64decode(manifest["signature"], validate=True)
    if len(signature) != 64:
        raise ValueError("invalid_signature")
    signed = json.dumps(
        {k: v for k, v in manifest.items() if k != "signature"},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()
    Ed25519PublicKey.from_public_bytes(public).verify(signature, signed)
    if manifest.get("signing_key_id") != hashlib.sha256(public).hexdigest()[:16]:
        raise ValueError("signing_key_id_mismatch")

    present = set()
    expected_files = {"manifest.signed.json"}
    for artifact in assets:
        if not isinstance(artifact, dict):
            raise ValueError("invalid_release_artifact")
        arch = artifact.get("architecture")
        if arch not in NAMES or arch in present:
            raise ValueError("duplicate_or_unsupported_architecture")
        present.add(arch)
        filename = NAMES[arch]
        url = f"https://github.com/{repo}/releases/download/agent-v{version}/{filename}"
        if (
            artifact.get("platform") != "linux"
            or artifact.get("filename") != filename
            or artifact.get("url") != url
            or artifact.get("kind") != "executable"
        ):
            raise ValueError("release_target_mismatch")
        expected_files.add(filename)
        _hash_binary(directory / filename, artifact.get("size"), artifact.get("sha256"))
    if architecture not in present:
        raise ValueError("requested_architecture_missing")
    if {entry.name for entry in directory.iterdir()} != expected_files:
        raise ValueError("unexpected_release_file")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    parser.add_argument("--public-key-b64", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--repo", required=True)
    parser.add_argument(
        "--architecture", choices=("x86_64", "aarch64"), default="x86_64"
    )
    a = parser.parse_args()
    verify(a.directory, a.public_key_b64, a.version, a.repo, a.architecture)
    print("SIGNED_NATIVE_RELEASE_VERIFIED")
