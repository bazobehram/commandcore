"""Verify an offline privileged-helper artifact without extracting or executing it."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

MAX_MANIFEST = 1_048_576
MAX_HELPER = 134_217_728


def verify(
    manifest_path: Path, artifact_path: Path, public_key_b64: str, *, architecture: str
) -> dict:
    raw = manifest_path.read_bytes()
    if not 0 < len(raw) <= MAX_MANIFEST:
        raise ValueError("manifest size invalid")
    document = json.loads(raw)
    if not isinstance(document, dict):
        raise ValueError("manifest must be an object")
    signature = base64.b64decode(document.get("signature", ""), validate=True)
    key = base64.b64decode(public_key_b64, validate=True)
    if len(key) != 32 or len(signature) != 64:
        raise ValueError("invalid signing key or signature")
    canonical = json.dumps(
        {k: v for k, v in document.items() if k != "signature"},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    Ed25519PublicKey.from_public_bytes(key).verify(signature, canonical)
    if (
        document.get("schema_version") != 1
        or document.get("product") != "commandcore-agent"
    ):
        raise ValueError("unexpected signed release product")
    artifacts = document.get("artifacts")
    if not isinstance(artifacts, list):
        raise ValueError("artifact list missing")
    matches = [
        a
        for a in artifacts
        if isinstance(a, dict)
        and a.get("platform") == "linux"
        and a.get("architecture") == architecture
        and a.get("kind") == "privileged-helper"
    ]
    if len(matches) != 1:
        raise ValueError("exactly one signed privileged-helper artifact is required")
    entry = matches[0]
    expected_size = entry.get("size")
    expected_hash = entry.get("sha256")
    if type(expected_size) is not int or not 0 < expected_size <= MAX_HELPER:
        raise ValueError("invalid artifact size")
    if (
        not isinstance(expected_hash, str)
        or re.fullmatch(r"[a-f0-9]{64}", expected_hash) is None
    ):
        raise ValueError("invalid artifact checksum")
    if (
        artifact_path.is_symlink()
        or not artifact_path.is_file()
        or artifact_path.stat().st_size != expected_size
    ):
        raise ValueError("artifact path or size invalid")
    digest = hashlib.sha256()
    with artifact_path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    if digest.hexdigest() != expected_hash:
        raise ValueError("artifact digest mismatch")
    return {
        "version": document.get("version"),
        "architecture": architecture,
        "sha256": expected_hash,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--trusted-public-key-b64", required=True)
    parser.add_argument("--architecture", choices=("x86_64", "arm64"), required=True)
    args = parser.parse_args()
    result = verify(
        args.manifest,
        args.artifact,
        args.trusted_public_key_b64,
        architecture=args.architecture,
    )
    print("VERIFIED SIGNED HELPER", json.dumps(result, sort_keys=True))
    print("This check does not install or execute privileged code.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
