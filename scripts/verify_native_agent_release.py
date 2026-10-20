#!/usr/bin/env python3
"""Verify an externally signed native Agent release before publishing."""

import argparse
import base64
import hashlib
import json
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def verify(
    directory: Path,
    public_key_b64: str,
    version: str,
    repo: str,
    architecture: str = "x86_64",
) -> None:
    manifest = json.loads((directory / "manifest.signed.json").read_text())
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
    if architecture not in ("x86_64", "aarch64"):
        raise ValueError("unsupported_release_architecture")
    present = set()
    for artifact in assets:
        arch = artifact.get("architecture")
        if arch not in ("x86_64", "aarch64") or arch in present:
            raise ValueError("duplicate_or_unsupported_architecture")
        present.add(arch)
        filename = (
            "commandcore-agent-linux-arm64"
            if arch == "aarch64"
            else "commandcore-agent-linux-x86_64"
        )
        url = f"https://github.com/{repo}/releases/download/agent-v{version}/{filename}"
        if (
            artifact.get("platform") != "linux"
            or artifact.get("filename") != filename
            or artifact.get("url") != url
            or artifact.get("kind") != "executable"
        ):
            raise ValueError("release_target_mismatch")
        content = (directory / filename).read_bytes()
        if (
            artifact.get("size") != len(content)
            or artifact.get("sha256") != hashlib.sha256(content).hexdigest()
        ):
            raise ValueError("release_checksum_mismatch")
    if architecture not in present:
        raise ValueError("requested_architecture_missing")
    public = base64.b64decode(public_key_b64, validate=True)
    if len(public) != 32:
        raise ValueError("invalid_public_key")
    signed = json.dumps(
        {k: v for k, v in manifest.items() if k != "signature"},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()
    Ed25519PublicKey.from_public_bytes(public).verify(
        base64.b64decode(manifest["signature"], validate=True), signed
    )
    if manifest.get("signing_key_id") != hashlib.sha256(public).hexdigest()[:16]:
        raise ValueError("signing_key_id_mismatch")


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
