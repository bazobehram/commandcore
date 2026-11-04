#!/usr/bin/env python3
"""Prepare an UNSIGNED Linux Agent release manifest from verified CI candidates.

Offline, fail-closed review handoff. No key generation, signing or publication.
The reviewer must still approve provenance, release version and lifecycle tests.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from urllib.parse import urlsplit

from package_unsigned_native_candidate import (
    BINARY_NAMES,
    file_bytes,
    verify as verify_candidate,
)

SHA = re.compile(r"[a-f0-9]{40}")
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?")
MAX_META = 8192


def prepare(
    candidates: dict[str, Path],
    source_sha: str,
    release_version: str,
    origin: str,
    output: Path,
) -> dict:
    if not SHA.fullmatch(source_sha) or not VERSION.fullmatch(release_version):
        raise ValueError("invalid_release_identity")
    parsed = urlsplit(origin)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
        or parsed.port not in (None, 443)
        or any(ord(c) <= 32 or ord(c) == 127 for c in origin)
    ):
        raise ValueError("invalid_release_origin")
    if set(candidates) != set(BINARY_NAMES):
        raise ValueError("both_linux_architectures_required")
    if output.exists() or output.is_symlink():
        raise ValueError("output_already_exists")
    origin = "https://" + parsed.hostname.lower()
    artifacts = []
    for arch in ("x86_64", "arm64"):
        folder = candidates[arch]
        verify_candidate(folder, source_sha, arch)
        raw = file_bytes(folder / "UNSIGNED_BUILD_METADATA.json", MAX_META)
        metadata = json.loads(raw)
        if (
            metadata["architecture"] != arch
            or metadata["source_commit"] != source_sha
            or metadata["release_status"] != "UNSIGNED_NOT_APPROVED"
            or metadata["signatures"] != "NONE"
        ):
            raise ValueError("unapproved_candidate")
        name = BINARY_NAMES[arch]
        artifacts.append(
            {
                "platform": "linux",
                "architecture": arch,
                "kind": "executable",
                "filename": name,
                "url": f"{origin}/releases/agent/{release_version}/{name}",
                "size": metadata["size"],
                "sha256": metadata["sha256"],
            }
        )
    manifest = {
        "schema_version": 1,
        "product": "commandcore-agent",
        "version": release_version,
        "artifacts": artifacts,
    }
    # A signer must add signing_key_id from an independently trusted public key
    # and attach an offline Ed25519 signature. Never infer key identity here.
    output.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
    return manifest


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--x86-candidate", type=Path, required=True)
    p.add_argument("--arm64-candidate", type=Path, required=True)
    p.add_argument("--source-sha", required=True)
    p.add_argument("--release-version", required=True)
    p.add_argument("--origin", required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    prepare(
        {"x86_64": a.x86_candidate, "arm64": a.arm64_candidate},
        a.source_sha,
        a.release_version,
        a.origin,
        a.output,
    )
    print("LINUX_RELEASE_MANIFEST=UNSIGNED_REVIEW_DRAFT")
    print("SIGNING_KEY_ID=NOT_ASSIGNED")
    print("SIGNATURE=NONE")
    print("LIFECYCLE_APPROVAL=NOT_VERIFIED")
    print("PUBLICATION=NOT_PERFORMED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
