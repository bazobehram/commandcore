"""Prepare an UNSIGNED Linux Agent release manifest from verified CI candidates.

Offline, fail-closed review handoff. No key generation, signing or publication.
The reviewer must still approve provenance, release version and lifecycle tests.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from urllib.parse import urlsplit

from package_unsigned_native_candidate import BINARY_NAMES, file_bytes
from package_unsigned_native_candidate import verify as verify_candidate

SHA = re.compile(r"[a-f0-9]{40}")
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?")
MAX_META = 8192
REPOSITORY = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*")


def prepare(
    candidates: dict[str, Path],
    source_sha: str,
    release_version: str,
    origin: str | None,
    output: Path,
    x86_only: bool = False,
    github_repo: str | None = None,
) -> dict:
    if not SHA.fullmatch(source_sha) or not VERSION.fullmatch(release_version):
        raise ValueError("invalid_release_identity")
    if (origin is None) == (github_repo is None):
        raise ValueError("choose_exactly_one_release_destination")
    if github_repo is not None:
        if not REPOSITORY.fullmatch(github_repo) or any(
            part in (".", "..") for part in github_repo.split("/")
        ):
            raise ValueError("invalid_github_repository")
        artifact_base = f"https://github.com/{github_repo}/releases/download/agent-v{release_version}"
    else:
        assert origin is not None
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
        artifact_base = (
            f"https://{parsed.hostname.lower()}/releases/agent/{release_version}"
        )
    expected_architectures = {"x86_64"} if x86_only else set(BINARY_NAMES)
    if set(candidates) != expected_architectures:
        raise ValueError(
            "x86_only_required" if x86_only else "both_linux_architectures_required"
        )
    if output.exists() or output.is_symlink():
        raise ValueError("output_already_exists")
    artifacts = []
    for arch in ("x86_64",) if x86_only else ("x86_64", "arm64"):
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
        if metadata["package_version"] != release_version:
            raise ValueError("candidate_release_version_mismatch")
        name = BINARY_NAMES[arch]
        artifacts.append(
            {
                "platform": "linux",
                "architecture": arch,
                "kind": "executable",
                "filename": name,
                "url": f"{artifact_base}/{name}",
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
    p.add_argument("--arm64-candidate", type=Path)
    p.add_argument(
        "--x86-only",
        action="store_true",
        help="Explicit x86_64-only unsigned review; does not approve publication",
    )
    p.add_argument("--source-sha", required=True)
    p.add_argument("--release-version", required=True)
    destination = p.add_mutually_exclusive_group(required=True)
    destination.add_argument("--origin")
    destination.add_argument(
        "--github-repo", help="Owner/repo for GitHub release assets"
    )
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    if a.x86_only == (a.arm64_candidate is not None):
        p.error("choose --x86-only OR supply --arm64-candidate")
    candidates = {"x86_64": a.x86_candidate}
    if a.arm64_candidate is not None:
        candidates["arm64"] = a.arm64_candidate
    prepare(
        candidates,
        a.source_sha,
        a.release_version,
        a.origin,
        a.output,
        x86_only=a.x86_only,
        github_repo=a.github_repo,
    )
    print("LINUX_RELEASE_MANIFEST=UNSIGNED_REVIEW_DRAFT")
    print("SIGNING_KEY_ID=NOT_ASSIGNED")
    print("SIGNATURE=NONE")
    print("LIFECYCLE_APPROVAL=NOT_VERIFIED")
    print("PUBLICATION=NOT_PERFORMED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
