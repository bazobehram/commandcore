#!/usr/bin/env python3
"""Verify downloaded CI release artifact before any production deployment.

Only validates the candidate package; never extracts, executes or deploys it.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
import zipfile
from pathlib import Path


def verify(
    archive: Path, checksum_file: Path, manifest_file: Path, expected_sha: str
) -> None:
    if not re.fullmatch(r"[0-9a-f]{40}", expected_sha):
        raise ValueError("expected Git SHA must be a full lowercase 40-character SHA-1")
    manifest = dict(
        line.split("=", 1)
        for line in manifest_file.read_text().splitlines()
        if "=" in line
    )
    if manifest.get("git_sha") != expected_sha:
        raise ValueError("Git SHA mismatch")
    if not re.fullmatch(r"[0-9a-f]{64}", manifest.get("mcp_contract_sha256", "")):
        raise ValueError("missing or invalid MCP contract checksum")
    expected_line = checksum_file.read_text().strip()
    match = re.fullmatch(r"([0-9a-f]{64})  commandcore-release.zip", expected_line)
    if match is None:
        raise ValueError("invalid checksum format")
    if archive.name != "commandcore-release.zip":
        raise ValueError("unexpected archive name")
    if hashlib.sha256(archive.read_bytes()).hexdigest() != match.group(1):
        raise ValueError("release archive digest mismatch")
    with zipfile.ZipFile(archive) as zf:
        if zf.testzip() is not None:
            raise ValueError("corrupted release ZIP")
        contract = zf.read("commandcore-release/docs/mcp-tool-contract.json")
        if hashlib.sha256(contract).hexdigest() != manifest["mcp_contract_sha256"]:
            raise ValueError("embedded MCP contract digest mismatch")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--checksum", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--expected-git-sha", required=True)
    args = parser.parse_args()
    try:
        verify(args.archive, args.checksum, args.manifest, args.expected_git_sha)
    except (OSError, ValueError, zipfile.BadZipFile, KeyError) as exc:
        print(f"ARTIFACT REJECTED: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    print("ARTIFACT VERIFIED: archive, Git SHA and MCP contract match")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
