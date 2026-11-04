#!/usr/bin/env python3
"""Make/verify an unsigned, source-pinned Linux native Agent review bundle.

No signing keys or network operations. Does NOT approve installation or release.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import stat
import struct
import subprocess
from pathlib import Path

BINARY_NAMES = {"x86_64": "commandcore-agent-linux-x86_64", "arm64": "commandcore-agent-linux-arm64"}
BINARY_NAME = BINARY_NAMES["x86_64"]  # compatibility for existing x64 consumers
MANIFEST_NAME = "UNSIGNED_BUILD_METADATA.json"
SOURCE_NAME = "SOURCE_COMMIT.txt"
HASH_NAME = "SHA256SUMS.txt"
MAX_BINARY_SIZE = 134_217_728
SHA256_RE = re.compile(r"[a-f0-9]{64}")
COMMIT_RE = re.compile(r"[a-f0-9]{40}")
VERSION_RE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?")
GLIBC_RE = re.compile(r"GLIBC_([0-9]+)\.([0-9]+)")


def file_bytes(path: Path, max_size: int) -> bytes:
    if path.is_symlink():
        raise ValueError("candidate_symlink")
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= max_size:
        raise ValueError("candidate_file_type_or_size")
    return path.read_bytes()


def elf_linux(raw: bytes, architecture: str = "x86_64") -> None:
    if architecture not in BINARY_NAMES:
        raise ValueError("unsupported_candidate_architecture")
    if (
        len(raw) < 64
        or raw[:4] != b"\x7fELF"
        or raw[4] != 2  # ELFCLASS64
        or raw[5] != 1  # little endian
        or raw[6] != 1  # ELF current version
        or struct.unpack_from("<H", raw, 16)[0] != 3  # ET_DYN (PIE)
        or struct.unpack_from("<H", raw, 18)[0] != (62 if architecture == "x86_64" else 183)
    ):
        raise ValueError("not_linux_expected_architecture_pie_elf")


def elf_linux_amd64(raw: bytes) -> None:
    """Legacy public validator for x86_64 fixtures."""
    elf_linux(raw, "x86_64")


def glibc_max_required(binary: Path) -> tuple[int, int]:
    result = subprocess.run(
        ["readelf", "--version-info", str(binary)],
        capture_output=True,
        text=True,
        check=True,
        timeout=15,
    )
    found = {(int(a), int(b)) for a, b in GLIBC_RE.findall(result.stdout)}
    if not found:
        raise ValueError("missing_glibc_symbol_evidence")
    maximum = max(found)
    # Installer promises glibc 2.36+, so build on Ubuntu 22.04 and enforce
    # runtime symbol compatibility rather than assuming newer runner ABIs.
    if maximum > (2, 36):
        raise ValueError("glibc_requirement_exceeds_2_36")
    return maximum


def prepare(
    binary: Path,
    output: Path,
    source_sha: str,
    version: str,
    cargo_lock: Path,
    rustc_version: str,
    cargo_version: str,
    architecture: str = "x86_64",
) -> None:
    if architecture not in BINARY_NAMES:
        raise ValueError("unsupported_candidate_architecture")
    binary_name = BINARY_NAMES[architecture]
    if not COMMIT_RE.fullmatch(source_sha) or not VERSION_RE.fullmatch(version):
        raise ValueError("invalid_build_identity")
    if output.exists() or output.is_symlink():
        raise ValueError("refuse_existing_output")
    raw = file_bytes(binary, MAX_BINARY_SIZE)
    elf_linux(raw, architecture)
    glibc_max = glibc_max_required(binary)
    lock = file_bytes(cargo_lock, 10 * 1024 * 1024)
    metadata = {
        "schema_version": 1,
        "kind": "commandcore-unsigned-native-agent-review-candidate",
        "release_status": "UNSIGNED_NOT_APPROVED",
        "source_commit": source_sha,
        "package_version": version,
        "platform": "linux",
        "architecture": architecture,
        "filename": binary_name,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size": len(raw),
        "cargo_lock_sha256": hashlib.sha256(lock).hexdigest(),
        "max_required_glibc": f"{glibc_max[0]}.{glibc_max[1]}",
        "rustc": rustc_version,
        "cargo": cargo_version,
        "provenance": "CI_BUILD_RECORD_NOT_INDEPENDENT_ATTESTATION",
        "signatures": "NONE",
        "device_lifecycle": "NOT_VERIFIED",
    }
    output.mkdir(parents=True)
    shutil.copyfile(binary, output / binary_name)
    (output / MANIFEST_NAME).write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (output / SOURCE_NAME).write_text(source_sha + "\n", encoding="ascii")
    entries = [binary_name, MANIFEST_NAME, SOURCE_NAME]
    (output / HASH_NAME).write_text(
        "".join(
            f"{hashlib.sha256((output / name).read_bytes()).hexdigest()}  {name}\n"
            for name in entries
        ),
        encoding="ascii",
    )


def verify(directory: Path, source_sha: str, architecture: str = "x86_64") -> None:
    if architecture not in BINARY_NAMES:
        raise ValueError("unsupported_candidate_architecture")
    binary_name = BINARY_NAMES[architecture]
    if not COMMIT_RE.fullmatch(source_sha):
        raise ValueError("invalid_source_sha")
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("invalid_candidate_directory")
    if {item.name for item in directory.iterdir()} != {
        binary_name,
        MANIFEST_NAME,
        SOURCE_NAME,
        HASH_NAME,
    }:
        raise ValueError("unexpected_candidate_file")
    raw = file_bytes(directory / binary_name, MAX_BINARY_SIZE)
    elf_linux(raw, architecture)
    manifest_bytes = file_bytes(directory / MANIFEST_NAME, 8_192)
    marker = file_bytes(directory / SOURCE_NAME, 128)
    hash_file = file_bytes(directory / HASH_NAME, 1024)
    data = json.loads(manifest_bytes)
    if (
        not isinstance(data, dict)
        or set(data)
        != {
            "schema_version",
            "kind",
            "release_status",
            "source_commit",
            "package_version",
            "platform",
            "architecture",
            "filename",
            "sha256",
            "size",
            "cargo_lock_sha256",
            "max_required_glibc",
            "rustc",
            "cargo",
            "provenance",
            "signatures",
            "device_lifecycle",
        }
        or data["schema_version"] != 1
        or data["kind"] != "commandcore-unsigned-native-agent-review-candidate"
        or data["release_status"] != "UNSIGNED_NOT_APPROVED"
        or data["source_commit"] != source_sha
        or marker != (source_sha + "\n").encode("ascii")
        or data["platform"] != "linux"
        or data["architecture"] != architecture
        or data["filename"] != binary_name
        or data["size"] != len(raw)
        or data["sha256"] != hashlib.sha256(raw).hexdigest()
        or not SHA256_RE.fullmatch(data["cargo_lock_sha256"])
        or not VERSION_RE.fullmatch(data["package_version"])
        or data["provenance"] != "CI_BUILD_RECORD_NOT_INDEPENDENT_ATTESTATION"
        or data["signatures"] != "NONE"
        or data["device_lifecycle"] != "NOT_VERIFIED"
    ):
        raise ValueError("invalid_candidate_metadata")
    expected_hashes = "".join(
        f"{hashlib.sha256((directory / name).read_bytes()).hexdigest()}  {name}\n"
        for name in [binary_name, MANIFEST_NAME, SOURCE_NAME]
    ).encode("ascii")
    if hash_file != expected_hashes:
        raise ValueError("candidate_hash_manifest_mismatch")
    # The checksum covers metadata, but does not prove its glibc claim is true.
    # Re-read the ELF version requirements during independent review.
    required_glibc = glibc_max_required(directory / binary_name)
    if data["max_required_glibc"] != f"{required_glibc[0]}.{required_glibc[1]}":
        raise ValueError("candidate_glibc_evidence_mismatch")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "verify"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--architecture", choices=tuple(BINARY_NAMES), default="x86_64")
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--version")
    parser.add_argument("--cargo-lock", type=Path)
    parser.add_argument("--rustc-version", default="")
    parser.add_argument("--cargo-version", default="")
    args = parser.parse_args()
    if args.action == "prepare":
        if args.binary is None or args.version is None or args.cargo_lock is None:
            parser.error("prepare requires binary, version and cargo-lock")
        prepare(
            args.binary,
            args.output,
            args.source_sha,
            args.version,
            args.cargo_lock,
            args.rustc_version,
            args.cargo_version,
            args.architecture,
        )
    else:
        verify(args.output, args.source_sha, args.architecture)
    print("UNSIGNED_NATIVE_CANDIDATE=INTEGRITY_VERIFIED")
    print("SIGNATURES=NONE")
    print("SOURCE_PROVENANCE=CI_RECORD_ONLY")
    print("LIFECYCLE_APPROVAL=NOT_VERIFIED")
    print("PUBLICATION=NOT_PERFORMED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
