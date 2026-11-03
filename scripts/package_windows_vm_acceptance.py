"""Build and verify the offline Windows M3 interactive-VM acceptance bundle.

This artifact contains harmless Task Scheduler logon/reboot probes only.
It never ships an Agent, installer, identity, enrollment key, or production URL.
"""
from __future__ import annotations

import argparse
import hashlib
import re
import stat
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

REPO = Path(__file__).resolve().parents[1]
FILES = (
    "docs/WINDOWS_INTERACTIVE_VM_ACCEPTANCE.md",
    "scripts/windows_interactive_vm_logon_acceptance.ps1",
    "scripts/windows_interactive_logon_action.ps1",
    "scripts/windows_interactive_vm_task_shape.ps1",
    "scripts/windows_interactive_vm_task_shape_probe.ps1",
    "scripts/windows_interactive_vm_proof_validation.ps1",
    "scripts/windows_interactive_vm_proof_probe.ps1",
)
SOURCE_NAME = "SOURCE_COMMIT.txt"
HASHES_NAME = "SHA256SUMS.txt"
MAX_FILE = 128 * 1024


def _zip_entry(name: str, body: bytes) -> tuple[ZipInfo, bytes]:
    info = ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
    info.compress_type = ZIP_DEFLATED
    info.external_attr = (stat.S_IFREG | 0o644) << 16
    return info, body


def build(destination: Path, source_sha: str) -> None:
    if not re.fullmatch(r"[0-9a-f]{40}", source_sha):
        raise ValueError("Exact lowercase 40-character commit SHA required")
    entries: dict[str, bytes] = {}
    for name in FILES:
        path = REPO / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_FILE:
            raise ValueError("Unsafe or missing acceptance bundle input: " + name)
        entries[name] = path.read_bytes()
    entries[SOURCE_NAME] = (source_sha + "\n").encode("ascii")
    hashes = "".join(
        hashlib.sha256(body).hexdigest() + "  " + name + "\n"
        for name, body in sorted(entries.items())
    )
    entries[HASHES_NAME] = hashes.encode("ascii")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(destination, "w") as archive:
        for name, body in sorted(entries.items()):
            info, data = _zip_entry(name, body)
            archive.writestr(info, data)
    verify(destination)


def verify(archive_path: Path) -> None:
    expected = set(FILES) | {SOURCE_NAME, HASHES_NAME}
    with ZipFile(archive_path, "r") as archive:
        infos = archive.infolist()
        names = [i.filename for i in infos]
        if len(names) != len(expected) or set(names) != expected:
            raise ValueError("Archive missing required file, contains extras, or has duplicates")
        entries: dict[str, bytes] = {}
        for info in infos:
            if info.file_size > MAX_FILE or not stat.S_ISREG(info.external_attr >> 16):
                raise ValueError("Unsafe archive entry")
            entries[info.filename] = archive.read(info)
    source_sha = entries[SOURCE_NAME].decode("ascii").strip()
    if not re.fullmatch(r"[0-9a-f]{40}", source_sha):
        raise ValueError("Invalid source commit marker")
    expected_lines = [
        hashlib.sha256(entries[name]).hexdigest() + "  " + name
        for name in sorted(expected - {HASHES_NAME})
    ]
    if entries[HASHES_NAME].decode("ascii").splitlines() != expected_lines:
        raise ValueError("Archive content hash mismatch")
    print("PASS: offline Windows VM bundle structure and content hashes verified")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--output", type=Path)
    group.add_argument("--verify", type=Path)
    parser.add_argument("--source-sha", help="Exact source commit SHA when packaging")
    args = parser.parse_args()
    if args.output:
        if not args.source_sha:
            parser.error("--source-sha is required with --output")
        build(args.output, args.source_sha)
    else:
        verify(args.verify)


if __name__ == "__main__":
    main()
