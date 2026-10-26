"""Verify every wheel in an offline helper wheelhouse against a signed inventory.

This check is read-only and does not authorize root execution.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path


def validate(root: Path, inventory: Path) -> dict:
    if root.is_symlink() or not root.is_dir():
        raise ValueError("invalid wheelhouse")
    manifest = json.loads(inventory.read_text())
    if (
        manifest.get("schema_version") != 1
        or manifest.get("product") != "commandcore-helper-wheelhouse"
    ):
        raise ValueError("wrong wheelhouse inventory")
    entries = manifest.get("wheels")
    if not isinstance(entries, list) or not 1 <= len(entries) <= 128:
        raise ValueError("invalid wheel inventory")
    expected = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("invalid wheel entry")
        name, digest, size = entry.get("name"), entry.get("sha256"), entry.get("size")
        if not isinstance(name, str) or not re.fullmatch(
            r"[A-Za-z0-9_.+-]+\.whl", name
        ):
            raise ValueError("unsafe wheel name")
        if (
            name in expected
            or not isinstance(digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
        ):
            raise ValueError("duplicate wheel or invalid checksum")
        if type(size) is not int or not 0 < size <= 64 * 1024 * 1024:
            raise ValueError("invalid wheel size")
        expected[name] = (digest, size)
    actual = {p.name for p in root.iterdir()}
    if actual != set(expected):
        raise ValueError("wheelhouse missing or unexpected files")
    for name, (digest, size) in expected.items():
        p = root / name
        if p.is_symlink() or not p.is_file() or p.stat().st_size != size:
            raise ValueError("unsafe wheel path or size")
        if hashlib.sha256(p.read_bytes()).hexdigest() != digest:
            raise ValueError("wheel checksum mismatch")
    return {
        "verified": True,
        "wheel_count": len(expected),
        "requires_signed_parent_manifest": True,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--wheelhouse", required=True, type=Path)
    parser.add_argument("--inventory", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(validate(args.wheelhouse, args.inventory), sort_keys=True))


if __name__ == "__main__":
    main()
