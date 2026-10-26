"""Inspect an already signature-verified privileged-helper bundle without extraction."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import tarfile
import zipfile
from pathlib import Path

MAX_ARCHIVE = 134_217_728
MAX_WHEEL = 64 * 1024 * 1024


def inspect_bundle(path: Path) -> dict:
    if (
        path.is_symlink()
        or not path.is_file()
        or not 0 < path.stat().st_size <= MAX_ARCHIVE
    ):
        raise ValueError("invalid helper bundle")
    with tarfile.open(path, "r:gz") as bundle:
        members = bundle.getmembers()
        if len(members) != 2 or any(not m.isfile() for m in members):
            raise ValueError("unexpected helper bundle members")
        names = [m.name for m in members]
        if "metadata.json" not in names:
            raise ValueError("helper metadata absent")
        metadata_member = next(m for m in members if m.name == "metadata.json")
        if metadata_member.size > 16_384:
            raise ValueError("oversized helper metadata")
        metadata = json.load(bundle.extractfile(metadata_member))
        if (
            not isinstance(metadata, dict)
            or metadata.get("schema_version") != 1
            or metadata.get("product") != "commandcore-privileged-helper-candidate"
            or metadata.get("unsigned") is not True
        ):
            raise ValueError("unexpected helper metadata")
        wheel_name = metadata.get("wheel_name")
        if not isinstance(wheel_name, str) or not re.fullmatch(
            r"commandcore_agent-[A-Za-z0-9_.+-]+-py3-none-any\.whl", wheel_name
        ):
            raise ValueError("invalid helper wheel name")
        if set(names) != {"metadata.json", wheel_name}:
            raise ValueError("unexpected helper bundle member name")
        wheel_member = next(m for m in members if m.name == wheel_name)
        expected_size = metadata.get("wheel_size")
        expected_hash = metadata.get("wheel_sha256")
        if (
            type(expected_size) is not int
            or not 0 < expected_size <= MAX_WHEEL
            or wheel_member.size != expected_size
        ):
            raise ValueError("invalid helper wheel size")
        if not isinstance(expected_hash, str) or not re.fullmatch(
            r"[0-9a-f]{64}", expected_hash
        ):
            raise ValueError("invalid helper wheel hash")
        wheel_bytes = bundle.extractfile(wheel_member).read(MAX_WHEEL + 1)
        if (
            len(wheel_bytes) != expected_size
            or hashlib.sha256(wheel_bytes).hexdigest() != expected_hash
        ):
            raise ValueError("helper wheel checksum mismatch")
        import io

        with zipfile.ZipFile(io.BytesIO(wheel_bytes)) as wheel:
            info = wheel.infolist()
            if not info or len(info) > 2048 or wheel.testzip() is not None:
                raise ValueError("invalid helper wheel")
            for item in info:
                components = item.filename.split("/")
                mode = (item.external_attr >> 16) & 0o170000
                if (
                    item.filename.startswith("/")
                    or "\\" in item.filename
                    or ".." in components
                    or mode == 0o120000
                ):
                    raise ValueError("unsafe helper wheel member")
            scripts = [
                i for i in info if i.filename.endswith(".dist-info/entry_points.txt")
            ]
            if len(scripts) != 1 or b"commandcore-helper" not in wheel.read(scripts[0]):
                raise ValueError("missing helper entrypoint")
    return {
        "wheel_name": wheel_name,
        "wheel_sha256": expected_hash,
        "version": metadata.get("version"),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(inspect_bundle(args.bundle), sort_keys=True))
    print(
        "Verified archive layout only; this does not authenticate signatures or install code."
    )


if __name__ == "__main__":
    main()
