"""Stage deterministic unsigned helper candidate; never install or sign it."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import re
import tarfile
import zipfile
from pathlib import Path

MAX_WHEEL = 64 * 1024 * 1024


def build(wheel: Path, output: Path, *, version: str) -> dict:
    if not re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z.+-]{0,63}", version):
        raise ValueError("invalid version")
    if (
        wheel.is_symlink()
        or not wheel.is_file()
        or not wheel.name.startswith("commandcore_agent-")
        or wheel.suffix != ".whl"
    ):
        raise ValueError("only a regular CommandCore Agent wheel is accepted")
    size = wheel.stat().st_size
    if not 0 < size <= MAX_WHEEL:
        raise ValueError("wheel size invalid")
    with zipfile.ZipFile(wheel) as package:
        entries = package.infolist()
        if package.testzip() is not None or not entries:
            raise ValueError("corrupt wheel")
        for item in entries:
            parts = item.filename.split("/")
            if (
                item.filename.startswith("/")
                or "\\" in item.filename
                or any(part in ("", ".", "..") for part in parts[:-1])
                or ((item.external_attr >> 16) & 0o170000) == 0o120000
            ):
                raise ValueError("unsafe wheel entry")
        scripts = [
            name
            for name in package.namelist()
            if name.endswith(".dist-info/entry_points.txt")
        ]
        if (
            len(scripts) != 1
            or "commandcore-helper" not in package.read(scripts[0]).decode()
        ):
            raise ValueError("helper entry point missing")
    data = wheel.read_bytes()
    metadata = {
        "schema_version": 1,
        "product": "commandcore-privileged-helper-candidate",
        "version": version,
        "wheel_name": wheel.name,
        "wheel_sha256": hashlib.sha256(data).hexdigest(),
        "wheel_size": len(data),
        "unsigned": True,
    }
    payload = json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode()
    if output.exists():
        raise FileExistsError("refusing to overwrite helper candidate")
    output.parent.mkdir(parents=True, exist_ok=True)
    with (
        output.open("wb") as stream,
        gzip.GzipFile(fileobj=stream, mode="wb", filename="", mtime=0) as compressed,
        tarfile.open(
            fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT
        ) as archive,
    ):
        for name, content in (("metadata.json", payload), (wheel.name, data)):
            entry = tarfile.TarInfo(name)
            entry.size = len(content)
            entry.mtime = 0
            entry.mode = 0o644
            entry.uid = entry.gid = 0
            entry.uname = entry.gname = ""
            archive.addfile(entry, io.BytesIO(content))
    return metadata


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--wheel", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    result = build(args.wheel, args.output, version=args.version)
    print(json.dumps(result, sort_keys=True))
    print("UNSIGNED CANDIDATE ONLY. Do not install as root.")


if __name__ == "__main__":
    main()
