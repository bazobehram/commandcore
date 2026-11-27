"""Package a single reviewed Angular build for both release targets."""

import argparse
import hashlib
import json
import re
import zipfile
from pathlib import Path

MAX_BYTES = 64 * 1024 * 1024
MAX_FILES = 1024


def package(root: Path, output: Path, commit: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("invalid source commit")
    if root.is_symlink() or not root.is_dir():
        raise ValueError("invalid workspace directory")
    root = root.resolve()
    if output.resolve().is_relative_to(root):
        raise ValueError("output must be outside workspace")
    files = {}
    total = 0
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError("workspace symlinks are not supported")
        rel = path.relative_to(root).as_posix()
        if any(
            not re.fullmatch(r"[A-Za-z0-9_-][A-Za-z0-9._-]*", part)
            for part in rel.split("/")
        ):
            raise ValueError("invalid workspace path")
        if path.is_dir():
            continue
        if not path.is_file() or path.suffix == ".map":
            raise ValueError("unexpected workspace asset")
        total += path.stat().st_size
        if total > MAX_BYTES or len(files) >= MAX_FILES:
            raise ValueError("workspace exceeds release bounds")
        files[rel] = path.read_bytes()
    if not files.get("index.html") or not any(
        re.fullmatch(r"main-[A-Za-z0-9]+\.js", name) and data
        for name, data in files.items()
    ):
        raise ValueError("workspace index or main bundle missing")
    metadata = {
        "schema": 1,
        "source_commit": commit,
        "files": {
            name: hashlib.sha256(data).hexdigest() for name, data in files.items()
        },
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "x", compression=zipfile.ZIP_DEFLATED) as archive:

        def add(name, data):
            entry = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            entry.external_attr = 0o100644 << 16
            archive.writestr(entry, data, compress_type=zipfile.ZIP_DEFLATED)

        add("WORKSPACE_RELEASE.json", json.dumps(metadata, sort_keys=True).encode())
        for name, data in files.items():
            add("browser/" + name, data)
    return hashlib.sha256(output.read_bytes()).hexdigest()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--commit", required=True)
    args = parser.parse_args()
    print(package(args.root, args.output, args.commit))
