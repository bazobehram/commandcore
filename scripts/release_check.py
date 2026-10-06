#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import sys
import zipfile
from pathlib import PurePosixPath

FORBIDDEN_DIRS = {
    ".git",
    "__pycache__",
    ".pytest_cache",
    ".venv",
    "venv",
    "target",
    ".ruff_cache",
}
FORBIDDEN_NAMES = {
    ".env",
    "agent.json",
    "agent-state.json",
    "enrollment.pending.json",
    "helper.key",
    "commandcore.sqlite3",
}
FORBIDDEN_SUFFIXES = {".pyc", ".pyo", ".sqlite3", ".db"}
SECRET_PATTERNS = (
    (
        re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        "private key block",
    ),
    (re.compile(rb"\bsk-[A-Za-z0-9_-]{20,}"), "OpenAI-style secret key"),
    (re.compile(rb"\bghp_[A-Za-z0-9]{30,}"), "GitHub personal access token"),
)


def bad_entry(name: str) -> str | None:
    p = PurePosixPath(name)
    parts = set(p.parts)
    if parts & FORBIDDEN_DIRS:
        return f"forbidden directory: {parts & FORBIDDEN_DIRS}"
    if p.name in FORBIDDEN_NAMES:
        return f"forbidden state/secret filename: {p.name}"
    if p.name.startswith(".env.") and p.name != ".env.example":
        return f"forbidden dotenv secret filename: {p.name}"
    if p.suffix in FORBIDDEN_SUFFIXES:
        return f"forbidden generated/state suffix: {p.suffix}"
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("zip_path")
    args = ap.parse_args()
    problems: list[str] = []
    try:
        with zipfile.ZipFile(args.zip_path) as zf:
            broken = zf.testzip()
            if broken:
                problems.append(f"corrupt entry: {broken}")
            for info in zf.infolist():
                reason = bad_entry(info.filename)
                if reason:
                    problems.append(f"{info.filename}: {reason}")
                    continue
                if info.is_dir() or info.file_size > 2 * 1024 * 1024:
                    continue
                data = zf.read(info)
                for pattern, label in SECRET_PATTERNS:
                    if pattern.search(data):
                        problems.append(f"{info.filename}: suspected {label}")
    except Exception as exc:
        print(f"RELEASE_CHECK FAIL: {exc}", file=sys.stderr)
        return 2
    if problems:
        print("RELEASE_CHECK FAIL", file=sys.stderr)
        for problem in problems:
            print(f"- {problem}", file=sys.stderr)
        return 1
    print("RELEASE_CHECK PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
