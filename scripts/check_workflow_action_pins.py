#!/usr/bin/env python3
"""Require immutable full-SHA references for third-party workflow actions."""

from __future__ import annotations

import re
from pathlib import Path

WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"
USES = re.compile(r"^\s*(?:-\s*)?uses:\s*(?P<ref>[^\s#]+)")
PIN = re.compile(r"^[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+(?:/[a-zA-Z0-9_.-]+)*@[0-9a-f]{40}$")


def scan_workflows(directory: Path) -> list[str]:
    errors: list[str] = []
    paths = sorted((*directory.glob("*.yml"), *directory.glob("*.yaml")))
    if not paths:
        return [f"{directory}: no workflow YAML files found"]
    for path in paths:
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            match = USES.match(line)
            if not match:
                continue
            ref = match.group("ref")
            if ref.startswith("./"):
                continue  # local repository action: reviewed as source
            if not PIN.fullmatch(ref):
                errors.append(f"{path.name}:{lineno}: action must use a full commit SHA: {ref}")
    return errors


if __name__ == "__main__":
    problems = scan_workflows(WORKFLOWS)
    if problems:
        print("Workflow action pin check FAILED:")
        for problem in problems:
            print(f"  - {problem}")
        raise SystemExit(1)
    print("Workflow action pin check passed.")
