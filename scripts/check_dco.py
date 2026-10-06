#!/usr/bin/env python3
"""Verify Developer Certificate of Origin sign-off for a commit range."""

from __future__ import annotations

import argparse
import re
import subprocess

SIGNOFF = re.compile(r"^Signed-off-by:\s+.+\s+<[^<>\s]+@[^<>\s]+>\s*$", re.MULTILINE)


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], text=True).strip()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--base", help="Base ref/commit. Defaults to the parent of HEAD."
    )
    args = parser.parse_args()

    if args.base:
        base = git("merge-base", "HEAD", args.base)
        rev_range = f"{base}..HEAD"
        commits = [c for c in git("rev-list", "--reverse", rev_range).splitlines() if c]
    else:
        head_with_parents = git("rev-list", "--parents", "-n", "1", "HEAD").split()
        if len(head_with_parents) == 1:
            commits = [head_with_parents[0]]
        else:
            rev_range = f"{head_with_parents[1]}..HEAD"
            commits = [
                c for c in git("rev-list", "--reverse", rev_range).splitlines() if c
            ]
    failures: list[str] = []

    for commit in commits:
        message = git("show", "-s", "--format=%B", commit)
        if not SIGNOFF.search(message):
            subject = git("show", "-s", "--format=%s", commit)
            failures.append(f"{commit[:12]} {subject}")

    if failures:
        print("Missing DCO Signed-off-by trailer:")
        for failure in failures:
            print(f"  - {failure}")
        print("Use: git commit -s")
        return 1

    print(f"DCO check passed for {len(commits)} commit(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
