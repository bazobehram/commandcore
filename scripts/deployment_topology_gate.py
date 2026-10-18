#!/usr/bin/env python3
"""Fail closed when an intended deployment does not match the live Compose topology.

Read-only: no Docker Compose invocation, credentials, or container mutations.
"""

from __future__ import annotations

import argparse
import json
import subprocess


def validate(expected: list[str], actual: list[str]) -> list[str]:
    problems = []
    if not actual:
        problems.append("no production compose configurations found")
    if len(actual) != len(set(actual)):
        problems.append("duplicate production compose configurations")
    if expected != actual:
        problems.append(
            "compose configuration paths/order differ from approved topology"
        )
    if any(not p.startswith("/") or "\n" in p for p in actual):
        problems.append("invalid compose configuration path")

    def is_accessible(path: str) -> bool:
        try:
            with open(path, "rb") as file:
                file.read(1)
            return True
        except (OSError, ValueError):
            return False

    if any(not is_accessible(p) for p in actual):
        problems.append("one or more live compose files are missing or inaccessible")
    if any(not is_accessible(p) for p in expected):
        problems.append(
            "one or more approved compose files are missing or inaccessible"
        )
    return problems


def live_compose_files(container: str) -> list[str]:
    result = subprocess.run(
        [
            "docker",
            "inspect",
            container,
            "--format",
            '{{index .Config.Labels "com.docker.compose.project.config_files"}}',
        ],
        check=True,
        text=True,
        capture_output=True,
        timeout=10,
    )
    raw = result.stdout.strip()
    return [item for item in raw.split(",") if item and item != "<no value>"]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--container", required=True)
    ap.add_argument(
        "--approved-file",
        required=True,
        help="Local private JSON file containing compose_files array",
    )
    args = ap.parse_args()
    try:
        with open(args.approved_file, encoding="utf-8") as file:
            expected = json.load(file)["compose_files"]
        if not isinstance(expected, list) or any(
            not isinstance(x, str) for x in expected
        ):
            raise ValueError("approved compose_files must be a string array")
        actual = live_compose_files(args.container)
        problems = validate(expected, actual)
    except (
        OSError,
        ValueError,
        KeyError,
        subprocess.SubprocessError,
        json.JSONDecodeError,
    ) as exc:
        problems = [f"preflight unavailable: {type(exc).__name__}"]
    if problems:
        print("DEPLOYMENT BLOCKED: " + "; ".join(problems))
        return 1
    print(
        f"TOPOLOGY PASS: {len(expected)} approved compose overlays match live configuration"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
