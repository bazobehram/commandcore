#!/usr/bin/env python3
"""Read-only audit of live CommandCore application-code bind mounts.

This checks source overlays, NOT image provenance or full behavioral parity.
No data volumes, secret files, command outputs or user records are inspected.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import subprocess
from typing import Any

APP_TARGETS = (
    ("/site-packages/commandcore_server/", "apps/server/commandcore_server"),
    ("/share/commandcore/web/", "apps/web"),
)


def app_relative_path(target: str) -> Path | None:
    """Map an installed application-code target to a source-relative file."""
    if not isinstance(target, str):
        return None
    for marker, source_dir in APP_TARGETS:
        if marker not in target:
            continue
        relative = target.split(marker, 1)[1]
        parts = PurePosixPath(relative).parts
        if not parts or any(part in (".", "..") for part in parts):
            raise ValueError("invalid application code mount target")
        return Path(source_dir, *parts)
    return None


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(128 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def classify_overrides(
    mounts: list[dict[str, Any]], source_root: Path
) -> list[dict[str, str]]:
    """Return non-sensitive source-overlay findings, without host paths."""
    findings: list[dict[str, str]] = []
    for mount in mounts:
        if mount.get("Type") != "bind":
            continue
        target = mount.get("Destination", "")
        relative = app_relative_path(target)
        if relative is None:
            continue
        source = mount.get("Source")
        if not isinstance(source, str) or not source:
            status = "missing_override_file"
        else:
            override = Path(source)
            expected = source_root / relative
            if not override.is_file():
                status = "missing_override_file"
            elif not expected.is_file():
                status = "not_in_source"
            elif sha256_file(override) == sha256_file(expected):
                status = "matches_source"
            else:
                status = "differs_from_source"
        findings.append(
            {
                "target": str(relative).replace("\\", "/"),
                "status": status,
            }
        )
    return sorted(findings, key=lambda item: item["target"])


def inspect_mounts(container: str) -> list[dict[str, Any]]:
    result = subprocess.run(
        ["docker", "inspect", container],
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    )
    inspected = json.loads(result.stdout)
    if len(inspected) != 1 or not isinstance(inspected[0].get("Mounts"), list):
        raise ValueError("invalid container inspection result")
    return inspected[0]["Mounts"]


def audit(container: str, source_root: Path, strict: bool) -> tuple[dict, bool]:
    if not (source_root / "apps/server/commandcore_server").is_dir():
        raise ValueError("source_root is not a CommandCore repository checkout")
    findings = classify_overrides(inspect_mounts(container), source_root)
    differing = sum(finding["status"] != "matches_source" for finding in findings)
    blocked = differing > 0 or (strict and bool(findings))
    report = {
        "container": container,
        "code_override_count": len(findings),
        "nonmatching_override_count": differing,
        "immutable_code_gate": "BLOCK" if blocked else "PASS",
        "strict": strict,
        "overrides": findings,
        "note": (
            "A PASS only checks source bind mounts; image identity, signing, "
            "environment, database migrations and runtime tests require separate gates."
        ),
    }
    return report, blocked


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--container", required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument(
        "--strict",
        action="store_true",
        help="block every application-code bind mount, even if source bytes match",
    )
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args()
    try:
        report, blocked = audit(args.container, args.source_root, args.strict)
    except (
        OSError,
        ValueError,
        json.JSONDecodeError,
        subprocess.SubprocessError,
    ) as exc:
        print("OVERLAY AUDIT BLOCKED: " + type(exc).__name__)
        return 2
    if args.json:
        print(json.dumps(report, sort_keys=True))
    else:
        print(
            "OVERLAY "
            + ("BLOCKED" if blocked else "PASS")
            + ": code binds="
            + str(report["code_override_count"])
            + ", nonmatching="
            + str(report["nonmatching_override_count"])
            + ", strict="
            + str(args.strict)
        )
        for finding in report["overrides"]:
            print(f"  {finding['status']}: {finding['target']}")
    return 1 if blocked else 0


if __name__ == "__main__":
    raise SystemExit(main())
