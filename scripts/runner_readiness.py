#!/usr/bin/env python3
"""Read-only suitability checks for a dedicated GitHub deployment runner.

This is not runner registration, enrollment, or deployment authorization.
"""

from __future__ import annotations

import argparse
import json
import grp
import os
import shutil
import subprocess
from pathlib import Path


def evaluate(
    *,
    uid: int,
    docker_access: bool,
    root: bool,
    runner_dir: Path,
    services: list[str],
    groups: set[str] | None = None,
) -> list[str]:
    blockers = []
    if uid == 0 or root:
        blockers.append("runner must not run as root")
    privileged = (groups or set()) & {"sudo", "wheel", "docker", "lxd", "adm"}
    if privileged:
        blockers.append("runner account belongs to privileged groups")
    if docker_access:
        blockers.append("runner account has direct Docker socket access")
    if any("actions.runner" in service for service in services):
        blockers.append("existing runner service must be reviewed before enrollment")
    if runner_dir.exists() and runner_dir.is_symlink():
        blockers.append("runner directory must not be a symlink")
    return blockers


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runner-dir", default="/opt/commandcore-runner")
    args = parser.parse_args()
    runner_dir = Path(args.runner_dir)
    services = subprocess.run(
        ["systemctl", "list-unit-files", "--type=service", "--no-legend"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    ).stdout.splitlines()
    socket = Path("/var/run/docker.sock")
    docker_access = os.access(socket, os.R_OK | os.W_OK)
    blockers = evaluate(
        uid=os.getuid(),
        root=os.geteuid() == 0,
        docker_access=docker_access,
        runner_dir=runner_dir,
        services=services,
        groups={grp.getgrgid(g).gr_name for g in os.getgroups()},
    )
    report = {
        "status": "blocked" if blockers else "preflight_only",
        "blockers": blockers,
        "git_available": shutil.which("git") is not None,
        "runner_directory_exists": runner_dir.exists(),
        "note": "This does not authorize installing a runner or production deployment.",
    }
    print(json.dumps(report, indent=2))
    return 1 if blockers else 0


if __name__ == "__main__":
    raise SystemExit(main())
