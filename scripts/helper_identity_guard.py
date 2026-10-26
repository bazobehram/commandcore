"""Read-only identity guard for isolated privileged-helper installation.

This does not install, elevate, restart services, or access secret contents.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


def inspect_agent(home: Path, username: str) -> dict:
    if sys.platform != "linux":
        raise ValueError("Linux only")
    if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", username):
        raise ValueError("invalid agent username")
    if home.is_symlink() or not home.is_dir():
        raise ValueError("invalid home directory")
    agent_root = home / ".local/share/commandcore-agent"
    current = agent_root / "current"
    state = agent_root / "state"
    # A helper installer must never mutate either the user-owned runtime or state.
    protected = [
        home / ".config/systemd/user/commandcore-agent.service",
        current,
        state,
    ]
    present = [str(p) for p in protected if p.exists() or p.is_symlink()]
    local_agent = home / ".local/bin/commandcore-agent"
    if not local_agent.exists() and not local_agent.is_symlink():
        raise ValueError("existing user Agent not found; helper-only upgrade refused")
    if not any(
        p.exists() or p.is_symlink() for p in (current, agent_root / "releases")
    ):
        raise ValueError("existing release layout absent; refusing blind migration")
    return {
        "existing_agent": True,
        "agent_username": username,
        "protected_paths": present,
        "agent_launcher": str(local_agent),
        "install_scope": "root-owned helper runtime only",
        "agent_replacement_allowed": False,
        "reenrollment_allowed": False,
        "service_restart_allowed": False,
        "requires_local_root_consent": True,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--home", required=True, type=Path)
    parser.add_argument("--username", required=True)
    args = parser.parse_args()
    print(json.dumps(inspect_agent(args.home, args.username), sort_keys=True))
    print("READ ONLY: Device identity and Agent service were not changed.")


if __name__ == "__main__":
    main()
