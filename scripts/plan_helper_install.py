"""Generate a fail-closed, read-only helper installation plan for local review.

Never starts, elevates, replaces or reenrolls the Agent. A separate audited
root installer is required to execute a plan after explicit local consent.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path


def load(filename: str):
    path = Path(__file__).resolve().with_name(filename)
    spec = importlib.util.spec_from_file_location(path.stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def plan(
    manifest: Path,
    bundle: Path,
    key: str,
    *,
    version: str,
    arch: str,
    home: Path,
    username: str,
    install_root: Path,
) -> dict:
    if install_root != Path("/opt/commandcore-agent/helper"):
        raise ValueError("noncanonical root helper path rejected")
    safety = load("helper_identity_guard.py").inspect_agent(home, username)
    verified = load("helper_install_preflight.py").verify_inputs(
        manifest, bundle, key, architecture=arch, expected_version=version
    )
    if verified["result"] != "VERIFIED_NOT_INSTALLED":
        raise ValueError("signed helper verification required")
    return {
        "state": "AWAITING_LOCAL_ROOT_APPROVAL",
        "verified_version": version,
        "archive_sha256": verified["bundle_sha256"],
        "wheel_sha256": verified["wheel_sha256"],
        "root_target": str(install_root),
        "agent_launcher": safety["agent_launcher"],
        "protected_agent_paths": safety["protected_paths"],
        "planned_operations": [
            "Reverify signed package from root-owned staging before use",
            "Stage versioned root-owned helper runtime separately from Agent",
            "Validate installed files, ownership, permissions and entrypoint",
            "Atomically activate helper service only after local typed consent",
            "On failure disable helper, restore previous helper runtime and ceiling",
            "Verify existing Agent identity and user-level service unchanged",
        ],
        "requires_local_approval": True,
        "root_operation_executed": False,
        "agent_reenrolled": False,
        "agent_replaced": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--trusted-public-key-b64", required=True)
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--architecture", choices=("x86_64", "arm64"), required=True)
    parser.add_argument("--agent-home", required=True, type=Path)
    parser.add_argument("--agent-user", required=True)
    args = parser.parse_args()
    result = plan(
        args.manifest,
        args.bundle,
        args.trusted_public_key_b64,
        version=args.expected_version,
        arch=args.architecture,
        home=args.agent_home,
        username=args.agent_user,
        install_root=Path("/opt/commandcore-agent/helper"),
    )
    print(json.dumps(result, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
