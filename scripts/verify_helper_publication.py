"""Verify a complete externally signed Linux helper release before publication.

This tool performs read-only validation. It NEVER signs, installs or activates
privileged code, and it refuses loose files outside the expected release layout.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
from pathlib import Path


def _load(script: str):
    path = Path(__file__).resolve().with_name(script + ".py")
    spec = importlib.util.spec_from_file_location("cc_" + script, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify(
    root: Path,
    public_key: str,
    version: str,
    architecture: str,
    python_minor: str = "3.13",
) -> dict:
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-rc[0-9]+)?", version):
        raise ValueError("invalid release version")
    if architecture not in ("x86_64", "arm64"):
        raise ValueError("invalid release architecture")
    if python_minor not in ("3.11", "3.12", "3.13"):
        raise ValueError("invalid helper Python minor version")
    if root.is_symlink() or not root.is_dir():
        raise ValueError("signed release root is unsafe")
    bundle_name = f"commandcore-helper-linux-{architecture}.tar.gz"
    expected = {"manifest.signed.json", bundle_name, "wheels"}
    if {p.name for p in root.iterdir()} != expected:
        raise ValueError("incomplete or unexpected signed helper assets")
    manifest = root / "manifest.signed.json"
    bundle = root / bundle_name
    wheels = root / "wheels"
    if any(p.is_symlink() or not p.is_file() for p in (manifest, bundle)):
        raise ValueError("unsafe signed release file")
    if wheels.is_symlink() or not wheels.is_dir():
        raise ValueError("signed wheelhouse missing")
    entries = sorted(wheels.iterdir())
    if not 1 <= len(entries) <= 128:
        raise ValueError("signed wheelhouse must contain 1..128 wheels")
    if any(p.is_symlink() or not p.is_file() or p.suffix != ".whl" for p in entries):
        raise ValueError("unexpected signed wheelhouse member")
    if len({p.name for p in entries}) != len(entries):
        raise ValueError("duplicate signed wheelhouse filename")

    # The signing public key is a protected release policy input, not an
    # automatic key downloaded from the same untrusted release directory.
    release = _load("verify_signed_helper_wheelhouse").verify(
        manifest, bundle, wheels, public_key, architecture
    )
    if release.get("version") != version:
        raise ValueError("signed release version mismatch")
    document = json.loads(manifest.read_text())
    if document.get("python_minor") != python_minor:
        raise ValueError("signed helper Python version mismatch")
    artifacts = document.get("artifacts")
    if not isinstance(artifacts, list) or len(artifacts) != 1:
        raise ValueError("exactly one architecture-scoped helper artifact is required")
    entry = artifacts[0]
    if (
        entry.get("filename") != bundle_name
        or entry.get("platform") != "linux"
        or entry.get("architecture") != architecture
        or entry.get("kind") != "privileged-helper"
    ):
        raise ValueError("signed helper target mismatch")
    offline = _load("check_helper_offline_dependencies").check(
        wheels, python_version=python_minor
    )
    if offline["wheel_count"] != release["wheel_count"]:
        raise ValueError("signed inventory and dependency closure disagree")
    return {
        "verified": True,
        "version": version,
        "architecture": architecture,
        "python_minor": python_minor,
        "helper_sha256": release["helper_sha256"],
        "wheel_count": offline["wheel_count"],
        "assets": [str(manifest), str(bundle), *(str(p) for p in entries)],
        "signed_by_external_authority": True,
        "root_operation": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--trusted-public-key-b64", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--architecture", choices=("x86_64", "arm64"), required=True)
    parser.add_argument(
        "--python-minor", choices=("3.11", "3.12", "3.13"), required=True
    )
    args = parser.parse_args()
    result = verify(
        args.root,
        args.trusted_public_key_b64,
        args.version,
        args.architecture,
        args.python_minor,
    )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
