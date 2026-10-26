"""Fail-closed, non-mutating signed Linux helper installation preflight."""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path


def load(name: str, filename: str):
    path = Path(__file__).resolve().with_name(filename)
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify_inputs(
    manifest: Path, bundle: Path, key: str, *, architecture: str, expected_version: str
) -> dict:
    if sys.platform != "linux":
        raise ValueError("Linux only")
    if not expected_version or len(expected_version) > 64:
        raise ValueError("Expected release version required")
    signature = load("cc_helper_signature", "verify_signed_helper.py")
    archive = load("cc_helper_archive", "inspect_helper_bundle.py")
    signed = signature.verify(manifest, bundle, key, architecture=architecture)
    inspected = archive.inspect_bundle(bundle)
    if (
        signed["version"] != expected_version
        or inspected["version"] != expected_version
    ):
        raise ValueError(
            "Signed version, bundle version and expected version must match"
        )
    return {
        "result": "VERIFIED_NOT_INSTALLED",
        "version": expected_version,
        "architecture": architecture,
        "bundle_sha256": signed["sha256"],
        "wheel_sha256": inspected["wheel_sha256"],
        "permission_changes": False,
        "device_reenrolled": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--trusted-public-key-b64", required=True)
    parser.add_argument("--architecture", choices=("x86_64", "arm64"), required=True)
    parser.add_argument("--expected-version", required=True)
    args = parser.parse_args()
    result = verify_inputs(
        args.manifest,
        args.bundle,
        args.trusted_public_key_b64,
        architecture=args.architecture,
        expected_version=args.expected_version,
    )
    print(json.dumps(result, sort_keys=True))
    print("No root operation performed. Separate local authorization is mandatory.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
