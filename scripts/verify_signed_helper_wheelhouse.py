"""Bind every offline dependency to the Ed25519 signed helper release manifest.

Only verification. Does not extract, install, activate services or confer root access.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path


def load(path: Path):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify(
    manifest: Path, artifact: Path, wheelhouse: Path, key: str, arch: str
) -> dict:
    scripts = Path(__file__).resolve().parent
    release = load(scripts / "verify_signed_helper.py")
    signed = release.verify(manifest, artifact, key, architecture=arch)
    document = json.loads(manifest.read_text())
    inventory = document.get("offline_wheelhouse")
    if not isinstance(inventory, dict):
        raise ValueError("signed manifest must contain offline_wheelhouse inventory")
    if (
        inventory.get("schema_version") != 1
        or inventory.get("product") != "commandcore-helper-wheelhouse"
    ):
        raise ValueError("invalid signed offline wheelhouse inventory")
    inventory_checker = load(scripts / "validate_helper_wheelhouse_manifest.py")
    # The entire inventory is authenticated by the Ed25519 verification above.
    # No local inventory file can override the signed contents.
    import tempfile

    with tempfile.TemporaryDirectory(prefix="cc-helper-inventory-") as directory:
        path = Path(directory) / "signed-inventory.json"
        path.write_text(json.dumps(inventory))
        result = inventory_checker.validate(wheelhouse, path)
    if not result["verified"]:
        raise ValueError("offline wheelhouse integrity failed")
    return {
        "result": "SIGNED_OFFLINE_WHEELHOUSE_VERIFIED",
        "version": signed["version"],
        "architecture": arch,
        "helper_sha256": signed["sha256"],
        "wheel_count": result["wheel_count"],
        "installed": False,
    }


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--manifest", type=Path, required=True)
    p.add_argument("--artifact", type=Path, required=True)
    p.add_argument("--wheelhouse", type=Path, required=True)
    p.add_argument("--trusted-public-key-b64", required=True)
    p.add_argument("--architecture", choices=("x86_64", "arm64"), required=True)
    a = p.parse_args()
    print(
        json.dumps(
            verify(
                a.manifest,
                a.artifact,
                a.wheelhouse,
                a.trusted_public_key_b64,
                a.architecture,
            ),
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
