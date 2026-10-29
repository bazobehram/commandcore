"""Offline-only, locally confirmed Ed25519 helper release signing tool.

This script does not generate keys, access networks, or install/activate helpers.
Use on an isolated operator-controlled signing computer, never on a device
managed by CommandCore. Do not put the private key in CI or on a managed control-plane computer.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import os
import re
import shutil
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def load(script: str):
    file = Path(__file__).resolve().with_name(script + ".py")
    spec = importlib.util.spec_from_file_location("cc_" + script, file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def file_info(path: Path, limit: int) -> tuple[int, str]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("candidate file must be a regular non-symlink")
    size = path.stat().st_size
    if not 0 < size <= limit:
        raise ValueError("candidate file size invalid")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for data in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(data)
    return size, digest.hexdigest()


def load_private_key(path: Path) -> Ed25519PrivateKey:
    if path.is_symlink() or not path.is_file():
        raise PermissionError("private signing key must be a local regular file")
    info = path.stat()
    if info.st_uid != os.geteuid() or info.st_mode & 0o077 or info.st_size > 8192:
        raise PermissionError("private key must be owned by current user, mode 0600")
    candidate = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(candidate, Ed25519PrivateKey):
        raise TypeError("only Ed25519 signing keys are permitted")
    return candidate


def prepare_manifest(
    bundle: Path,
    wheels: Path,
    version: str,
    architecture: str,
    python_minor: str,
    source_commit: str,
) -> dict:
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-rc[0-9]+)?", version):
        raise ValueError("invalid release version")
    if architecture not in ("x86_64", "arm64") or python_minor not in (
        "3.11",
        "3.12",
        "3.13",
    ):
        raise ValueError("unsupported signed helper target")
    if not re.fullmatch(r"[0-9a-f]{40}", source_commit):
        raise ValueError("reviewed Git source SHA is required")
    if wheels.is_symlink() or not wheels.is_dir():
        raise ValueError("wheelhouse must be a regular directory")
    expected_bundle = f"commandcore-helper-linux-{architecture}.tar.gz"
    if bundle.name != expected_bundle:
        raise ValueError("candidate bundle filename does not match architecture")
    bundle_size, bundle_hash = file_info(bundle, 134_217_728)
    inspected = load("inspect_helper_bundle").inspect_bundle(bundle)
    if inspected["version"] != version:
        raise ValueError("candidate bundle version mismatch")
    wheel_paths = sorted(wheels.iterdir())
    if not 1 <= len(wheel_paths) <= 128:
        raise ValueError("invalid offline wheel count")
    inventory = []
    for wheel in wheel_paths:
        if not re.fullmatch(r"[A-Za-z0-9_.+-]+\.whl", wheel.name):
            raise ValueError("unexpected wheel filename")
        size, digest = file_info(wheel, 64 * 1024 * 1024)
        inventory.append({"name": wheel.name, "sha256": digest, "size": size})
    inspected_wheel = next(
        (entry for entry in inventory if entry["name"] == inspected["wheel_name"]),
        None,
    )
    if not inspected_wheel or inspected_wheel["sha256"] != inspected["wheel_sha256"]:
        raise ValueError("bundle wheel does not match offline wheelhouse")
    closure = load("check_helper_offline_dependencies").check(
        wheels, python_version=python_minor
    )
    if closure["wheel_count"] != len(inventory):
        raise ValueError("incomplete wheelhouse")
    return {
        "schema_version": 1,
        "product": "commandcore-agent",
        "version": version,
        "python_minor": python_minor,
        "source_commit_sha": source_commit,
        "artifacts": [
            {
                "filename": expected_bundle,
                "platform": "linux",
                "architecture": architecture,
                "kind": "privileged-helper",
                "size": bundle_size,
                "sha256": bundle_hash,
            }
        ],
        "offline_wheelhouse": {
            "schema_version": 1,
            "product": "commandcore-helper-wheelhouse",
            "wheels": inventory,
        },
    }


def sign_to_directory(
    private_key_file: Path,
    bundle: Path,
    wheels: Path,
    output: Path,
    version: str,
    architecture: str,
    python_minor: str,
    source_commit: str,
) -> dict:
    manifest = prepare_manifest(
        bundle, wheels, version, architecture, python_minor, source_commit
    )
    if output.exists() or output.is_symlink():
        raise FileExistsError("signed output directory already exists")
    if output.parent.is_symlink() or not output.parent.is_dir():
        raise ValueError("unsafe signed output parent directory")
    private = load_private_key(private_key_file)
    canonical = json.dumps(
        manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    manifest["signature"] = base64.b64encode(private.sign(canonical)).decode()
    pub = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    public_key = base64.b64encode(pub).decode()
    with tempfile.TemporaryDirectory(
        prefix=".cc-signed-staging-", dir=output.parent
    ) as directory:
        stage = Path(directory)
        (stage / "wheels").mkdir()
        shutil.copyfile(bundle, stage / bundle.name)
        for wheel in sorted(wheels.iterdir()):
            shutil.copyfile(wheel, stage / "wheels" / wheel.name)
        (stage / "manifest.signed.json").write_text(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n"
        )
        # Validate staged copies with exactly the public-release verification
        # implementation before atomically exposing any release files.
        result = load("verify_signed_helper_wheelhouse").verify(
            stage / "manifest.signed.json",
            stage / bundle.name,
            stage / "wheels",
            public_key,
            architecture,
        )
        if result["version"] != version:
            raise ValueError("staged signed release verification failed")
        stage.rename(output)
    return {
        "signed": True,
        "version": version,
        "architecture": architecture,
        "python_minor": python_minor,
        "public_key_b64": public_key,
        "output": str(output),
        "device_installation": False,
    }


def local_approval(version: str, arch: str, python_minor: str) -> None:
    with open("/dev/tty", "r+", encoding="utf-8") as terminal:
        terminal.write(
            f"Sign privileged helper {version}, {arch}, Python {python_minor}? "
            "This may authorize root-level code on other computers.\n"
            "Only proceed on a trusted offline signing machine after reviewing "
            "the source and candidate bundle.\n"
            "Type SIGN HELPER RELEASE to authorize: "
        )
        terminal.flush()
        if terminal.readline().strip() != "SIGN HELPER RELEASE":
            raise PermissionError("offline signer authorization declined")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--wheelhouse", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--architecture", choices=("x86_64", "arm64"), required=True)
    parser.add_argument(
        "--python-minor", choices=("3.11", "3.12", "3.13"), required=True
    )
    parser.add_argument("--reviewed-source-commit", required=True)
    args = parser.parse_args()
    local_approval(args.version, args.architecture, args.python_minor)
    result = sign_to_directory(
        args.private_key,
        args.bundle,
        args.wheelhouse,
        args.output,
        args.version,
        args.architecture,
        args.python_minor,
        args.reviewed_source_commit,
    )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
