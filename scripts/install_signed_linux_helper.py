"""One-time, locally approved installation of an independently signed Linux helper.

The normal network Agent is never replaced or reenrolled. A caller must supply
signed helper assets and a complete signed offline wheelhouse. No remote root
activation is provided; this command must be invoked from the device's terminal.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path


def _load(script: str):
    source = Path(__file__).resolve().with_name(script + ".py")
    spec = importlib.util.spec_from_file_location("cc_" + script, source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify_signed_wheels(*args):
    return _load("verify_signed_helper_wheelhouse").verify(*args)


def verify_dependencies(*args):
    return _load("check_helper_offline_dependencies").check(*args)


def inspect_bundle(*args):
    return _load("inspect_helper_bundle").inspect_bundle(*args)


ROOT = Path("/opt/commandcore-agent/helper")
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:-rc[0-9]+)?\Z")
ARCH = ("x86_64", "arm64")


def validate_assets(
    manifest: Path, bundle: Path, wheelhouse: Path, key: str, version: str, arch: str
) -> dict:
    if not VERSION.fullmatch(version) or arch not in ARCH:
        raise ValueError("invalid signed helper version or architecture")
    signed = verify_signed_wheels(manifest, bundle, wheelhouse, key, arch)
    inspected = inspect_bundle(bundle)
    dependencies = verify_dependencies(wheelhouse)
    if signed["version"] != version or inspected["version"] != version:
        raise ValueError("helper release version differs from signed assets")
    wheel_path = wheelhouse / inspected["wheel_name"]
    import hashlib

    if not wheel_path.is_file() or wheel_path.is_symlink():
        raise ValueError("helper wheel missing from signed wheelhouse")
    if hashlib.sha256(wheel_path.read_bytes()).hexdigest() != inspected["wheel_sha256"]:
        raise ValueError("helper bundle differs from signed wheelhouse")
    return {
        "version": version,
        "architecture": arch,
        "helper_digest": signed["helper_sha256"],
        "wheel_count": dependencies["wheel_count"],
    }


def _root_dir(path: Path) -> None:
    if path.is_symlink() or not path.is_dir():
        raise PermissionError("unsafe root helper directory")
    st = path.stat()
    if st.st_uid != 0 or st.st_mode & 0o022:
        raise PermissionError("helper directory must be root-owned and protected")


def _approval(version: str, username: str) -> None:
    # --yes is intentionally not supported. A web/API caller cannot approve.
    with open("/dev/tty", "r+", encoding="utf-8") as terminal:
        terminal.write(
            f"Install a root-capable CommandCore helper {version} for {username}?\n"
            "This grants the locally approved ceiling FULL_CONTROL, while "
            "server and account permissions remain separate.\n"
            "Type ENABLE FULL_CONTROL to approve: "
        )
        terminal.flush()
        if terminal.readline().strip() != "ENABLE FULL_CONTROL":
            raise PermissionError("local administrator approval declined")


def _copy_verified(source: Path, target: Path, limit: int = 64 * 1024 * 1024) -> None:
    # Open the source inode without following a symlink. Re-check size and
    # type on the descriptor to defend against path replacement races.
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= limit:
            raise ValueError("unsafe signed asset inode or size")
        with os.fdopen(os.dup(fd), "rb") as inp, target.open("xb") as out:
            remaining = limit + 1
            while remaining > 0:
                chunk = inp.read(min(1024 * 1024, remaining))
                if not chunk:
                    break
                remaining -= len(chunk)
                out.write(chunk)
            if remaining == 0:
                raise ValueError("signed asset exceeds size limit")
        target.chmod(0o600)
    finally:
        os.close(fd)


def install(
    manifest: Path,
    bundle: Path,
    wheelhouse: Path,
    key: str,
    version: str,
    arch: str,
    username: str,
) -> dict:
    if os.geteuid() != 0 or sys.platform != "linux":
        raise PermissionError("local Linux administrator authorization required")
    user = pwd.getpwnam(username)
    if user.pw_uid == 0:
        raise ValueError("the network Agent must remain nonroot")
    # Confirm that the helper belongs to an existing managed user Agent.
    # This is read-only and never rewrites enrollment keys or service units.
    _load("helper_identity_guard").inspect_agent(Path(user.pw_dir), username)
    _root_dir(ROOT.parent.parent)
    if ROOT.exists() or ROOT.is_symlink():
        _root_dir(ROOT)
        if (ROOT / "venv").exists() or (ROOT / "venv").is_symlink():
            raise FileExistsError(
                "existing helper requires reviewed upgrade/rollback procedure"
            )
    # Bound untrusted input sizes before copying into a root-owned staging area.
    if (
        manifest.is_symlink()
        or not manifest.is_file()
        or not 0 < manifest.stat().st_size <= 1_048_576
        or bundle.is_symlink()
        or not bundle.is_file()
        or not 0 < bundle.stat().st_size <= 134_217_728
        or wheelhouse.is_symlink()
        or not wheelhouse.is_dir()
    ):
        raise ValueError("unsafe signed source assets")
    incoming = list(wheelhouse.iterdir())
    if not 1 <= len(incoming) <= 128:
        raise ValueError("invalid wheelhouse entry count")
    for wheel in incoming:
        if (
            wheel.is_symlink()
            or not wheel.is_file()
            or wheel.stat().st_size > 64 * 1024 * 1024
        ):
            raise ValueError("unsafe wheelhouse member")
    _approval(version, username)
    # No system paths are created until the device-local operator approves.
    ROOT.parent.mkdir(mode=0o700, exist_ok=True)
    _root_dir(ROOT.parent)
    ROOT.mkdir(mode=0o700, exist_ok=True)
    _root_dir(ROOT)
    # Copy ALL untrusted-source data into root-owned private staging first.
    # Signature, archive and wheelhouse hashes are rechecked after the copy
    # to prevent unprivileged modification between verification and pip.
    with tempfile.TemporaryDirectory(prefix=".signed-stage-", dir=ROOT) as stage_name:
        stage = Path(stage_name)
        stage.chmod(0o700)
        staged_manifest, staged_bundle = (
            stage / "manifest.json",
            stage / "helper.tar.gz",
        )
        _copy_verified(manifest, staged_manifest, 1_048_576)
        _copy_verified(bundle, staged_bundle, 134_217_728)
        wheels = stage / "wheels"
        wheels.mkdir(mode=0o700)
        for source in incoming:
            if not re.fullmatch(r"[A-Za-z0-9_.+-]+\.whl", source.name):
                raise ValueError("unexpected wheelhouse member")
            _copy_verified(source, wheels / source.name)
        verified = validate_assets(
            staged_manifest, staged_bundle, wheels, key, version, arch
        )
        # Never use a network Python index or a user-controlled pip config.
        release = ROOT / "venv"
        if release.exists() or release.is_symlink():
            raise FileExistsError("existing helper runtime cannot be overwritten")
        # Build the venv at its FINAL root-owned path. Relocating a populated
        # venv breaks absolute shebangs in pip-generated helper entry points.
        # On any build failure remove this new, inactive helper-only runtime.
        try:
            subprocess.run([sys.executable, "-m", "venv", str(release)], check=True)
            clean_env = {
                "PATH": "/usr/bin:/bin",
                "HOME": "/root",
                "PIP_CONFIG_FILE": os.devnull,
                "PIP_NO_INDEX": "1",
                "PYTHONNOUSERSITE": "1",
            }
            subprocess.run(
                [
                    str(release / "bin/python"),
                    "-m",
                    "pip",
                    "install",
                    "--no-index",
                    "--only-binary=:all:",
                    "--find-links",
                    str(wheels),
                    f"commandcore-agent=={version}",
                ],
                env=clean_env,
                check=True,
            )
            helper = release / "bin/commandcore-helper"
            agent_cli = release / "bin/commandcore-agent"
            if not helper.is_file() or not agent_cli.is_file():
                raise RuntimeError("signed helper entry points missing")
        except Exception:
            if release.is_dir() and not release.is_symlink():
                shutil.rmtree(release)
            raise
    try:
        subprocess.run(
            [
                str(ROOT / "venv/bin/commandcore-agent"),
                "enable-full-control",
                "--agent-user",
                username,
                "--acknowledge-root-access",
            ],
            check=True,
        )
    except Exception:
        # Fail closed, and permit a clean local retry. Never touch Agent state.
        subprocess.run(
            ["systemctl", "disable", "--now", "commandcore-helper.service"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            if release.is_dir() and not release.is_symlink():
                shutil.rmtree(release)
        except OSError:
            pass
        raise
    return {
        **verified,
        "local_preparation": "ENABLED",
        "server_permission_unchanged": True,
        "agent_reenrolled": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--wheelhouse", type=Path, required=True)
    parser.add_argument("--trusted-public-key-b64", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--architecture", choices=ARCH, required=True)
    parser.add_argument("--agent-user", required=True)
    parser.add_argument(
        "--install", action="store_true", help="requires local root and typed approval"
    )
    args = parser.parse_args()
    try:
        if args.install:
            outcome = install(
                args.manifest,
                args.bundle,
                args.wheelhouse,
                args.trusted_public_key_b64,
                args.version,
                args.architecture,
                args.agent_user,
            )
        else:
            outcome = validate_assets(
                args.manifest,
                args.bundle,
                args.wheelhouse,
                args.trusted_public_key_b64,
                args.version,
                args.architecture,
            )
            outcome["local_preparation"] = "NOT_INSTALLED"
        print(json.dumps(outcome, sort_keys=True))
        return 0
    except (
        OSError,
        ValueError,
        PermissionError,
        subprocess.CalledProcessError,
        RuntimeError,
    ) as exc:
        print(
            f"Signed helper setup blocked: {type(exc).__name__}: {exc}", file=sys.stderr
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
