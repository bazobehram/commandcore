"""One-invocation, locally approved Linux helper onboarding.

Invoked by the signed normal-user Agent installer AFTER successful enrollment.
A separate out-of-band pinned helper signing key authorizes the complete release.
No helper install, root command, or Agent identity mutation occurs on failed checks.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path

MAX_BUNDLE = 134_217_728
MAX_WHEEL = 64 * 1024 * 1024
SCRIPTS = (
    "install_signed_linux_helper.py",
    "verify_signed_helper_wheelhouse.py",
    "verify_signed_helper.py",
    "validate_helper_wheelhouse_manifest.py",
    "inspect_helper_bundle.py",
    "check_helper_offline_dependencies.py",
    "helper_identity_guard.py",
)


def _url(raw: str) -> str:
    url = urllib.parse.urlsplit(raw)
    if (
        url.scheme != "https"
        or not url.hostname
        or url.username
        or url.password
        or url.query
        or url.fragment
        or any(ord(c) < 33 for c in raw)
    ):
        raise ValueError("Helper release requires plain HTTPS URL")
    return raw.rstrip("/")


def _fetch(url: str, output: Path, limit: int) -> None:
    # Never trust or write any unsanitized source-provided destination name.
    request = urllib.request.Request(
        _url(url), headers={"User-Agent": "CommandCore-helper-bootstrap/1"}
    )
    with urllib.request.urlopen(request, timeout=35) as resp:
        if urllib.parse.urlsplit(resp.geturl()).scheme != "https":
            raise ValueError("Release download downgraded from HTTPS")
        with output.open("xb") as dest:
            remaining = limit + 1
            while remaining:
                block = resp.read(min(1024 * 1024, remaining))
                if not block:
                    break
                dest.write(block)
                remaining -= len(block)
            if remaining == 0:
                raise ValueError("Release asset exceeds safe download size")


def _verify_signature(document: dict, public_key_b64: str, staging: Path) -> None:
    if not isinstance(document, dict):
        raise ValueError("helper manifest object required")
    signature = base64.b64decode(document.get("signature", ""), validate=True)
    public = base64.b64decode(public_key_b64, validate=True)
    if len(signature) != 64 or len(public) != 32:
        raise ValueError("invalid pinned helper signature/key")
    payload = json.dumps(
        {k: v for k, v in document.items() if k != "signature"},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()
    key_file = staging / "public.der"
    key_file.write_bytes(bytes.fromhex("302a300506032b6570032100") + public)
    sig_file = staging / "signature.bin"
    sig_file.write_bytes(signature)
    canonical = staging / "canonical.json"
    canonical.write_bytes(payload)
    proc = subprocess.run(
        [
            "openssl",
            "pkeyutl",
            "-verify",
            "-rawin",
            "-pubin",
            "-keyform",
            "DER",
            "-inkey",
            str(key_file),
            "-sigfile",
            str(sig_file),
            "-in",
            str(canonical),
        ],
        capture_output=True,
        check=False,
    )
    if proc.returncode:
        raise ValueError("helper manifest signature did not verify")


def _validate_document(
    doc: dict, version: str, arch: str, python_minor: str
) -> tuple[str, list[dict], str]:
    if doc.get("schema_version") != 1 or doc.get("product") != "commandcore-agent":
        raise ValueError("wrong signed helper product/schema")
    if doc.get("version") != version or doc.get("python_minor") != python_minor:
        raise ValueError("signed helper release/runtime mismatch")
    sha = doc.get("source_commit_sha")
    if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ValueError("signed source commit required")
    artifacts = doc.get("artifacts")
    bundle = f"commandcore-helper-linux-{arch}.tar.gz"
    if not isinstance(artifacts, list) or len(artifacts) != 1:
        raise ValueError("one signed helper artifact required")
    item = artifacts[0]
    if (
        item.get("filename") != bundle
        or item.get("platform") != "linux"
        or item.get("architecture") != arch
        or item.get("kind") != "privileged-helper"
    ):
        raise ValueError("signed helper target mismatch")
    inventory = doc.get("offline_wheelhouse", {})
    if (
        not isinstance(inventory, dict)
        or inventory.get("schema_version") != 1
        or inventory.get("product") != "commandcore-helper-wheelhouse"
    ):
        raise ValueError("missing signed offline inventory")
    wheels = inventory.get("wheels")
    if not isinstance(wheels, list) or not 1 <= len(wheels) <= 128:
        raise ValueError("invalid signed wheel inventory")
    names = [v.get("name") for v in wheels if isinstance(v, dict)]
    if len(names) != len(wheels) or len(set(names)) != len(names):
        raise ValueError("duplicate or malformed signed wheel inventory")
    if (
        sum(
            bool(re.fullmatch(r"pip-[0-9][A-Za-z0-9_.+-]*-py3-none-any\.whl", str(n)))
            for n in names
        )
        != 1
    ):
        raise ValueError("signed pip bootstrap wheel missing")
    return bundle, [item, *wheels], sha


def _verified_asset(
    root: Path, filename: str, entry: dict, url: str, maximum: int
) -> None:
    if (
        not re.fullmatch(r"[A-Za-z0-9_.+-]{1,180}", filename)
        or filename.startswith(".")
        or not isinstance(entry.get("size"), int)
        or not 0 < entry["size"] <= maximum
        or not re.fullmatch(r"[0-9a-f]{64}", str(entry.get("sha256", "")))
    ):
        raise ValueError("unsafe signed asset metadata")
    target = root / filename
    _fetch(url + "/" + filename, target, min(entry["size"], maximum))
    if target.stat().st_size != entry["size"]:
        raise ValueError("signed asset size mismatch")
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    if digest != entry["sha256"]:
        raise ValueError("signed asset digest mismatch")


def prepare(
    release_url: str,
    key: str,
    version: str,
    arch: str,
    python_minor: str,
    username: str,
    *,
    verify_only: bool = False,
) -> dict:
    if os.geteuid() == 0:
        raise PermissionError("run the one-command installer as the normal device user")
    if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", username):
        raise ValueError("invalid Agent username")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-rc[0-9]+)?", version):
        raise ValueError("invalid signed helper version")
    if arch not in ("x86_64", "arm64") or python_minor not in ("3.11", "3.12", "3.13"):
        raise ValueError("unsupported Linux helper target")
    release_url = _url(release_url)
    with tempfile.TemporaryDirectory(prefix="cc-local-helper-") as path:
        root = Path(path)
        root.chmod(0o700)
        manifest = root / "manifest.signed.json"
        _fetch(release_url + "/manifest.signed.json", manifest, 1_048_576)
        doc = json.loads(manifest.read_text(), object_pairs_hook=_no_duplicate_keys)
        _verify_signature(doc, key, root)
        bundle, entries, source_sha = _validate_document(
            doc, version, arch, python_minor
        )
        bundle_dir = root / "wheels"
        bundle_dir.mkdir(mode=0o700)
        _verified_asset(root, bundle, entries[0], release_url, MAX_BUNDLE)
        for entry in entries[1:]:
            _verified_asset(bundle_dir, entry["name"], entry, release_url, MAX_WHEEL)
        script_base = f"https://raw.githubusercontent.com/bazobehram/commandcore/{source_sha}/scripts"
        scripts_dir = root / "scripts"
        scripts_dir.mkdir(mode=0o700)
        for script in SCRIPTS:
            _fetch(script_base + "/" + script, scripts_dir / script, 1_048_576)
        # Files are only evaluated after signed release verification, by an
        # approved local administrator. The installer rechecks signed assets
        # in an exclusive root-owned staging directory before invoking pip.
        if verify_only:
            return {
                "result": "SIGNED_RELEASE_DOWNLOADED_NOT_INSTALLED",
                "version": version,
            }
        if not sys.stdin.isatty() and not Path("/dev/tty").exists():
            raise PermissionError("interactive local administrator approval required")
        subprocess.run(
            [
                "sudo",
                "--",
                sys.executable,
                str(scripts_dir / "install_signed_linux_helper.py"),
                "--manifest",
                str(manifest),
                "--bundle",
                str(root / bundle),
                "--wheelhouse",
                str(bundle_dir),
                "--trusted-public-key-b64",
                key,
                "--version",
                version,
                "--architecture",
                arch,
                "--agent-user",
                username,
                "--install",
            ],
            check=True,
            env={
                "PATH": "/usr/bin:/bin",
                "HOME": os.environ.get("HOME", ""),
                "LANG": "C",
            },
        )
        return {"result": "LOCAL_HELPER_SETUP_REQUESTED", "version": version}


def _no_duplicate_keys(pairs):
    result = {}
    for k, v in pairs:
        if k in result:
            raise ValueError("duplicate signed manifest field")
        result[k] = v
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--release-url", required=True)
    p.add_argument("--trusted-public-key-b64", required=True)
    p.add_argument("--version", required=True)
    p.add_argument("--architecture", required=True)
    p.add_argument("--python-minor", required=True)
    p.add_argument("--agent-user", required=True)
    p.add_argument("--verify-only", action="store_true")
    args = p.parse_args()
    result = prepare(
        args.release_url,
        args.trusted_public_key_b64,
        args.version,
        args.architecture,
        args.python_minor,
        args.agent_user,
        verify_only=args.verify_only,
    )
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
