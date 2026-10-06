"""Cross-language signed manifest acceptance against the actual native verifier."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from package_installers import package


def main() -> None:
    executable = os.environ["COMMANDCORE_NATIVE_VERIFIER"]
    key = Ed25519PrivateKey.generate()
    public = base64.b64encode(
        key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode()
    with tempfile.TemporaryDirectory(prefix="commandcore-native-release-") as temp:
        root = Path(temp)
        manifest = root / "manifest.json"
        artifact = root / "agent.exe"
        artifact.write_bytes(b"signed fixture")
        data = {
            "schema_version": 1,
            "product": "commandcore-agent",
            "version": "0.9.0-rc1",
            "description": "Unicode release metadata — Ελληνικά",
            "artifacts": [
                {
                    "platform": "windows",
                    "architecture": "x86_64",
                    "kind": "executable",
                    "url": "https://example.invalid/agent.exe",
                    "size": artifact.stat().st_size,
                    "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                }
            ],
        }

        def sign() -> None:
            body = {k: v for k, v in data.items() if k != "signature"}
            canonical = json.dumps(
                body, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ).encode()
            data["signature"] = base64.b64encode(key.sign(canonical)).decode()
            manifest.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")

        def verify(expected: bool) -> None:
            result = subprocess.run(
                [
                    executable,
                    "verify-release",
                    str(manifest),
                    "--public-key",
                    public,
                    "--platform",
                    "windows",
                    "--architecture",
                    "x86_64",
                    "--artifact",
                    str(artifact),
                ],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
            if (result.returncode == 0) != expected:
                raise AssertionError(
                    f"native verification outcome mismatch: {result.stderr}"
                )

        sign()
        verify(True)
        package(manifest, public, root / "installers")
        windows = (root / "installers/windows.ps1").read_text(encoding="utf-8")
        assert "__COMMANDCORE_VERIFIER_" not in windows
        assert public in windows and data["artifacts"][0]["sha256"] in windows
        assert b"\r" not in (root / "installers/linux.sh").read_bytes()
        manifest_url = (
            "https://example.invalid/private/manifest.json?candidate=operator's"
        )
        package(manifest, public, root / "private-feed", manifest_url)
        linux = (root / "private-feed/linux.sh").read_text(encoding="utf-8")
        windows = (root / "private-feed/windows.ps1").read_text(encoding="utf-8")
        assert "operator'\"'\"'s" in linux
        assert "operator''s" in windows
        try:
            package(
                manifest,
                public,
                root / "insecure-feed",
                "http://example.invalid/manifest",
            )
        except ValueError as exc:
            assert str(exc) == "manifest_requires_https"
        else:
            raise AssertionError("packager accepted HTTP manifest feed")
        artifact.write_bytes(b"tampered")
        verify(False)
        artifact.write_bytes(b"signed fixture")
        data["version"] = "1.0.0"
        manifest.write_text(json.dumps(data), encoding="utf-8")
        verify(False)
        try:
            package(manifest, public, root / "rejected")
        except InvalidSignature:
            print("PASS: installer packager rejects invalid manifest signature")
        else:
            raise AssertionError("packager accepted invalid signature")
        sign()
        data["artifacts"][0]["url"] = "http://example.invalid/agent.exe"
        sign()
        verify(False)
    print(
        "PASS: Python signer/native Ed25519 verification, Unicode canonicalization, artifact/signature tampering, HTTPS and installer pins"
    )


if __name__ == "__main__":
    main()
