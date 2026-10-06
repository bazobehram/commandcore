"""Generate pinned installer files from an already signed release manifest.

Offline operator build tool; never handles a signing private key. The verifier
pin comes from the signed Windows artifact, not a mutable network response.
"""

from __future__ import annotations

import argparse
import base64
import json
import re
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def package(
    manifest: Path,
    public: str,
    output: Path,
    manifest_url: str = "",
    linux_only: bool = False,
) -> None:
    raw = manifest.read_bytes()
    if len(raw) > 1_048_576:
        raise ValueError("manifest_too_large")
    data = json.loads(raw)
    canonical = json.dumps(
        {k: v for k, v in data.items() if k != "signature"},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()
    Ed25519PublicKey.from_public_bytes(base64.b64decode(public, validate=True)).verify(
        base64.b64decode(data["signature"], validate=True), canonical
    )
    if data.get("schema_version") != 1 or data.get("product") != "commandcore-agent":
        raise ValueError("wrong_release_product")
    matches = [
        a
        for a in data["artifacts"]
        if a.get("platform") == ("linux" if linux_only else "windows")
        and a.get("architecture") == "x86_64"
        and a.get("kind") == "executable"
    ]
    if len(matches) != 1:
        raise ValueError("no_unique_windows_verifier")
    artifact = matches[0]
    if type(artifact.get("size")) is not int or not 0 < artifact["size"] <= 134_217_728:
        raise ValueError("invalid_artifact_size")
    url = urlsplit(artifact["url"])
    if (
        url.scheme != "https"
        or not url.hostname
        or url.username
        or url.password
        or url.fragment
    ):
        raise ValueError("verifier_requires_https")
    # The URL becomes a PowerShell literal; reject control characters and escape
    # apostrophes. The embedded public key and hash have strict alphabets.
    if any(ord(c) < 32 for c in artifact["url"]) or not re.fullmatch(
        "[a-f0-9]{64}", artifact["sha256"]
    ):
        raise ValueError("invalid_verifier_pin")
    root = Path(__file__).resolve().parents[1]
    if manifest_url:
        parsed = urlsplit(manifest_url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.fragment
            or any(ord(c) < 32 for c in manifest_url)
        ):
            raise ValueError("manifest_requires_https")
    windows = (root / "install/windows.ps1").read_text(encoding="utf-8")
    if manifest_url:
        windows = windows.replace(
            "[string]$ManifestUrl = ''",
            "[string]$ManifestUrl = '" + manifest_url.replace("'", "''") + "'",
            1,
        )
    for token, value in {
        "__COMMANDCORE_RELEASE_PUBLIC_KEY__": public,
        "__COMMANDCORE_VERIFIER_URL__": artifact["url"].replace("'", "''"),
        "__COMMANDCORE_VERIFIER_SHA256__": artifact["sha256"],
    }.items():
        if windows.count(token) != 1:
            raise ValueError("installer_template_pin_mismatch")
        windows = windows.replace(token, value)
    linux = (root / "install/linux.sh").read_text(encoding="utf-8")
    if manifest_url:
        linux = linux.replace(
            "manifest=\n",
            "manifest='" + manifest_url.replace("'", "'\"'\"'") + "'\n",
            1,
        )
    linux = linux.replace(
        "set -eu\n",
        f"set -eu\nCOMMANDCORE_RELEASE_PUBLIC_KEY_B64='{public}'\nexport COMMANDCORE_RELEASE_PUBLIC_KEY_B64\n",
        1,
    )
    output.mkdir(parents=True, exist_ok=True)
    if not linux_only:
        (output / "windows.ps1").write_text(windows, encoding="utf-8", newline="\n")
    (output / "linux.sh").write_text(linux, encoding="utf-8", newline="\n")
    (output / "manifest.json").write_bytes(raw)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--public-key", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest-url", default="")
    parser.add_argument("--linux-only", action="store_true")
    args = parser.parse_args()
    package(
        args.manifest, args.public_key, args.output, args.manifest_url, args.linux_only
    )
    print("Generated pinned installer candidates; platform acceptance still required.")
