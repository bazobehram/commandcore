"""Verify installer manifest and select one artifact; emits public metadata only."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--public-key", required=True)
    parser.add_argument("--platform", choices=["linux", "windows"], required=True)
    parser.add_argument("--architecture", choices=["x86_64", "arm64"], required=True)
    parser.add_argument("--artifact", type=Path)
    args = parser.parse_args()
    raw = args.manifest.read_bytes()
    if len(raw) > 1048576:
        raise ValueError("manifest_too_large")
    data = json.loads(raw)
    canonical = json.dumps(
        {k: v for k, v in data.items() if k != "signature"},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()
    Ed25519PublicKey.from_public_bytes(
        base64.b64decode(args.public_key, validate=True)
    ).verify(base64.b64decode(data["signature"], validate=True), canonical)
    if data.get("schema_version") != 1 or data.get("product") != "commandcore-agent":
        raise ValueError("invalid_product_or_schema")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,60}", data["version"]):
        raise ValueError("invalid_version")
    artifacts = [
        a
        for a in data["artifacts"]
        if a.get("platform") == args.platform
        and a.get("architecture") == args.architecture
        and a.get("kind") == "executable"
    ]
    if len(artifacts) != 1:
        raise ValueError("no_unique_supported_artifact")
    artifact = artifacts[0]
    url = urlsplit(artifact["url"])
    if (
        url.scheme != "https"
        or not url.hostname
        or url.username
        or url.password
        or url.fragment
    ):
        raise ValueError("artifact_requires_https")
    if (
        not re.fullmatch("[a-f0-9]{64}", artifact["sha256"])
        or type(artifact["size"]) is not int
        or not 0 < artifact["size"] <= 134217728
    ):
        raise ValueError("invalid_integrity_metadata")
    if args.artifact:
        binary = args.artifact.read_bytes()
        if (
            len(binary) != artifact["size"]
            or hashlib.sha256(binary).hexdigest() != artifact["sha256"]
        ):
            raise ValueError("artifact_integrity_failed")
    print(json.dumps({**artifact, "version": data["version"]}))


if __name__ == "__main__":
    main()
