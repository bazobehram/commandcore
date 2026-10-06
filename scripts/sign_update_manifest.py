#!/usr/bin/env python3
"""Offline helper to sign a CommandCore Agent update manifest.

The Ed25519 private key is supplied as a raw 32-byte base64 value or a file
containing it. Never store release private keys in the CommandCore repository or
control-plane host.
"""

from __future__ import annotations
import argparse, base64, json
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def canonical(d):
    return json.dumps(
        {k: v for k, v in d.items() if k != "signature"},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()


p = argparse.ArgumentParser()
p.add_argument("manifest")
p.add_argument("--private-key-file", required=True)
p.add_argument("--output")
a = p.parse_args()
raw = Path(a.private_key_file).read_text().strip()
key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(raw, validate=True))
data = json.loads(Path(a.manifest).read_text())
data["signature"] = base64.b64encode(key.sign(canonical(data))).decode()
out = Path(a.output or a.manifest)
out.write_text(json.dumps(data, indent=2) + "\n")
print(out)
