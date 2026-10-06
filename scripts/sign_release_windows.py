"""Operator-workstation Ed25519 signing with current-user Windows DPAPI custody.

The protected seed is outside the repository and application containers. No raw
seed is written or printed. This is not an HSM or an Authenticode certificate.
"""

from __future__ import annotations

import argparse
import base64
import ctypes
import hashlib
import json
import os
import subprocess
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)


class Blob(ctypes.Structure):
    _fields_ = [("size", ctypes.c_ulong), ("data", ctypes.POINTER(ctypes.c_ubyte))]


def dpapi(raw: bytes, *, decrypt: bool = False) -> bytes:
    if os.name != "nt":
        raise RuntimeError("Windows operator workstation required")
    crypt = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    buffer = (ctypes.c_ubyte * len(raw)).from_buffer_copy(raw)
    entropy_bytes = b"commandcore-release-ed25519-v1"
    entropy_buffer = (ctypes.c_ubyte * len(entropy_bytes)).from_buffer_copy(
        entropy_bytes
    )
    source = Blob(len(raw), buffer)
    entropy = Blob(len(entropy_bytes), entropy_buffer)
    target = Blob()
    # UI_FORBIDDEN; no machine-wide flag. CryptUnprotectData never receives a
    # description pointer, avoiding a second allocation to manage.
    function = crypt.CryptUnprotectData if decrypt else crypt.CryptProtectData
    function.argtypes = [
        ctypes.POINTER(Blob),
        ctypes.c_void_p,
        ctypes.POINTER(Blob),
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.POINTER(Blob),
    ]
    function.restype = ctypes.c_int
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    if not function(
        ctypes.byref(source),
        None,
        ctypes.byref(entropy),
        None,
        None,
        1,
        ctypes.byref(target),
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.string_at(target.data, target.size)
    finally:
        kernel.LocalFree(target.data)


def initialize(vault: Path) -> str:
    if vault.exists():
        raise RuntimeError("Signing vault already exists; refusing key replacement")
    vault.mkdir(parents=True)
    sid = subprocess.check_output(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "[Security.Principal.WindowsIdentity]::GetCurrent().User.Value",
        ],
        text=True,
    ).strip()
    subprocess.run(
        [
            "icacls.exe",
            str(vault),
            "/inheritance:r",
            "/grant:r",
            f"*{sid}:(OI)(CI)F",
            "*S-1-5-18:(OI)(CI)F",
        ],
        check=True,
        capture_output=True,
    )
    key = Ed25519PrivateKey.generate()
    seed = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    protected = dpapi(seed)
    with (vault / "release-seed.dpapi").open("xb") as file:
        file.write(protected)
    public = base64.b64encode(
        key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode()
    (vault / "release-public-key.txt").write_text(public + "\n", encoding="ascii")
    return public


def sign(vault: Path, source: Path, output: Path) -> None:
    raw = source.read_bytes()
    if len(raw) > 1_048_576:
        raise ValueError("manifest_too_large")
    data = json.loads(raw)
    if data.get("schema_version") != 1 or data.get("product") != "commandcore-agent":
        raise ValueError("wrong_release_product")
    key = Ed25519PrivateKey.from_private_bytes(
        dpapi((vault / "release-seed.dpapi").read_bytes(), decrypt=True)
    )
    public = base64.b64encode(
        key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode()
    if public != (vault / "release-public-key.txt").read_text(encoding="ascii").strip():
        raise ValueError("signing_vault_public_key_mismatch")
    body = {k: v for k, v in data.items() if k != "signature"}
    canonical = json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    data["signature"] = base64.b64encode(key.sign(canonical)).decode()
    output.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=["init", "sign"])
    parser.add_argument(
        "--vault",
        type=Path,
        default=Path(os.getenv("LOCALAPPDATA", ".")) / "CommandCore/Signing",
    )
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.operation == "init":
        public = initialize(args.vault)
        print("Public key: " + public)
        print(
            "Public-key SHA256: " + hashlib.sha256(base64.b64decode(public)).hexdigest()
        )
        print("Protected custody: " + str(args.vault))
    else:
        if not args.manifest or not args.output:
            parser.error("sign requires --manifest and --output")
        sign(args.vault, args.manifest, args.output)
        print("Signed manifest: " + str(args.output))
