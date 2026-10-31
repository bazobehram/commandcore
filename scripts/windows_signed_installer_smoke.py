"""Real signed Windows installer acceptance on a disposable CI runner only.

Creates a temporary local HTTPS CA, signed native feed, and disposable
non-administrator Windows user. Never points at a production control plane.
The only installer switches are -NoEnroll -NoTask; interactive Scheduled Task,
enrollment and upgrade lifecycle remain separate release gates.
"""

from __future__ import annotations

import base64
import hashlib
import http.server
import ipaddress
import json
import os
import re
import secrets
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from package_installers import package

ROOT = Path(__file__).resolve().parents[1]


def create_tls_files(directory: Path) -> tuple[Path, Path, Path]:
    now = datetime.now(timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Disposable CommandCore CI Root")]
    )
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    leaf = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(ca.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(hours=8))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    ca_path = directory / "ci-ca.cer"
    cert_path = directory / "ci-server.pem"
    key_path = directory / "ci-server.key"
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    cert_path.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        leaf_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return ca_path, cert_path, key_path


def create_release(feed: Path, output: Path, native: Path, origin: str) -> None:
    artifact = feed / "agent.exe"
    artifact.write_bytes(native.read_bytes())
    signer = ed25519.Ed25519PrivateKey.generate()
    public = base64.b64encode(
        signer.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
    ).decode()
    manifest = {
        "schema_version": 1,
        "product": "commandcore-agent",
        "version": "0.9.0-rc1",
        "artifacts": [
            {
                "platform": "windows",
                "architecture": "x86_64",
                "kind": "executable",
                "url": origin + "/agent.exe",
                "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                "size": artifact.stat().st_size,
            }
        ],
    }
    canonical = json.dumps(
        manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    manifest["signature"] = base64.b64encode(signer.sign(canonical)).decode()
    dest = feed / "releases" / "agent"
    dest.mkdir(parents=True)
    manifest_path = dest / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    package(manifest_path, public, output, origin + "/releases/agent/manifest.json")


def run_powershell(script: Path, env: dict[str, str], *args: str) -> None:
    process = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(script),
            *args,
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=155,
        check=False,
    )
    # Do not expose task credentials, fixtures or raw PowerShell exceptions.
    if process.returncode:
        stages = re.findall(r"(?m)^CI_INSTALL_STAGE:([a-z_]+)\s*$", process.stdout)
        safe_stage = stages[-1] if stages else "unknown"
        print("FAIL: windows_installer_stage=" + safe_stage)
        raise RuntimeError("standard_user_installer_acceptance_failed")


def main() -> int:
    if os.name != "nt" or os.environ.get("CI") != "true":
        print("NOT_RUN: disposable Windows CI runner required")
        return 2
    native = Path(os.environ["COMMANDCORE_NATIVE_VERIFIER"]).resolve()
    if not native.is_file():
        raise RuntimeError("native_verifier_missing")
    # Public test assets are readable by the standard user. TLS private keys
    # remain separately under the runner administrator's private temp root.
    parent = Path(os.environ["PROGRAMDATA"])
    with (
        tempfile.TemporaryDirectory(
            prefix="commandcore-win-install-", dir=parent
        ) as tmp,
        tempfile.TemporaryDirectory(prefix="commandcore-ci-tls-") as tls_tmp,
    ):
        base = Path(tmp)
        feed = base / "feed"
        output = base / "installers"
        feed.mkdir()
        (base / "result").mkdir()
        ca_path, cert_path, key_path = create_tls_files(Path(tls_tmp))
        handler = lambda *args, **kwargs: QuietHandler(
            *args, directory=str(feed), **kwargs
        )
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(cert_path), str(key_path))
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        origin = f"https://localhost:{server.server_port}"
        root_hash = ca_path.read_bytes()
        ca_thumbprint = (
            x509.load_pem_x509_certificate(root_hash).fingerprint(hashes.SHA1()).hex()
        )
        env = os.environ.copy()
        env["COMMANDCORE_CI_USER_PASSWORD"] = "Cc!" + secrets.token_urlsafe(18).replace(
            "-", "a"
        ).replace("_", "b")
        user = "cc" + secrets.token_hex(5)
        server_thread.start()
        trusted = False
        try:
            create_release(feed, output, native, origin)
            shutil.copyfile(
                ROOT / "scripts" / "windows_signed_installer_worker.ps1",
                output / "worker.ps1",
            )
            add = subprocess.run(
                ["certutil.exe", "-addstore", "-f", "Root", str(ca_path)],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            if add.returncode:
                raise RuntimeError("ephemeral_ca_trust_failed")
            trusted = True
            run_powershell(
                ROOT / "scripts" / "windows_signed_installer_driver.ps1",
                env,
                user,
                str(base),
                origin,
            )
            print(
                json.dumps(
                    {
                        "status": "PASS",
                        "platform": "windows",
                        "signed_manifest_and_artifact": True,
                        "real_powershell_installer": True,
                        "non_admin_install_user": True,
                        "no_enroll": True,
                        "no_task": True,
                        "scope": "installation only; reboot/task/enrollment remain gated",
                    }
                )
            )
        finally:
            server.shutdown()
            server.server_close()
            server_thread.join(timeout=5)
            if trusted:
                subprocess.run(
                    ["certutil.exe", "-delstore", "Root", ca_thumbprint],
                    capture_output=True,
                    timeout=15,
                    check=False,
                )
            env.pop("COMMANDCORE_CI_USER_PASSWORD", None)
    return 0


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *_args) -> None:
        pass


if __name__ == "__main__":
    sys.exit(main())
