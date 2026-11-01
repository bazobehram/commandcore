"""Real signed Windows installer acceptance on a disposable CI runner only.

Creates a temporary local HTTPS CA, signed native feed, and disposable
non-administrator Windows user. Never points at a production control plane.
The installer runs with -NoEnroll -NoTask. We also assert that a repeat
installation and a forced upgrade without identity/task fail without changing
any installed binaries or metadata. Genuine interactive Scheduled Task,
enrollment and authenticated upgrade lifecycle remain separate release gates.
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


def create_tls_files(
    directory: Path, *, crl_url: str | None = None
) -> tuple[Path, Path, Path]:
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
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    leaf_builder = (
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
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
    )
    if crl_url is not None:
        # Windows Schannel requires a reachable CRL for this ephemeral CA.
        # A signed CRL may be transported over local HTTP without weakening TLS.
        leaf_builder = leaf_builder.add_extension(
            x509.CRLDistributionPoints(
                [
                    x509.DistributionPoint(
                        full_name=[x509.UniformResourceIdentifier(crl_url)],
                        relative_name=None,
                        reasons=None,
                        crl_issuer=None,
                    )
                ]
            ),
            critical=False,
        )
        crl = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(ca.subject)
            .last_update(now - timedelta(minutes=5))
            .next_update(now + timedelta(days=1))
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )
        (directory / "ci.crl").write_bytes(crl.public_bytes(serialization.Encoding.DER))
    leaf = leaf_builder.sign(ca_key, hashes.SHA256())
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
    # Both are served only by the local ephemeral TLS fixture.
    # The tampered manifest retains the original signature; it must fail
    # Ed25519 validation. The modified verifier must fail its pinned SHA-256
    # before PowerShell ever attempts to execute it.
    tampered = {**manifest, "version": "0.9.0-rc2"}
    (dest / "manifest-tampered.json").write_text(
        json.dumps(tampered), encoding="utf-8"
    )
    (feed / "tampered-verifier.exe").write_bytes(artifact.read_bytes() + b"\x00")
    package(manifest_path, public, output, origin + "/releases/agent/manifest.json")


def run_powershell(script: Path, env: dict[str, str], *args: str) -> None:
    process = subprocess.run(
        [
            "pwsh.exe",
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
        gate_failures = re.findall(
            r"(?m)^CI_SIGNED_INSTALL_MISSING_GATE:([a-z_]+)\s*$", process.stdout
        )
        for gate in gate_failures:
            if gate in {
                "repeat_denied",
                "upgrade_without_identity_denied",
                "unchanged_after_denial",
            }:
                print("FAIL: windows_installer_missing_gate=" + gate)
        hints = re.findall(r"(?m)^CI_WORKER_FAILURE_HINT:([a-z_]+)\s*$", process.stdout)
        allowed_hints = {
            "other",
            "download_or_tls",
            "release_integrity",
            "release_metadata",
            "filesystem_acl",
            "powershell_policy",
            "preexisting_installation",
            "parameter_binding",
            "missing_command",
            "powershell_strictmode",
            "powershell_parse",
        }
        if hints and hints[-1] in allowed_hints:
            print("FAIL: windows_installer_failure_hint=" + hints[-1])
        missing = re.findall(
            r"(?m)^CI_INSTALLER_MISSING_COMMAND:([A-Za-z_]+)\s*$",
            process.stdout,
        )
        allowed_missing = {
            "Get_ScheduledTask",
            "Get_Command",
            "curl_exe",
            "Get_FileHash",
            "Get_ReleaseFile",
            "Get_ItemProperty",
            "Set_Acl",
            "New_Item",
            "ConvertFrom_Json",
            "Get_Content",
            "Remove_Item",
        }
        if missing and missing[-1] in allowed_missing:
            print("FAIL: windows_installer_missing_command=" + missing[-1])
        numbers = re.findall(
            r"(?m)^CI_INSTALLER_SOURCE_LINE:([0-9]{1,3})\s*$", process.stdout
        )
        if numbers and 0 < int(numbers[-1]) < 1000:
            print("FAIL: windows_installer_source_line=" + numbers[-1])
        curl_exits = re.findall(
            r"(?m)^CI_INSTALLER_CURL_EXIT:([0-9]{1,3})\s*$", process.stdout
        )
        if curl_exits and 0 < int(curl_exits[-1]) < 256:
            print("FAIL: windows_installer_curl_exit=" + curl_exits[-1])
        for key in (
            "CI_INSTALLER_FAILURE_TYPE",
            "CI_INSTALLER_FAILURE_ID",
            "CI_INSTALLER_FAILURE_COMMAND",
        ):
            safe_values = re.findall(
                rf"(?m)^{key}:([A-Za-z0-9_]{{1,64}})\s*$", process.stdout
            )
            if safe_values:
                print("FAIL: " + key + "=" + safe_values[-1])
        if safe_stage == "create_user":
            categories = re.findall(
                r"(?m)^CI_USER_CREATE_CATEGORY:([a-z_]+)\s*$", process.stdout
            )
            allowed = {
                "password_policy",
                "privilege",
                "name_collision",
                "argument",
                "other",
            }
            if categories and categories[-1] in allowed:
                print("FAIL: windows_user_create_category=" + categories[-1])
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
        handler = lambda *args, **kwargs: QuietHandler(
            *args, directory=str(feed), **kwargs
        )
        crl_server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        crl_thread = threading.Thread(target=crl_server.serve_forever, daemon=True)
        crl_url = f"http://127.0.0.1:{crl_server.server_port}/ci.crl"
        ca_path, cert_path, key_path = create_tls_files(Path(tls_tmp), crl_url=crl_url)
        shutil.copyfile(Path(tls_tmp) / "ci.crl", feed / "ci.crl")
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
        crl_thread.start()
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
                        "tampered_manifest_denial": True,
                        "pinned_verifier_tamper_denial": True,
                        "clean_after_tamper_denial": True,
                        "repeat_install_denial": True,
                        "upgrade_without_identity_denial": True,
                        "installed_artifacts_unchanged": True,
                        "scope": "no-enroll/no-task signed install and negative repeat/upgrade; genuine upgrade, reboot, task startup and enrollment remain gated",
                    }
                )
            )
        finally:
            server.shutdown()
            server.server_close()
            server_thread.join(timeout=5)
            crl_server.shutdown()
            crl_server.server_close()
            crl_thread.join(timeout=5)
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
