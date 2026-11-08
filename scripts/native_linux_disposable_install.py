"""Disposable real-binary clean-install acceptance using an ephemeral TEST key.

No production signer, enrollment, service, network exposure, or release approval.
Run only on ephemeral hosted runners or disposable isolated VMs.
"""

import argparse
import base64
import hashlib
import http.server
import json
import os
import shutil
import subprocess
import tempfile
import threading
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--candidate", required=True, type=Path)
parser.add_argument("--expected-source-sha", required=True)
args = parser.parse_args()
BINARY = args.candidate / "commandcore-agent-linux-x86_64"
INSTALLER = Path(__file__).resolve().parents[1] / "install/linux.sh"
META = json.loads((args.candidate / "UNSIGNED_BUILD_METADATA.json").read_text())
assert META["source_commit"] == args.expected_source_sha
assert (
    args.candidate / "SOURCE_COMMIT.txt"
).read_text().strip() == args.expected_source_sha
for line in (args.candidate / "SHA256SUMS.txt").read_text().splitlines():
    expected_hash, name = line.split("  ")
    assert name in {
        "commandcore-agent-linux-x86_64",
        "UNSIGNED_BUILD_METADATA.json",
        "SOURCE_COMMIT.txt",
    }
    assert (
        hashlib.sha256((args.candidate / name).read_bytes()).hexdigest()
        == expected_hash
    )
assert (
    META["release_status"] == "UNSIGNED_NOT_APPROVED" and META["signatures"] == "NONE"
)
assert META["architecture"] == "x86_64" and META["platform"] == "linux"
assert hashlib.sha256(BINARY.read_bytes()).hexdigest() == META["sha256"]
assert BINARY.stat().st_size == META["size"]

with tempfile.TemporaryDirectory(prefix="cc-disposable-real-installer-") as temp:
    base = Path(temp)
    feed = base / "feed"
    feed.mkdir()
    shutil.copyfile(BINARY, feed / "commandcore-agent-linux-x86_64")
    private = base / "test-only-private.pem"
    public_der = base / "test-only-public.der"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(private)],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    subprocess.run(
        [
            "openssl",
            "pkey",
            "-in",
            str(private),
            "-pubout",
            "-outform",
            "DER",
            "-out",
            str(public_der),
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    public_bytes = public_der.read_bytes()[-32:]
    assert len(public_bytes) == 32
    key = base64.b64encode(public_bytes).decode()
    key_id = hashlib.sha256(public_bytes).hexdigest()[:16]

    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=str(feed), **kwargs)

        def log_message(self, *_):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        artifact_url = f"http://127.0.0.1:{port}/commandcore-agent-linux-x86_64"
        item = {
            "platform": "linux",
            "architecture": "x86_64",
            "kind": "executable",
            "filename": "commandcore-agent-linux-x86_64",
            "url": artifact_url,
            "size": META["size"],
            "sha256": META["sha256"],
        }
        unsigned = {
            "schema_version": 1,
            "product": "commandcore-agent",
            "version": META["package_version"],
            "signing_key_id": key_id,
            "artifacts": [item],
        }
        canonical = base / "canonical.json"
        canonical.write_bytes(
            json.dumps(
                unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ).encode()
        )
        signature_path = base / "signature"
        subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-sign",
                "-rawin",
                "-inkey",
                str(private),
                "-in",
                str(canonical),
                "-out",
                str(signature_path),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        signed = {
            **unsigned,
            "signature": base64.b64encode(signature_path.read_bytes()).decode(),
        }
        (feed / "manifest.json").write_text(json.dumps(signed))

        def install(home_label, pubkey):
            home = base / home_label
            home.mkdir(mode=0o700)
            env = {
                **os.environ,
                "HOME": str(home),
                "XDG_DATA_HOME": str(home / "data"),
                "XDG_CONFIG_HOME": str(home / "config"),
                "COMMANDCORE_RELEASE_PUBLIC_KEY_B64": pubkey,
            }
            cmd = [
                "/bin/sh",
                str(INSTALLER),
                "--manifest",
                f"http://127.0.0.1:{port}/manifest.json",
                "--test-loopback",
                "--no-enroll",
                "--no-service",
                "--no-full-control-preparation",
            ]
            result = subprocess.run(
                cmd, check=False, env=env, capture_output=True, text=True, timeout=75
            )
            return result, home

        valid, home = install("verified-install", key)
        if valid.returncode:
            raise AssertionError(
                "installer_rejected_test_signed_artifact "
                + str(valid.returncode)
                + " "
                + valid.stderr[-950:]
            )
        installed = home / "data/commandcore-agent/current/commandcore-agent"
        assert (
            installed.exists()
            and hashlib.sha256(installed.read_bytes()).hexdigest() == META["sha256"]
        )
        result = subprocess.run(
            [str(installed), "--version"],
            capture_output=True,
            text=True,
            timeout=8,
            check=True,
        )
        assert META["package_version"] in result.stdout
        assert not (home / "config/commandcore/agent.json").exists()
        print(
            "DISPOSABLE_REAL_CI_BINARY_CLEAN_INSTALL=PASS; no-enroll, no-service, version checked",
            flush=True,
        )
        wrong_bytes = bytes([public_bytes[0] ^ 1]) + public_bytes[1:]
        bad, wrong_home = install(
            "wrong-trust-anchor", base64.b64encode(wrong_bytes).decode()
        )
        assert (
            bad.returncode != 0 and not (wrong_home / "data/commandcore-agent").exists()
        ), bad.stderr[-950:]
        print("WRONG_ED25519_TRUST_KEY_FAIL_CLOSED=PASS", flush=True)
        binary = feed / "commandcore-agent-linux-x86_64"
        raw = binary.read_bytes()
        binary.write_bytes(raw[:1024] + b"REPLACED" + raw[1032:])
        bad, tamper_home = install("modified-artifact", key)
        assert (
            bad.returncode != 0
            and not (tamper_home / "data/commandcore-agent").exists()
        ), bad.stderr[-950:]
        print("TAMPERED_ARTIFACT_NO_INSTALL=PASS", flush=True)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
print("EPHEMERAL_KEY_AND_TEST_INSTALLS_DESTROYED; NO_PRODUCTION_SIGNING_OR_ENROLLMENT")
