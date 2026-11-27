"""Signed Standard install is independent of privileged helper publication."""

import base64
import hashlib
import json
import subprocess

import pytest
from commandcore_server.distribution import install_distribution_routes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI
from fastapi.testclient import TestClient

ORIGIN = "https://public.example"
VERSION = "0.9.0-rc8"


def publish(root, mutation=None):
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes_raw()
    script = b'#!/bin/sh\n# --no-full-control-preparation\nprintf "%s\\n" "$@"\n'
    (root / "linux.sh").write_bytes(script)
    config = {
        "schema_version": 1,
        "server_url": ORIGIN,
        "agent_public_key_b64": base64.b64encode(public).decode(),
        "installer_sha256": hashlib.sha256(script).hexdigest(),
    }
    (root / "linux-standard-onboarding.json").write_text(json.dumps(config))
    (root / VERSION).mkdir()
    manifest = {
        "schema_version": 1,
        "product": "commandcore-agent",
        "version": VERSION,
        "signing_key_id": hashlib.sha256(public).hexdigest()[:16],
        "artifacts": [],
    }
    for arch in ("x86_64", "arm64"):
        filename = "commandcore-agent-linux-" + arch
        data = arch.encode()
        (root / VERSION / filename).write_bytes(data)
        manifest["artifacts"].append(
            {
                "platform": "linux",
                "architecture": arch,
                "kind": "executable",
                "filename": filename,
                "url": f"{ORIGIN}/releases/agent/{VERSION}/{filename}",
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        )
    if mutation:
        mutation(manifest)
    signed = json.dumps(
        manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    manifest["signature"] = base64.b64encode(key.sign(signed)).decode()
    (root / "manifest.json").write_text(json.dumps(manifest))


def client(root, origin=ORIGIN):
    app = FastAPI()
    install_distribution_routes(app, str(root), public_base_url=origin)
    return TestClient(app)


def test_standard_wrapper_without_helper(tmp_path):
    publish(tmp_path)
    with client(tmp_path) as c:
        r = c.get("/install/linux-standard-ready")
        assert r.status_code == 200
        assert r.headers["cache-control"] == "no-store"
        assert c.head("/install/linux-standard-ready").status_code == 200
        assert c.get("/install/linux-ready").status_code == 503
        assert "COMMANDCORE_RELEASE_PUBLIC_KEY_B64" in r.text
        assert "COMMANDCORE_HELPER" not in r.text
        out = subprocess.run(
            ["sh"], input=r.text, text=True, capture_output=True, check=True, timeout=3
        )
        assert out.stdout.splitlines() == [
            "--server",
            ORIGIN,
            "--no-full-control-preparation",
        ]


@pytest.mark.parametrize(
    "mutation",
    [
        lambda m: m["artifacts"][0].update(url="https://private.example/agent"),
        lambda m: m["artifacts"].pop(),
        lambda m: m["artifacts"][1].update(architecture="x86_64"),
        lambda m: m["artifacts"].__setitem__(0, "invalid"),
        lambda m: m.update(signing_key_id="wrong"),
        lambda m: m.update(product="other"),
    ],
)
def test_signed_invalid_manifest_fails_closed(tmp_path, mutation):
    publish(tmp_path, mutation)
    with client(tmp_path) as c:
        assert c.get("/install/linux-standard-ready").status_code == 503


@pytest.mark.parametrize(
    "target",
    [
        "linux.sh",
        "manifest.json",
        "linux-standard-onboarding.json",
        VERSION + "/commandcore-agent-linux-arm64",
    ],
)
def test_missing_release_file_fails_closed(tmp_path, target):
    publish(tmp_path)
    (tmp_path / target).unlink()
    with client(tmp_path) as c:
        assert c.head("/install/linux-standard-ready").status_code == 503


def test_tamper_origin_script_signature(tmp_path):
    publish(tmp_path)
    with client(tmp_path, "https://private.example") as c:
        assert c.get("/install/linux-standard-ready").status_code == 503
    m = tmp_path / "manifest.json"
    manifest = json.loads(m.read_text())
    manifest["signature"] = base64.b64encode(b"x" * 64).decode()
    m.write_text(json.dumps(manifest))
    with client(tmp_path) as c:
        assert c.get("/install/linux-standard-ready").status_code == 503


def test_modified_installer_fails_closed(tmp_path):
    publish(tmp_path)
    (tmp_path / "linux.sh").write_text(
        "#!/bin/sh\n# --no-full-control-preparation\nexit 0\n"
    )
    with client(tmp_path) as c:
        assert c.get("/install/linux-standard-ready").status_code == 503
