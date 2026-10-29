"""One-command onboarding must never downgrade silently to Agent-only setup."""

import base64
import json
import os
import subprocess
from pathlib import Path

import pytest
from commandcore_server.distribution import install_distribution_routes
from fastapi import FastAPI
from fastapi.testclient import TestClient

PUBLIC_KEY = base64.b64encode(b"p" * 32).decode()


def _client(path: Path) -> TestClient:
    app = FastAPI()
    install_distribution_routes(app, str(path))
    return TestClient(app)


def _config() -> dict:
    return {
        "schema_version": 1,
        "server_url": "https://private.example.org",
        "agent_public_key_b64": PUBLIC_KEY,
        "helper_release_url": "https://releases.example.org/helper-v0.9.0-rc7",
        "helper_public_key_b64": PUBLIC_KEY,
        "helper_release_version": "0.9.0-rc7",
        "helper_bootstrap_url": "https://example.org/reviewed/bootstrap.py",
        "helper_bootstrap_sha256": "b" * 64,
    }


def _publish(path: Path, config=None):
    (path / "linux.sh").write_text(
        "#!/bin/sh\nset -eu\n"
        "server=https://commandcore.example.com\n"
        'while [ "$#" -gt 0 ]; do\n'
        'case "$1" in --server) server=$2; shift 2;;'
        " --prepare-full-control) full=yes; shift;; esac\ndone\n"
        'printf \'%s:%s:%s\' "$server" "${full:-no}" '
        '"$COMMANDCORE_HELPER_RELEASE_VERSION"\n'
    )
    if config is not None:
        (path / "linux-onboarding.json").write_text(json.dumps(config))


def test_unpublished_full_control_installer_fails_closed(tmp_path):
    _publish(tmp_path)
    with _client(tmp_path) as client:
        assert client.get("/install/linux-ready").status_code == 503
        assert client.head("/install/linux-ready").status_code == 503
        # Previously published Agent-only installers remain available separately.
        assert client.get("/install/linux").status_code == 200


def test_full_control_installer_injects_public_pins_and_one_command(tmp_path):
    _publish(tmp_path, _config())
    with _client(tmp_path) as client:
        response = client.get("/install/linux-ready")
        assert response.status_code == 200
        assert response.headers["cache-control"] == "no-store"
        assert client.head("/install/linux-ready").status_code == 200
        assert "--prepare-full-control" in response.text
        assert "COMMANDCORE_HELPER_BOOTSTRAP_SHA256" in response.text
        assert "COMMANDCORE_RELEASE_PUBLIC_KEY_B64" in response.text
        result = subprocess.run(
            ["sh"],
            input=response.text,
            text=True,
            capture_output=True,
            timeout=3,
            check=True,
        )
        assert result.stdout == "https://private.example.org:yes:0.9.0-rc7"
        assert "PRIVATE KEY" not in response.text


@pytest.mark.parametrize(
    "mutator",
    [
        lambda d: d.update(server_url="https://example.org/';touch /tmp/hacked;#"),
        lambda d: d.update(helper_release_url="http://unsigned.example.org/helper"),
        lambda d: d.update(helper_public_key_b64="not-base64!"),
        lambda d: d.update(helper_bootstrap_sha256="0"),
        lambda d: d.update(helper_release_version="malicious;command"),
        lambda d: d.update(extra_secret="not allowed"),
    ],
)
def test_invalid_publication_never_returns_executable_script(tmp_path, mutator):
    config = _config()
    mutator(config)
    _publish(tmp_path, config)
    with _client(tmp_path) as client:
        assert client.get("/install/linux-ready").status_code == 503


def test_duplicate_config_fields_rejected(tmp_path):
    _publish(tmp_path, _config())
    config = tmp_path / "linux-onboarding.json"
    config.write_text(config.read_text()[:-1] + ',"server_url":"https://evil.example"}')
    with _client(tmp_path) as client:
        assert client.get("/install/linux-ready").status_code == 503


@pytest.mark.skipif(os.name == "nt", reason="symlink test on Unix")
def test_config_symlinks_are_never_published(tmp_path):
    _publish(tmp_path, _config())
    config = tmp_path / "linux-onboarding.json"
    config.rename(tmp_path / "source.json")
    config.symlink_to(tmp_path / "source.json")
    with _client(tmp_path) as client:
        assert client.get("/install/linux-ready").status_code == 503
