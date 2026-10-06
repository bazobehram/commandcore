import os

import pytest
from commandcore_server.distribution import install_distribution_routes
from fastapi import FastAPI
from fastapi.testclient import TestClient


def test_public_distribution_is_limited_to_published_files(tmp_path):
    (tmp_path / "linux.sh").write_text("#!/bin/sh\necho reviewed\n")
    (tmp_path / "uninstall-linux.sh").write_text("#!/bin/sh\necho uninstall\n")
    (tmp_path / "windows.ps1").write_text("Write-Output reviewed\n")
    (tmp_path / "uninstall-windows.ps1").write_text("Write-Output uninstall\n")
    (tmp_path / "manifest.json").write_text('{"signature":"fixture"}')
    release = tmp_path / "0.9.0-rc2"
    release.mkdir()
    (release / "commandcore-agent-linux-x86_64").write_bytes(b"fixture")
    (release / "commandcore-agent-windows-x86_64.exe").write_bytes(b"windows-fixture")
    (tmp_path / ".env").write_text("SECRET=not-public")
    app = FastAPI()
    install_distribution_routes(app, str(tmp_path))
    with TestClient(app) as client:
        script = client.get("/install/linux")
        assert script.status_code == 200
        assert script.headers["content-type"].startswith("text/x-shellscript")
        assert script.headers["x-content-type-options"] == "nosniff"
        assert client.head("/install/linux").status_code == 200
        assert client.get("/install/uninstall-linux").status_code == 200
        windows = client.get("/install/windows")
        assert windows.status_code == 200
        assert windows.headers["content-type"].startswith("text/plain")
        assert client.head("/install/windows").status_code == 200
        assert client.get("/install/uninstall-windows").status_code == 200
        assert (
            client.get(
                "/releases/agent/0.9.0-rc2/commandcore-agent-windows-x86_64.exe"
            ).content
            == b"windows-fixture"
        )
        assert client.get("/releases/agent/manifest.json").status_code == 200
        artifact = client.get(
            "/releases/agent/0.9.0-rc2/commandcore-agent-linux-x86_64"
        )
        assert artifact.content == b"fixture"
        assert "immutable" in artifact.headers["cache-control"]
        for path in [
            "/releases/agent/0.9.0-rc2/.env",
            "/releases/agent/0.9.0-rc2/linux.sh",
            "/releases/agent/0.9.0-rc2",
            "/releases/agent/%2e%2e/.env",
        ]:
            assert client.get(path).status_code == 404


@pytest.mark.skipif(
    os.name == "nt", reason="Linux symlink gate; Windows symlink privilege unavailable"
)
def test_distribution_rejects_symlinks(tmp_path):
    release = tmp_path / "0.9.0-rc2"
    release.mkdir()
    (tmp_path / ".env").write_text("SECRET=not-public")
    (release / "commandcore-agent-linux-x86_64").symlink_to(tmp_path / ".env")
    app = FastAPI()
    install_distribution_routes(app, str(tmp_path))
    with TestClient(app) as client:
        assert (
            client.get(
                "/releases/agent/0.9.0-rc2/commandcore-agent-linux-x86_64"
            ).status_code
            == 404
        )


def test_distribution_unpublished_by_default():
    app = FastAPI()
    install_distribution_routes(app, "")
    with TestClient(app) as client:
        assert client.get("/install/linux").status_code == 404
        assert client.get("/install/windows").status_code == 404
