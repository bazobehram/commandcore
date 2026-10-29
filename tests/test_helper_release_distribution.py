"""Published helper distribution serves only scoped immutable public artifacts."""

from fastapi import FastAPI
from fastapi.testclient import TestClient
from commandcore_server.distribution import install_distribution_routes

SCOPE = "v0.9.0-rc7-linux-x86_64-py312"


def client(root):
    app = FastAPI()
    install_distribution_routes(app, str(root))
    return TestClient(app)


def test_signed_helper_assets_are_readonly_and_immutable(tmp_path):
    directory = tmp_path / "helpers" / SCOPE
    directory.mkdir(parents=True)
    for name in (
        "manifest.signed.json",
        "commandcore-helper-linux-x86_64.tar.gz",
        "pip-25.3-py3-none-any.whl",
    ):
        (directory / name).write_bytes(b"test-public-fixture")
    with client(tmp_path) as c:
        for name in (
            "manifest.signed.json",
            "commandcore-helper-linux-x86_64.tar.gz",
            "pip-25.3-py3-none-any.whl",
        ):
            route = "/releases/helper/" + SCOPE + "/" + name
            response = c.get(route)
            assert response.status_code == 200
            assert response.content == b"test-public-fixture"
            assert "immutable" in response.headers["cache-control"]
            assert response.headers["x-content-type-options"] == "nosniff"
            assert c.head(route).status_code == 200
            assert c.post(route).status_code == 405


def test_missing_helper_release_does_not_claim_availability(tmp_path):
    with client(tmp_path) as c:
        assert (
            c.get("/releases/helper/" + SCOPE + "/manifest.signed.json").status_code
            == 404
        )
        assert c.get("/install/linux-ready").status_code == 503


def test_unrelated_files_and_architectures_not_exposed(tmp_path):
    directory = tmp_path / "helpers" / SCOPE
    directory.mkdir(parents=True)
    for name in (
        "secret.txt",
        "commandcore-helper-linux-arm64.tar.gz",
        "double..dot.whl",
    ):
        (directory / name).write_text("private-fixture")
    with client(tmp_path) as c:
        for name in (
            "secret.txt",
            "commandcore-helper-linux-arm64.tar.gz",
            "double..dot.whl",
        ):
            assert c.get("/releases/helper/" + SCOPE + "/" + name).status_code == 404
        assert (
            c.get(
                "/releases/helper/v0.9.0-rc7-linux-arm64-py312/commandcore-helper-linux-x86_64.tar.gz"
            ).status_code
            == 404
        )
        assert c.get("/releases/helper/bad/manifest.signed.json").status_code == 404
        assert c.get("/releases/helper/" + SCOPE + "/../../etc/passwd").status_code in (
            404,
            400,
        )
        assert (
            c.get("/releases/helper/" + SCOPE + "/not-a-wheel.zip").status_code == 404
        )


def test_symlink_not_served(tmp_path):
    directory = tmp_path / "helpers" / SCOPE
    directory.mkdir(parents=True)
    target = tmp_path / "outside"
    target.write_text("secret")
    (directory / "manifest.signed.json").symlink_to(target)
    with client(tmp_path) as c:
        assert (
            c.get("/releases/helper/" + SCOPE + "/manifest.signed.json").status_code
            == 404
        )
