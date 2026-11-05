"""Fail-closed checks for operator-approved policy pages."""

from fastapi import FastAPI
from fastapi.testclient import TestClient

from commandcore_server.legal_pages import MAX_POLICY_BYTES, install_legal_pages


def client_for(directory: str):
    app = FastAPI()
    install_legal_pages(app, directory)
    return TestClient(app)


def test_unpublished_is_not_invented():
    with client_for("") as client:
        assert client.get("/privacy").status_code == 404
        assert client.get("/terms").status_code == 404


def test_explicitly_published_html(tmp_path):
    (tmp_path / "privacy.html").write_text("<h1>Reviewed privacy policy</h1>")
    (tmp_path / "terms.html").write_text("<h1>Reviewed terms</h1>")
    with client_for(str(tmp_path)) as client:
        for page in ("privacy", "terms"):
            result = client.get("/" + page)
            assert result.status_code == 200
            assert result.headers["content-type"].startswith("text/html")
            assert result.headers["x-content-type-options"] == "nosniff"
            assert result.headers["cache-control"] == "no-cache"
            assert client.head("/" + page).status_code == 200


def test_symlinks_and_unapproved_content_refused(tmp_path):
    (tmp_path / "secret.html").write_text("DO NOT PUBLISH")
    (tmp_path / "privacy.html").symlink_to(tmp_path / "secret.html")
    (tmp_path / "terms.html").write_bytes(b"x" * (MAX_POLICY_BYTES + 1))
    with client_for(str(tmp_path)) as client:
        assert client.get("/privacy").status_code == 404
        assert client.get("/terms").status_code == 404
        assert client.get("/secret.html").status_code == 404


def test_missing_document_does_not_disclose_other_policy(tmp_path):
    (tmp_path / "privacy.html").write_text("Reviewed")
    with client_for(str(tmp_path)) as client:
        assert client.get("/privacy").status_code == 200
        assert client.get("/terms").status_code == 404
