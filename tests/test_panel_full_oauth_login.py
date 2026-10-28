"""Panel requests full scope by default, retaining explicit standard-only login."""

from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

from fastapi import FastAPI
from fastapi.testclient import TestClient

from commandcore_server.db import Database
from commandcore_server.onboarding_routes import install_routes


def test_oauth_login_requests_full_by_default_and_supports_standard(tmp_path):
    app = FastAPI()
    db = Database(str(tmp_path / "panel.sqlite3"))
    settings = SimpleNamespace(
        bootstrap_subject="registry",
        enrollment_ttl_seconds=600,
        public_base_url="https://panel.example",
        panel_oauth_client_id="test-client",
        oauth_issuer="https://issuer.example",
        oauth_audience="https://panel.example/api",
        panel_cookie_secure=True,
    )
    install_routes(
        app,
        db,
        settings,
        lambda: None,
        lambda _: True,
        object(),
        Path(__file__),
        object(),
    )
    client = TestClient(app, base_url="https://panel.example", follow_redirects=False)
    standard = client.get("/auth/login?access=standard")
    assert standard.status_code == 302
    std_params = parse_qs(urlsplit(standard.headers["location"]).query)
    assert std_params["scope"] == ["commandcore:read commandcore:standard"]
    full = client.get("/auth/login")
    assert full.status_code == 302
    full_params = parse_qs(urlsplit(full.headers["location"]).query)
    assert full_params["scope"] == [
        "commandcore:read commandcore:standard commandcore:full"
    ]
    assert full_params["state"] != std_params["state"]
    typo = client.get("/auth/login?access=invalid")
    assert (
        parse_qs(urlsplit(typo.headers["location"]).query)["scope"]
        == full_params["scope"]
    )
