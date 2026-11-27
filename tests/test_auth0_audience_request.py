"""Both provider request dialects use the same verified OAuth audience."""

from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from commandcore_server import onboarding_routes
from commandcore_server.config import Settings
from commandcore_server.db import Database
from commandcore_server.models import Principal


@pytest.mark.parametrize("parameter", [None, "audience", "resource"])
@pytest.mark.parametrize("subject", ["owner", "stranger"])
def test_panel_oauth_provider_syntax_and_owner_boundary(
    tmp_path, monkeypatch, parameter, subject
):
    settings = SimpleNamespace(
        bootstrap_subject="registry",
        enrollment_ttl_seconds=600,
        public_base_url="https://panel.example",
        panel_oauth_client_id="test-client",
        oauth_issuer="https://issuer.example",
        oauth_audience="https://panel.example/api",
        panel_cookie_secure=True,
        panel_cookie_name="panel_session",
        panel_session_ttl_seconds=600,
        session_secret="x" * 32,
        private_owner_subject="owner",
    )
    if parameter is not None:
        settings.panel_oauth_target_parameter = parameter
    expected = parameter or "audience"
    other = "resource" if expected == "audience" else "audience"
    exchanged = []
    verified = []

    class Exchange:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def post(self, url, *, data):
            exchanged.append((url, data))
            return SimpleNamespace(
                raise_for_status=lambda: None,
                json=lambda: {"access_token": "test-token", "expires_in": 600},
            )

    def verify(token):
        verified.append(token)
        return Principal(
            subject,
            "test-client",
            "oauth2",
            ("commandcore:read",),
            settings.oauth_issuer,
        )

    def client_factory(**kwargs):
        assert kwargs["follow_redirects"] is False
        return Exchange()

    monkeypatch.setattr(onboarding_routes.httpx, "AsyncClient", client_factory)
    app = FastAPI()
    db = Database(str(tmp_path / "panel.sqlite3"))
    onboarding_routes.install_routes(
        app,
        db,
        settings,
        lambda: None,
        lambda _: True,
        SimpleNamespace(verify=verify),
        Path(__file__),
        object(),
    )
    client = TestClient(app, base_url=settings.public_base_url, follow_redirects=False)
    # Query parameters cannot replace the server-selected audience or syntax.
    login = client.get("/auth/login?access=standard&audience=wrong&resource=wrong")
    assert login.status_code == 302
    params = parse_qs(urlsplit(login.headers["location"]).query)
    assert params[expected] == [settings.oauth_audience]
    assert other not in params
    assert params["scope"] == ["commandcore:read commandcore:standard"]
    state = params["state"][0]
    result = client.get("/auth/callback", params={"state": state, "code": "test-code"})
    assert len(exchanged) == 1 and verified == ["test-token"]
    url, body = exchanged[0]
    assert url == settings.oauth_issuer + "/oauth/token"
    assert body[expected] == settings.oauth_audience and other not in body
    assert (
        body["code_verifier"]
        and body["redirect_uri"] == settings.public_base_url + "/auth/callback"
    )
    if subject == "owner":
        assert result.status_code == 303
        assert "panel_session=" in result.headers.get("set-cookie", "")
    else:
        assert result.status_code == 403
        assert "panel_session" not in result.cookies
    assert (
        client.get(
            "/auth/callback", params={"state": state, "code": "test-code"}
        ).status_code
        == 400
    )
    assert len(exchanged) == 1


def test_invalid_provider_parameter_is_rejected_at_startup():
    with pytest.raises(RuntimeError, match="TARGET_PARAMETER"):
        Settings(panel_oauth_target_parameter="client_id").validate()
