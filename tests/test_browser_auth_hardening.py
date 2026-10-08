import importlib
from dataclasses import replace

import pytest
from commandcore_server.auth import ALL_SCOPES
from commandcore_server.models import Principal
from commandcore_server.security import issue_panel_session
from fastapi.testclient import TestClient
from starlette.requests import Request


@pytest.fixture
def server(tmp_path, monkeypatch):
    # Import the application only against an isolated database and fixture keys.
    monkeypatch.setenv("COMMANDCORE_API_TOKEN", "fixture-bootstrap-" + "x" * 40)
    monkeypatch.setenv("COMMANDCORE_PANEL_SESSION_SECRET", "fixture-panel-" + "y" * 40)
    monkeypatch.setenv("COMMANDCORE_DB", str(tmp_path / "server.sqlite3"))
    monkeypatch.setenv("COMMANDCORE_OAUTH_ENABLED", "false")
    from commandcore_server import config

    importlib.reload(config)
    from commandcore_server import main

    importlib.reload(main)
    monkeypatch.setattr(
        main,
        "settings",
        replace(
            main.settings,
            public_base_url="https://panel.example",
            public_bootstrap_enabled=False,
            panel_session_secret="fixture-panel-" + "y" * 40,
            recovery_enabled=True,
            oauth_algorithms=("RS256",),
        ),
    )
    yield main
    main.db.conn.close()


def test_bootstrap_disabled_and_oauth_remains_available(server, monkeypatch):
    assert server._authenticate_bearer(server.settings.api_token) is None
    expected = Principal("operator", "fixture", "oauth2", ALL_SCOPES)

    class Verifier:
        def verify(self, token):
            assert token == "oauth-fixture"
            return expected

    monkeypatch.setattr(server, "oauth_verifier", Verifier())
    assert server._authenticate_bearer("oauth-fixture") == expected


def test_branding_assets_are_public_and_versioned(server):
    from commandcore_server.web_assets import web_asset

    with TestClient(server.app) as client:
        for name in ("commandcore-icon.png", "commandcore-wordmark.png"):
            response = client.get("/" + name)
            assert response.status_code == 200
            assert response.headers["content-type"] == "image/png"
            assert response.content == web_asset(name).read_bytes()
        html = client.get("/").text
        assert 'href="/commandcore-icon.png?v=' in html
        assert 'src="/commandcore-wordmark.png?v=' in html
        version = html.split("/commandcore-icon.png?v=")[1].split('"')[0]
        assert server.mcp.icons == server.core_mcp.icons
        assert server.mcp.icons[0]["src"].endswith("/commandcore-icon.png?v=" + version)


@pytest.mark.parametrize(
    "headers,allowed",
    [
        ({}, False),
        ({"origin": "null"}, False),
        ({"origin": "https://evil.example"}, False),
        ({"origin": "https://panel.example/path"}, False),
        ({"origin": "https://panel.example", "sec-fetch-site": "cross-site"}, False),
        ({"origin": "https://panel.example"}, True),
        ({"sec-fetch-site": "same-origin"}, True),
        ({"sec-fetch-site": "none"}, False),
        ({"host": "evil.example", "origin": "https://evil.example"}, False),
    ],
)
def test_exact_origin_evidence(server, headers, allowed):
    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/api/session",
            "headers": [(k.encode(), v.encode()) for k, v in headers.items()],
        }
    )
    assert server._same_origin(request) is allowed


@pytest.mark.parametrize("kind", ["panel-cookie", "oauth2-panel"])
def test_cookie_mutations_missing_origin_denied(server, kind):
    token = issue_panel_session(
        secret=server.settings.session_secret,
        subject="operator",
        ttl_seconds=600,
        auth_kind=kind,
        scopes=ALL_SCOPES,
    )
    with TestClient(server.app, base_url="https://panel.example") as client:
        client.cookies.set(server.settings.panel_cookie_name, token)
        assert client.post("/api/enrollment-tokens").status_code == 403
        assert (
            client.post(
                "/api/enrollment-tokens", headers={"origin": "https://panel.example"}
            ).status_code
            == 200
        )
        assert client.get("/api/session").status_code == 200


def test_recovery_is_loopback_only_and_security_headers(server):
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    auth = {"authorization": "Bearer " + server.settings.api_token}
    with TestClient(server.app, client=("127.0.0.1", 2345)) as client:
        response = client.post("/recovery/mcp", headers=auth, json=body)
        assert response.status_code == 200
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["x-content-type-options"] == "nosniff"
        assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
        assert "max-age=" in response.headers["strict-transport-security"]
        assert client.post("/mcp", headers=auth, json=body).status_code == 401
        assert (
            client.post(
                "/api/session", json={"token": server.settings.api_token}
            ).status_code
            == 401
        )
    with TestClient(server.app, client=("203.0.113.1", 2345)) as client:
        assert (
            client.post(
                "/recovery/mcp",
                headers={**auth, "x-forwarded-for": "127.0.0.1"},
                json=body,
            ).status_code
            == 401
        )
    server.settings = replace(server.settings, recovery_enabled=False)
    with TestClient(server.app, client=("127.0.0.1", 2345)) as client:
        assert client.post("/recovery/mcp", headers=auth, json=body).status_code == 401


def test_hardened_mode_requires_independent_panel_secret():
    from commandcore_server.config import Settings

    with pytest.raises(RuntimeError, match="separate panel"):
        Settings(
            api_token="x" * 40, public_bootstrap_enabled=False, panel_session_secret=""
        ).validate()


def test_external_panel_assets_keep_mime_under_strict_csp(server):
    with TestClient(server.app) as client:
        for name in ("panel", "onboarding", "legacy-admin"):
            for extension, kind in (
                ("js", "application/javascript"),
                ("css", "text/css"),
            ):
                response = client.get(f"/{name}.{extension}")
                assert response.status_code == 200
                assert response.headers["content-type"].startswith(kind)
                assert response.headers["x-content-type-options"] == "nosniff"
                assert (
                    "'unsafe-inline'" not in response.headers["content-security-policy"]
                )


def test_html_uses_asset_content_identity_and_sensitive_no_store(server):
    import hashlib

    from commandcore_server.web_assets import web_asset

    with TestClient(server.app) as client:
        for page, asset in (("/", "panel.js"), ("/enroll/", "onboarding.js")):
            response = client.get(page)
            digest = hashlib.sha256(web_asset(asset).read_bytes()).hexdigest()[:16]
            assert f"/{asset}?v={digest}" in response.text
            assert response.headers["cache-control"] == "no-store"


def test_official_logo_is_served_as_local_asset(server):
    from commandcore_server.web_assets import web_asset

    with TestClient(server.app) as client:
        response = client.get("/commandcore-logo.webp")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("image/webp")
        assert response.headers["cache-control"] == "public, max-age=86400"
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.content == web_asset("commandcore-logo.webp").read_bytes()
