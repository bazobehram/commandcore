"""Private-owner checks preserve public defaults and protect signed sessions."""

from __future__ import annotations

import os
import subprocess
import sys

import pytest

from commandcore_server.config import Settings
from commandcore_server.private_owner import owner_allowed


def test_owner_match_and_default_multi_user():
    assert owner_allowed("", "alice")
    assert owner_allowed("", "bob")
    assert owner_allowed("alice", "alice")
    assert not owner_allowed("alice", "bob")
    assert not owner_allowed("alice", "")


def test_private_mode_requires_oauth_and_no_bootstrap():
    with pytest.raises(RuntimeError, match="requires OAuth"):
        Settings(
            api_token="x" * 32, private_owner_subject="alice", oauth_enabled=False
        ).validate()
    with pytest.raises(RuntimeError, match="disabled public bootstrap"):
        Settings(
            api_token="x" * 32,
            private_owner_subject="alice",
            oauth_enabled=True,
            public_bootstrap_enabled=True,
        ).validate()
    with pytest.raises(RuntimeError, match="single exact"):
        Settings(
            api_token="x" * 32, private_owner_subject="alice bob", oauth_enabled=True
        ).validate()


def test_bearer_and_cookie_owner_boundaries_in_isolated_server(tmp_path):
    # main.py initializes the runtime on import. Keep this test in a subprocess
    # so pytest's shared module state and live instances remain unaffected.
    script = """
from types import SimpleNamespace
from fastapi import HTTPException
from starlette.requests import Request
from commandcore_server.models import Principal
from commandcore_server.security import issue_panel_session
import importlib

main = importlib.import_module("commandcore_server.main")

def principal(sub):
    return Principal(sub, "fixture-client", "oauth2", ("commandcore:read", "commandcore:full"), "https://issuer.invalid/")

main.oauth_verifier = SimpleNamespace(verify=lambda token: principal(token))
main.settings = SimpleNamespace(
    api_token="fixture-" + "x" * 32,
    public_bootstrap_enabled=False,
    private_owner_subject="alice",
    panel_cookie_name="commandcore_session",
    session_secret="fixture-" + "y" * 32,
    oauth_issuer="https://issuer.invalid/",
)
assert main._authenticate_bearer("alice").subject == "alice"
assert main._authenticate_bearer("bob") is None

def request_for(sub):
    cookie = issue_panel_session(
        secret=main.settings.session_secret,
        subject=sub,
        ttl_seconds=180,
        scopes=("commandcore:read", "commandcore:full"),
        auth_kind="oauth2-panel",
    )
    return Request({
        "type": "http",
        "method": "GET",
        "path": "/api/session",
        "scheme": "https",
        "headers": [
            (b"host", b"private.invalid"),
            (b"cookie", ("commandcore_session=" + cookie).encode()),
        ],
        "server": ("private.invalid", 443),
    })

assert main.require_principal(request_for("alice"), None, None).subject == "alice"
try:
    main.require_principal(request_for("bob"), None, None)
    raise AssertionError("foreign panel session was accepted")
except HTTPException as error:
    assert error.status_code == 403

main.settings.private_owner_subject = ""
assert main._authenticate_bearer("bob").subject == "bob"
"""
    env = os.environ.copy()
    env.update(
        {
            "COMMANDCORE_API_TOKEN": "test-" + "t" * 32,
            "COMMANDCORE_PANEL_SESSION_SECRET": "test-" + "s" * 32,
            "COMMANDCORE_DB": str(tmp_path / "isolated.sqlite3"),
            "COMMANDCORE_OAUTH_ENABLED": "false",
            "COMMANDCORE_PUBLIC_BOOTSTRAP_ENABLED": "false",
            "COMMANDCORE_BROWSER_ENABLED": "false",
        }
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        env=env,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert result.returncode == 0, result.stderr
