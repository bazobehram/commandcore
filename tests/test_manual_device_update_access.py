"""Ownership and OAuth permission boundaries for per-device Agent updates."""

import importlib

import pytest
from commandcore_server.models import Principal
from fastapi import HTTPException


@pytest.fixture
def server(tmp_path, monkeypatch):
    monkeypatch.setenv("COMMANDCORE_API_TOKEN", "fixture-" + "x" * 40)
    monkeypatch.setenv("COMMANDCORE_PANEL_SESSION_SECRET", "fixture-" + "y" * 40)
    monkeypatch.setenv("COMMANDCORE_DB", str(tmp_path / "server.sqlite3"))
    monkeypatch.setenv("COMMANDCORE_OAUTH_ENABLED", "false")
    from commandcore_server import config

    importlib.reload(config)
    from commandcore_server import main

    importlib.reload(main)
    yield main
    main.db.conn.close()


def principal(subject="owner", scopes=("commandcore:full",)):
    return Principal(subject, "test-client", "oauth2-panel", scopes)


def test_owner_full_scope_can_inspect_own_single_device_rollout(server, monkeypatch):
    monkeypatch.setattr(
        server.db,
        "get_device",
        lambda device_id: {"owner_id": "owner", "revoked_at": None},
    )
    monkeypatch.setattr(
        server.db,
        "get_fleet_rollout",
        lambda owner, rollout: {"devices": [{"device_id": "target"}]},
    )
    result = server._verify_single_device_update(principal(), "target", "rollout")
    assert result["devices"][0]["device_id"] == "target"


def test_scope_without_full_control_cannot_advance(server, monkeypatch):
    monkeypatch.setattr(
        server.db,
        "get_device",
        lambda device_id: {"owner_id": "owner", "revoked_at": None},
    )
    with pytest.raises(HTTPException) as denied:
        server._verify_single_device_update(
            principal(scopes=("commandcore:read",)), "target", "rollout"
        )
    assert denied.value.status_code == 403


def test_rollout_is_bound_to_exact_one_owned_device(server, monkeypatch):
    monkeypatch.setattr(
        server.db,
        "get_device",
        lambda device_id: {"owner_id": "owner", "revoked_at": None},
    )
    monkeypatch.setattr(
        server.db,
        "get_fleet_rollout",
        lambda owner, rollout: {
            "devices": [{"device_id": "target"}, {"device_id": "other"}]
        },
    )
    with pytest.raises(HTTPException) as denied:
        server._verify_single_device_update(principal(), "target", "rollout")
    assert denied.value.status_code == 404
    monkeypatch.setattr(
        server.db,
        "get_fleet_rollout",
        lambda owner, rollout: {"devices": [{"device_id": "other"}]},
    )
    with pytest.raises(HTTPException) as mismatch:
        server._verify_single_device_update(principal(), "target", "rollout")
    assert mismatch.value.status_code == 404


def test_other_owner_cannot_access_update(server, monkeypatch):
    monkeypatch.setattr(
        server.db,
        "get_device",
        lambda device_id: {"owner_id": "someone-else", "revoked_at": None},
    )
    with pytest.raises(HTTPException) as denied:
        server._verify_single_device_update(principal(), "target", "rollout")
    assert denied.value.status_code == 404
