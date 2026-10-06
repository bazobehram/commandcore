from __future__ import annotations

import time

import pytest

from commandcore_server.db import Database
from commandcore_server.security import audit_summary


def test_enrollment_token_is_single_use(tmp_path):
    db = Database(str(tmp_path / "db.sqlite3"))
    item = db.create_enrollment_token("owner-a", 60)
    assert db.consume_enrollment_token(item["token"]) == "owner-a"
    assert db.consume_enrollment_token(item["token"]) is None


def test_expired_enrollment_token_fails(tmp_path):
    db = Database(str(tmp_path / "db.sqlite3"))
    item = db.create_enrollment_token("owner-a", -1)
    assert db.consume_enrollment_token(item["token"]) is None


def _device(db: Database, owner="owner-a"):
    return db.register_device(
        owner_id=owner,
        display_name="test",
        hostname="test",
        platform="Linux",
        architecture="x86_64",
        agent_version="0.1.0",
        agent_protocol_version="1",
        public_key_b64="AAAA",
        capabilities={"filesystem": True, "privileged_helper": False},
        auto_approve=True,
    )


def test_selection_is_owner_scoped(tmp_path):
    db = Database(str(tmp_path / "db.sqlite3"))
    d = _device(db)
    s = db.create_selection("owner-a", d["device_id"], 60)
    assert db.resolve_selection("owner-a", s["selection_id"]) == d["device_id"]
    with pytest.raises(KeyError):
        db.resolve_selection("owner-b", s["selection_id"])


def test_full_control_requires_helper(tmp_path):
    db = Database(str(tmp_path / "db.sqlite3"))
    d = _device(db)
    with pytest.raises(RuntimeError, match="full_control_requires_privileged_helper"):
        db.set_permission("owner-a", d["device_id"], "FULL_CONTROL")


def test_audit_redacts_secret_fields():
    text = audit_summary(
        {"path": "/tmp/a", "password": "secret", "nested": {"api_token": "abc"}}
    )
    assert "secret" not in text
    assert "abc" not in text
    assert "<redacted>" in text


def test_revoked_device_cannot_resolve(tmp_path):
    db = Database(str(tmp_path / "db.sqlite3"))
    d = _device(db)
    assert db.revoke_device("owner-a", d["device_id"])
    with pytest.raises(PermissionError):
        db.resolve_device("owner-a", d["device_id"])


def test_wrong_owner_cannot_resolve_device(tmp_path):
    db = Database(str(tmp_path / "db.sqlite3"))
    d = _device(db, owner="owner-a")
    with pytest.raises(KeyError):
        db.resolve_device("owner-b", d["device_id"])


def test_heartbeat_expiration_marks_offline(tmp_path):
    db = Database(str(tmp_path / "db.sqlite3"))
    d = _device(db)
    db.mark_online(
        d["device_id"],
        ip="127.0.0.1",
        agent_version="0.1.0",
        capabilities={},
        agent_protocol_version="1",
    )
    assert db.get_device(d["device_id"])["status"] == "online"
    assert db.expire_stale_devices(time.time() + 1) == 1
    assert db.get_device(d["device_id"])["status"] == "offline"


def test_enrollment_token_is_cli_safe(tmp_path):
    db = Database(str(tmp_path / "db.sqlite3"))
    token = db.create_enrollment_token("owner", 60)["token"]
    assert token.startswith("ccenr_")
    assert not token.startswith("-")
