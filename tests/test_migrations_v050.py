from __future__ import annotations

import sqlite3

from commandcore_server.db import Database


LEGACY_V04 = """
CREATE TABLE devices (
  id TEXT PRIMARY KEY, display_name TEXT NOT NULL, hostname TEXT NOT NULL,
  platform TEXT NOT NULL, architecture TEXT NOT NULL, agent_version TEXT NOT NULL,
  agent_protocol_version TEXT NOT NULL, public_key_b64 TEXT NOT NULL,
  device_token_hash TEXT NOT NULL, owner_id TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending', last_seen REAL,
  capabilities_json TEXT NOT NULL DEFAULT '{}', permission_profile TEXT NOT NULL DEFAULT 'STANDARD',
  created_at TEXT NOT NULL, approved_at TEXT, revoked_at TEXT, last_ip TEXT,
  tags_json TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE enrollment_tokens (
  id TEXT PRIMARY KEY, token_hash TEXT UNIQUE NOT NULL, owner_id TEXT NOT NULL,
  created_at REAL NOT NULL, expires_at REAL NOT NULL, used_at REAL, canceled_at REAL
);
"""


def test_v04_database_is_adopted_by_numbered_migrations(tmp_path):
    path = tmp_path / "legacy.sqlite3"
    conn = sqlite3.connect(path)
    conn.executescript(LEGACY_V04)
    conn.execute(
        "INSERT INTO devices VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            "d1",
            "legacy",
            "legacy",
            "Linux",
            "x86_64",
            "0.4.0",
            "1",
            "AAAA",
            "hash",
            "owner",
            "offline",
            None,
            "{}",
            "STANDARD",
            "2026-09-29T00:00:00+00:00",
            "2026-09-29T00:00:00+00:00",
            None,
            None,
            "[]",
        ),
    )
    conn.commit()
    conn.close()

    db = Database(str(path))
    versions = [
        r["version"]
        for r in db.conn.execute(
            "SELECT version FROM schema_migrations ORDER BY version"
        )
    ]
    assert versions == [1, 2, 3, 4, 5, 6]
    device = db.get_device("d1")
    assert device is not None
    assert device["key_generation"] == 1
    assert device["key_rotation_pending"] is False


def test_fresh_database_reports_current_migration_version(tmp_path):
    db = Database(str(tmp_path / "fresh.sqlite3"))
    row = db.conn.execute("SELECT MAX(version) AS v FROM schema_migrations").fetchone()
    assert row["v"] == 6


def test_legacy_enrollment_records_are_standard_on_migration(tmp_path):
    from commandcore_server.migrations import (
        migration_006_initial_permission_preference,
    )

    db = Database(str(tmp_path / "existing.sqlite3"))
    db.conn.execute(
        "INSERT INTO pending_enrollments (id,view_hash,poll_hash,code,public_key_b64,metadata_json,created_at,expires_at,status) "
        "VALUES ('old','view','poll','AAAA-AAAA','test-key','{}',0,9999999999,'consumed')"
    )
    db.conn.commit()
    migration_006_initial_permission_preference(db.conn)
    row = db.conn.execute(
        "SELECT desired_initial_profile FROM pending_enrollments WHERE id='old'"
    ).fetchone()
    assert row[0] == "STANDARD"
