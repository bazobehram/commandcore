from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {
        str(row[1]) for row in conn.execute(f"PRAGMA table_info({table})").fetchall()
    }


def _add_column(conn: sqlite3.Connection, table: str, definition: str) -> None:
    name = definition.split()[0]
    if name not in _columns(conn, table):
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {definition}")


BASELINE_SQL = """
CREATE TABLE IF NOT EXISTS devices (
  id TEXT PRIMARY KEY,
  display_name TEXT NOT NULL,
  hostname TEXT NOT NULL,
  platform TEXT NOT NULL,
  architecture TEXT NOT NULL,
  agent_version TEXT NOT NULL,
  agent_protocol_version TEXT NOT NULL,
  public_key_b64 TEXT NOT NULL,
  device_token_hash TEXT NOT NULL,
  owner_id TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  last_seen REAL,
  capabilities_json TEXT NOT NULL DEFAULT '{}',
  permission_profile TEXT NOT NULL DEFAULT 'STANDARD',
  created_at TEXT NOT NULL,
  approved_at TEXT,
  revoked_at TEXT,
  last_ip TEXT,
  tags_json TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_devices_owner ON devices(owner_id);
CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status);

CREATE TABLE IF NOT EXISTS device_grants (
  device_id TEXT NOT NULL,
  subject TEXT NOT NULL,
  max_permission_profile TEXT NOT NULL DEFAULT 'READ_ONLY',
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL,
  PRIMARY KEY(device_id, subject),
  FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_device_grants_subject ON device_grants(subject);

CREATE TABLE IF NOT EXISTS enrollment_tokens (
  id TEXT PRIMARY KEY,
  token_hash TEXT UNIQUE NOT NULL,
  owner_id TEXT NOT NULL,
  created_at REAL NOT NULL,
  expires_at REAL NOT NULL,
  used_at REAL,
  canceled_at REAL
);

CREATE TABLE IF NOT EXISTS selections (
  id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  created_at REAL NOT NULL,
  expires_at REAL NOT NULL,
  FOREIGN KEY(device_id) REFERENCES devices(id)
);
CREATE INDEX IF NOT EXISTS idx_selections_owner ON selections(owner_id);

CREATE TABLE IF NOT EXISTS jobs (
  execution_id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  tool TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at REAL NOT NULL,
  completed_at REAL,
  exit_code INTEGER,
  error TEXT
);

CREATE TABLE IF NOT EXISTS audit_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp TEXT NOT NULL,
  user_id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  device_id TEXT,
  tool TEXT NOT NULL,
  args_summary TEXT NOT NULL,
  execution_id TEXT,
  status TEXT NOT NULL,
  duration_ms INTEGER NOT NULL,
  exit_code INTEGER,
  risk_class TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_device ON audit_events(device_id);
"""


def migration_001_baseline(conn: sqlite3.Connection) -> None:
    conn.executescript(BASELINE_SQL)
    # v0.1 databases predate enrollment cancellation.
    _add_column(conn, "enrollment_tokens", "canceled_at REAL")


def migration_002_device_key_lifecycle(conn: sqlite3.Connection) -> None:
    _add_column(conn, "devices", "key_generation INTEGER NOT NULL DEFAULT 1")
    _add_column(conn, "devices", "previous_public_key_b64 TEXT")
    _add_column(conn, "devices", "key_rotated_at TEXT")
    _add_column(conn, "devices", "pending_public_key_b64 TEXT")
    _add_column(conn, "devices", "pending_key_rotation_id TEXT")
    _add_column(conn, "devices", "pending_key_expires_at REAL")


def migration_003_fleet_rollouts(conn: sqlite3.Connection) -> None:
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS fleet_rollouts (
      id TEXT PRIMARY KEY,
      owner_id TEXT NOT NULL,
      target_version TEXT NOT NULL,
      manifest_url TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'planned',
      current_ring INTEGER NOT NULL DEFAULT 0,
      stop_on_failure INTEGER NOT NULL DEFAULT 1,
      created_by TEXT NOT NULL,
      created_at REAL NOT NULL,
      updated_at REAL NOT NULL,
      last_error TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_fleet_rollouts_owner ON fleet_rollouts(owner_id, created_at DESC);

    CREATE TABLE IF NOT EXISTS fleet_rollout_devices (
      rollout_id TEXT NOT NULL,
      device_id TEXT NOT NULL,
      ring INTEGER NOT NULL,
      state TEXT NOT NULL DEFAULT 'pending',
      stage_metadata_path TEXT,
      observed_version TEXT,
      last_error TEXT,
      updated_at REAL NOT NULL,
      PRIMARY KEY(rollout_id, device_id),
      FOREIGN KEY(rollout_id) REFERENCES fleet_rollouts(id) ON DELETE CASCADE,
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_fleet_rollout_devices_state ON fleet_rollout_devices(rollout_id, ring, state);

    CREATE TABLE IF NOT EXISTS fleet_rollout_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      rollout_id TEXT NOT NULL,
      device_id TEXT,
      timestamp REAL NOT NULL,
      event TEXT NOT NULL,
      detail_json TEXT NOT NULL DEFAULT '{}',
      FOREIGN KEY(rollout_id) REFERENCES fleet_rollouts(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_fleet_rollout_events_rollout ON fleet_rollout_events(rollout_id, id);
    """)


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    apply: Callable[[sqlite3.Connection], None]


def migration_004_enrollment(conn: sqlite3.Connection) -> None:
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS pending_enrollments (
      id TEXT PRIMARY KEY, view_hash TEXT UNIQUE, poll_hash TEXT UNIQUE,
      code TEXT NOT NULL, public_key_b64 TEXT NOT NULL, metadata_json TEXT NOT NULL,
      created_at REAL NOT NULL, expires_at REAL NOT NULL,
      status TEXT NOT NULL, reviewer TEXT, grant_subject TEXT, device_id TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_pending_enrollment_key ON pending_enrollments(public_key_b64);
    CREATE TABLE IF NOT EXISTS enrollment_limits (
      key TEXT NOT NULL, window INTEGER NOT NULL, count INTEGER NOT NULL,
      PRIMARY KEY(key,window)
    );
    CREATE TABLE IF NOT EXISTS device_managers (
      device_id TEXT NOT NULL, subject TEXT NOT NULL,
      PRIMARY KEY(device_id,subject),
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS panel_login_transactions (
      state_hash TEXT PRIMARY KEY, verifier TEXT NOT NULL, expires_at REAL NOT NULL
    );
    """)


def migration_005_activity(conn: sqlite3.Connection) -> None:
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS activity_events (
      execution_id TEXT PRIMARY KEY, device_id TEXT NOT NULL,
      started_at REAL NOT NULL, event_json TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_activity_device ON activity_events(device_id, started_at DESC);
    """)


MIGRATIONS = (
    Migration(1, "baseline_v0_4_schema", migration_001_baseline),
    Migration(2, "device_key_lifecycle", migration_002_device_key_lifecycle),
    Migration(3, "fleet_rollouts", migration_003_fleet_rollouts),
    Migration(4, "agent_initiated_enrollment", migration_004_enrollment),
    Migration(5, "bounded_safe_activity", migration_005_activity),
)


def migrate(conn: sqlite3.Connection) -> list[int]:
    """Apply explicit, monotonic CommandCore schema migrations.

    The migrations are deliberately idempotent so pre-v0.5 databases that were
    created by the legacy CREATE/ALTER path can be adopted safely. Applied
    versions are persisted in schema_migrations and never silently skipped.
    """
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute(
        """CREATE TABLE IF NOT EXISTS schema_migrations (
        version INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        applied_at TEXT NOT NULL
        )"""
    )
    applied = {
        int(row[0])
        for row in conn.execute("SELECT version FROM schema_migrations").fetchall()
    }
    ran: list[int] = []
    for item in MIGRATIONS:
        if item.version in applied:
            continue
        item.apply(conn)
        conn.execute(
            "INSERT INTO schema_migrations(version,name,applied_at) VALUES(?,?,?)",
            (item.version, item.name, _now_iso()),
        )
        conn.commit()
        ran.append(item.version)
    return ran
