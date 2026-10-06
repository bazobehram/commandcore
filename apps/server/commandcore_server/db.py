from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .security import new_token, token_hash
from .migrations import migrate

PROFILE_RANK = {"READ_ONLY": 0, "STANDARD": 1, "FULL_CONTROL": 2}


def local_max_profile(capabilities: dict[str, Any]) -> str:
    value = str(capabilities.get("local_max_permission_profile", "STANDARD")).upper()
    if value not in PROFILE_RANK:
        value = "STANDARD"
    if value == "FULL_CONTROL" and not bool(
        capabilities.get("privileged_helper", False)
    ):
        return "STANDARD"
    return value


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class Database:
    def __init__(self, path: str):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        self._migrate()
        self.recover_incomplete_jobs()

    def _migrate(self) -> None:
        with self.lock:
            migrate(self.conn)

    def save_activity(self, event: dict[str, Any]) -> None:
        with self.lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO activity_events VALUES(?,?,?,?)",
                (
                    event["execution_id"],
                    event["device_id"],
                    event["started_at"],
                    json.dumps(event, separators=(",", ":")),
                ),
            )
            self.conn.execute(
                "DELETE FROM activity_events WHERE started_at < ?",
                (time.time() - 30 * 86400,),
            )
            self.conn.execute(
                "DELETE FROM activity_events WHERE execution_id NOT IN (SELECT execution_id FROM activity_events ORDER BY started_at DESC LIMIT 10000)"
            )
            self.conn.commit()

    def list_activity(self, device_id: str, limit: int = 100) -> list[dict[str, Any]]:
        with self.lock:
            rows = self.conn.execute(
                "SELECT event_json FROM activity_events WHERE device_id=? ORDER BY started_at DESC LIMIT ?",
                (device_id, max(1, min(limit, 250))),
            ).fetchall()
        return [json.loads(row[0]) for row in rows]

    def create_enrollment_token(
        self, owner_id: str, ttl_seconds: int
    ) -> dict[str, Any]:
        # Prefix avoids a URL-safe token beginning with '-' being interpreted
        # as an argparse option by `commandcore-agent enroll <token>`.
        raw = "ccenr_" + new_token(32)
        token_id = str(uuid.uuid4())
        now = time.time()
        with self.lock:
            self.conn.execute(
                "INSERT INTO enrollment_tokens(id, token_hash, owner_id, created_at, expires_at) VALUES(?,?,?,?,?)",
                (token_id, token_hash(raw), owner_id, now, now + ttl_seconds),
            )
            self.conn.commit()
        return {"id": token_id, "token": raw, "expires_at": now + ttl_seconds}

    def consume_enrollment_token(self, raw: str) -> str | None:
        digest = token_hash(raw)
        now = time.time()
        with self.lock:
            self.conn.execute("BEGIN IMMEDIATE")
            row = self.conn.execute(
                "SELECT * FROM enrollment_tokens WHERE token_hash=?", (digest,)
            ).fetchone()
            if (
                not row
                or row["used_at"] is not None
                or row["canceled_at"] is not None
                or row["expires_at"] < now
            ):
                self.conn.rollback()
                return None
            self.conn.execute(
                "UPDATE enrollment_tokens SET used_at=? WHERE id=?", (now, row["id"])
            )
            self.conn.commit()
            return str(row["owner_id"])

    def list_enrollment_tokens(
        self, owner_id: str, limit: int = 50
    ) -> list[dict[str, Any]]:
        now = time.time()
        with self.lock:
            rows = self.conn.execute(
                "SELECT id,created_at,expires_at,used_at,canceled_at FROM enrollment_tokens WHERE owner_id=? ORDER BY created_at DESC LIMIT ?",
                (owner_id, limit),
            ).fetchall()
        out: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            if item["used_at"] is not None:
                item["status"] = "used"
            elif item["canceled_at"] is not None:
                item["status"] = "canceled"
            elif item["expires_at"] < now:
                item["status"] = "expired"
            else:
                item["status"] = "active"
            out.append(item)
        return out

    def cancel_enrollment_token(self, owner_id: str, token_id: str) -> bool:
        now = time.time()
        with self.lock:
            cur = self.conn.execute(
                "UPDATE enrollment_tokens SET canceled_at=? WHERE id=? AND owner_id=? AND used_at IS NULL AND canceled_at IS NULL AND expires_at>=?",
                (now, token_id, owner_id, now),
            )
            self.conn.commit()
            return cur.rowcount == 1

    def register_device(
        self,
        *,
        owner_id: str,
        display_name: str,
        hostname: str,
        platform: str,
        architecture: str,
        agent_version: str,
        agent_protocol_version: str,
        public_key_b64: str,
        capabilities: dict[str, Any],
        auto_approve: bool = False,
    ) -> dict[str, Any]:
        device_id = str(uuid.uuid4())
        raw_device_token = new_token(40)
        created = now_iso()
        status = "offline" if auto_approve else "pending"
        approved_at = created if auto_approve else None
        with self.lock:
            self.conn.execute(
                """INSERT INTO devices(id,display_name,hostname,platform,architecture,agent_version,
                agent_protocol_version,public_key_b64,device_token_hash,owner_id,status,last_seen,
                capabilities_json,permission_profile,created_at,approved_at,tags_json)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    device_id,
                    display_name,
                    hostname,
                    platform,
                    architecture,
                    agent_version,
                    agent_protocol_version,
                    public_key_b64,
                    token_hash(raw_device_token),
                    owner_id,
                    status,
                    None,
                    json.dumps(capabilities),
                    "STANDARD",
                    created,
                    approved_at,
                    "[]",
                ),
            )
            self.conn.commit()
        return {
            "device_id": device_id,
            "device_token": raw_device_token,
            "status": status,
        }

    @staticmethod
    def _device(row: sqlite3.Row | None) -> dict[str, Any] | None:
        if not row:
            return None
        d = dict(row)
        d["capabilities"] = json.loads(d.pop("capabilities_json") or "{}")
        d["tags"] = json.loads(d.pop("tags_json") or "[]")
        d.pop("device_token_hash", None)
        d["key_rotation_pending"] = (
            bool(d.get("pending_key_rotation_id"))
            and float(d.get("pending_key_expires_at") or 0) >= time.time()
        )
        # Pending rotation identifiers/keys are internal protocol state, not
        # device-list metadata. Public clients only need generation/status.
        d.pop("pending_public_key_b64", None)
        d.pop("pending_key_rotation_id", None)
        d.pop("pending_key_expires_at", None)
        d.pop("previous_public_key_b64", None)
        return d

    def get_device(self, device_id: str) -> dict[str, Any] | None:
        with self.lock:
            return self._device(
                self.conn.execute(
                    "SELECT * FROM devices WHERE id=?", (device_id,)
                ).fetchone()
            )

    def get_device_auth_row(self, device_id: str) -> dict[str, Any] | None:
        with self.lock:
            row = self.conn.execute(
                "SELECT * FROM devices WHERE id=?", (device_id,)
            ).fetchone()
            return dict(row) if row else None

    def list_devices(self, owner_id: str) -> list[dict[str, Any]]:
        with self.lock:
            rows = self.conn.execute(
                "SELECT * FROM devices WHERE owner_id=? ORDER BY created_at",
                (owner_id,),
            ).fetchall()
        return [self._device(r) for r in rows if r is not None]

    def get_accessible_device(
        self, subject: str, device_id: str
    ) -> dict[str, Any] | None:
        """Return a device visible to subject plus the grant ceiling used for execution."""
        with self.lock:
            row = self.conn.execute(
                """SELECT d.*, g.max_permission_profile AS grant_max_permission_profile
                   FROM devices d
                   LEFT JOIN device_grants g ON g.device_id=d.id AND g.subject=?
                   WHERE d.id=? AND (d.owner_id=? OR g.subject IS NOT NULL)""",
                (subject, device_id, subject),
            ).fetchone()
        if not row:
            return None
        device = self._device(row)
        assert device is not None
        is_owner = device["owner_id"] == subject
        grant_max = (
            "FULL_CONTROL"
            if is_owner
            else str(
                device.pop("grant_max_permission_profile", "READ_ONLY") or "READ_ONLY"
            )
        )
        device.pop("grant_max_permission_profile", None)
        device["access_max_permission_profile"] = grant_max
        device["is_owner"] = is_owner
        return device

    def list_accessible_devices(self, subject: str) -> list[dict[str, Any]]:
        with self.lock:
            rows = self.conn.execute(
                """SELECT d.*, g.max_permission_profile AS grant_max_permission_profile
                   FROM devices d
                   LEFT JOIN device_grants g ON g.device_id=d.id AND g.subject=?
                   WHERE d.owner_id=? OR g.subject IS NOT NULL
                   ORDER BY d.created_at""",
                (subject, subject),
            ).fetchall()
        out: list[dict[str, Any]] = []
        for row in rows:
            device = self._device(row)
            if device is None:
                continue
            is_owner = device["owner_id"] == subject
            grant_max = (
                "FULL_CONTROL"
                if is_owner
                else str(
                    device.pop("grant_max_permission_profile", "READ_ONLY")
                    or "READ_ONLY"
                )
            )
            device.pop("grant_max_permission_profile", None)
            device["access_max_permission_profile"] = grant_max
            device["is_owner"] = is_owner
            out.append(device)
        return out

    def resolve_accessible_device(self, subject: str, ref: str) -> dict[str, Any]:
        candidates = self.list_accessible_devices(subject)
        exact_id = [d for d in candidates if d["id"] == ref]
        matches = exact_id or [
            d for d in candidates if d["display_name"] == ref or d["hostname"] == ref
        ]
        if not matches:
            raise KeyError("device_not_found")
        if len(matches) > 1:
            raise ValueError("ambiguous_device_name")
        device = matches[0]
        if device["revoked_at"]:
            raise PermissionError("device_revoked")
        return device

    def upsert_device_grant(
        self,
        owner_id: str,
        device_id: str,
        subject: str,
        max_permission_profile: str,
        created_by: str,
    ) -> bool:
        profile = max_permission_profile.upper()
        if profile not in PROFILE_RANK:
            raise ValueError("invalid_permission_profile")
        if not subject or subject == owner_id:
            raise ValueError("grant_subject_must_be_non_owner")
        with self.lock:
            row = self.conn.execute(
                "SELECT owner_id,revoked_at FROM devices WHERE id=?", (device_id,)
            ).fetchone()
            if not row or row["owner_id"] != owner_id or row["revoked_at"]:
                return False
            self.conn.execute(
                """INSERT INTO device_grants(device_id,subject,max_permission_profile,created_at,created_by)
                   VALUES(?,?,?,?,?)
                   ON CONFLICT(device_id,subject) DO UPDATE SET
                     max_permission_profile=excluded.max_permission_profile,
                     created_at=excluded.created_at,
                     created_by=excluded.created_by""",
                (device_id, subject, profile, now_iso(), created_by),
            )
            self.conn.commit()
            return True

    def revoke_device_grant(self, owner_id: str, device_id: str, subject: str) -> bool:
        with self.lock:
            cur = self.conn.execute(
                """DELETE FROM device_grants
                   WHERE device_id=? AND subject=?
                   AND EXISTS(SELECT 1 FROM devices d WHERE d.id=device_grants.device_id AND d.owner_id=?)""",
                (device_id, subject, owner_id),
            )
            self.conn.commit()
            return cur.rowcount == 1

    def list_device_grants(self, owner_id: str, device_id: str) -> list[dict[str, Any]]:
        with self.lock:
            owner = self.conn.execute(
                "SELECT 1 FROM devices WHERE id=? AND owner_id=?", (device_id, owner_id)
            ).fetchone()
            if not owner:
                return []
            rows = self.conn.execute(
                "SELECT subject,max_permission_profile,created_at,created_by FROM device_grants WHERE device_id=? ORDER BY subject",
                (device_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    def resolve_device(self, owner_id: str, ref: str) -> dict[str, Any]:
        with self.lock:
            exact = self.conn.execute(
                "SELECT * FROM devices WHERE owner_id=? AND id=?", (owner_id, ref)
            ).fetchall()
            if not exact:
                exact = self.conn.execute(
                    "SELECT * FROM devices WHERE owner_id=? AND (display_name=? OR hostname=?)",
                    (owner_id, ref, ref),
                ).fetchall()
        if not exact:
            raise KeyError("device_not_found")
        if len(exact) > 1:
            raise ValueError("ambiguous_device_name")
        device = self._device(exact[0])
        assert device is not None
        if device["revoked_at"]:
            raise PermissionError("device_revoked")
        return device

    def update_device_metadata(
        self,
        owner_id: str,
        device_id: str,
        *,
        display_name: str | None = None,
        tags: list[str] | None = None,
    ) -> bool:
        device = self.get_device(device_id)
        if not device or device["owner_id"] != owner_id or device["revoked_at"]:
            return False
        updates: list[str] = []
        values: list[Any] = []
        if display_name is not None:
            name = display_name.strip()
            if not name or len(name) > 120:
                raise ValueError("invalid_display_name")
            updates.append("display_name=?")
            values.append(name)
        if tags is not None:
            clean = []
            seen = set()
            for tag in tags:
                value = str(tag).strip()
                if not value or len(value) > 40 or value in seen:
                    continue
                seen.add(value)
                clean.append(value)
                if len(clean) >= 20:
                    break
            updates.append("tags_json=?")
            values.append(json.dumps(clean))
        if not updates:
            return True
        values.extend([device_id, owner_id])
        with self.lock:
            cur = self.conn.execute(
                f"UPDATE devices SET {', '.join(updates)} WHERE id=? AND owner_id=? AND revoked_at IS NULL",
                values,
            )
            self.conn.commit()
            return cur.rowcount == 1

    def approve_device(self, owner_id: str, device_id: str) -> bool:
        with self.lock:
            cur = self.conn.execute(
                "UPDATE devices SET status='offline', approved_at=? WHERE id=? AND owner_id=? AND revoked_at IS NULL AND approved_at IS NULL",
                (now_iso(), device_id, owner_id),
            )
            self.conn.commit()
            return cur.rowcount == 1

    def revoke_device(self, owner_id: str, device_id: str) -> bool:
        with self.lock:
            cur = self.conn.execute(
                "UPDATE devices SET status='revoked', revoked_at=? WHERE id=? AND owner_id=? AND revoked_at IS NULL",
                (now_iso(), device_id, owner_id),
            )
            self.conn.commit()
            return cur.rowcount == 1

    def rotate_device_token(self, owner_id: str, device_id: str) -> str | None:
        raw = new_token(40)
        with self.lock:
            cur = self.conn.execute(
                "UPDATE devices SET device_token_hash=? WHERE id=? AND owner_id=? AND revoked_at IS NULL",
                (token_hash(raw), device_id, owner_id),
            )
            self.conn.commit()
            return raw if cur.rowcount == 1 else None

    def prepare_device_key_rotation(
        self,
        device_id: str,
        current_public_key_b64: str,
        new_public_key_b64: str,
        ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        if not new_public_key_b64 or new_public_key_b64 == current_public_key_b64:
            raise ValueError("new_device_key_must_differ")
        rotation_id = str(uuid.uuid4())
        expires_at = time.time() + max(30, min(int(ttl_seconds), 900))
        with self.lock:
            self.conn.execute("BEGIN IMMEDIATE")
            row = self.conn.execute(
                "SELECT public_key_b64,revoked_at,key_generation FROM devices WHERE id=?",
                (device_id,),
            ).fetchone()
            if not row or row["revoked_at"] is not None:
                self.conn.rollback()
                raise KeyError("device_not_found_or_revoked")
            if str(row["public_key_b64"]) != current_public_key_b64:
                self.conn.rollback()
                raise PermissionError("active_device_key_changed")
            self.conn.execute(
                """UPDATE devices SET pending_public_key_b64=?,pending_key_rotation_id=?,
                pending_key_expires_at=? WHERE id=?""",
                (new_public_key_b64, rotation_id, expires_at, device_id),
            )
            self.conn.commit()
            return {
                "rotation_id": rotation_id,
                "expires_at": expires_at,
                "key_generation": int(row["key_generation"] or 1),
            }

    def pending_device_key_rotation(self, device_id: str) -> dict[str, Any] | None:
        with self.lock:
            row = self.conn.execute(
                """SELECT pending_public_key_b64,pending_key_rotation_id,pending_key_expires_at,
                key_generation FROM devices WHERE id=? AND revoked_at IS NULL""",
                (device_id,),
            ).fetchone()
            if not row or not row["pending_key_rotation_id"]:
                return None
            # Expired rotation state is not authority. Clear it eagerly so the
            # panel does not show a permanent pending badge and a reconnecting
            # Agent can safely start a fresh two-key proof.
            if float(row["pending_key_expires_at"] or 0) < time.time():
                self.conn.execute(
                    "UPDATE devices SET pending_public_key_b64=NULL,pending_key_rotation_id=NULL,pending_key_expires_at=NULL WHERE id=?",
                    (device_id,),
                )
                self.conn.commit()
                return None
            return dict(row)

    def confirm_device_key_rotation(
        self, device_id: str, rotation_id: str, expected_new_public_key_b64: str
    ) -> int:
        now = time.time()
        with self.lock:
            self.conn.execute("BEGIN IMMEDIATE")
            row = self.conn.execute(
                """SELECT public_key_b64,pending_public_key_b64,pending_key_rotation_id,
                pending_key_expires_at,key_generation,revoked_at FROM devices WHERE id=?""",
                (device_id,),
            ).fetchone()
            if not row or row["revoked_at"] is not None:
                self.conn.rollback()
                raise KeyError("device_not_found_or_revoked")
            if str(row["pending_key_rotation_id"] or "") != rotation_id:
                self.conn.rollback()
                raise PermissionError("key_rotation_not_pending")
            if float(row["pending_key_expires_at"] or 0) < now:
                self.conn.execute(
                    "UPDATE devices SET pending_public_key_b64=NULL,pending_key_rotation_id=NULL,pending_key_expires_at=NULL WHERE id=?",
                    (device_id,),
                )
                self.conn.commit()
                raise TimeoutError("key_rotation_expired")
            if str(row["pending_public_key_b64"] or "") != expected_new_public_key_b64:
                self.conn.rollback()
                raise PermissionError("pending_device_key_mismatch")
            generation = int(row["key_generation"] or 1) + 1
            self.conn.execute(
                """UPDATE devices SET previous_public_key_b64=public_key_b64,
                public_key_b64=pending_public_key_b64,key_generation=?,key_rotated_at=?,
                pending_public_key_b64=NULL,pending_key_rotation_id=NULL,pending_key_expires_at=NULL
                WHERE id=?""",
                (generation, now_iso(), device_id),
            )
            self.conn.commit()
            return generation

    def cancel_device_key_rotation(
        self, device_id: str, rotation_id: str | None = None
    ) -> bool:
        with self.lock:
            if rotation_id:
                cur = self.conn.execute(
                    """UPDATE devices SET pending_public_key_b64=NULL,pending_key_rotation_id=NULL,
                    pending_key_expires_at=NULL WHERE id=? AND pending_key_rotation_id=?""",
                    (device_id, rotation_id),
                )
            else:
                cur = self.conn.execute(
                    """UPDATE devices SET pending_public_key_b64=NULL,pending_key_rotation_id=NULL,
                    pending_key_expires_at=NULL WHERE id=? AND pending_key_rotation_id IS NOT NULL""",
                    (device_id,),
                )
            self.conn.commit()
            return cur.rowcount == 1

    def set_permission(self, owner_id: str, device_id: str, profile: str) -> bool:
        if profile not in PROFILE_RANK:
            raise ValueError("invalid_permission_profile")
        device = self.get_device(device_id)
        if not device or device["owner_id"] != owner_id:
            return False
        max_profile = local_max_profile(device["capabilities"])
        if PROFILE_RANK[profile] > PROFILE_RANK[max_profile]:
            if profile == "FULL_CONTROL" and not bool(
                device["capabilities"].get("privileged_helper", False)
            ):
                raise RuntimeError("full_control_requires_privileged_helper")
            raise RuntimeError(f"permission_exceeds_device_local_max:{max_profile}")
        with self.lock:
            cur = self.conn.execute(
                "UPDATE devices SET permission_profile=? WHERE id=? AND owner_id=?",
                (profile, device_id, owner_id),
            )
            self.conn.commit()
            return cur.rowcount == 1

    def mark_online(
        self,
        device_id: str,
        *,
        ip: str | None,
        agent_version: str,
        capabilities: dict[str, Any],
        agent_protocol_version: str,
    ) -> None:
        with self.lock:
            self.conn.execute(
                """UPDATE devices SET status='online',last_seen=?,last_ip=?,agent_version=?,
                capabilities_json=?,agent_protocol_version=? WHERE id=? AND revoked_at IS NULL""",
                (
                    time.time(),
                    ip,
                    agent_version,
                    json.dumps(capabilities),
                    agent_protocol_version,
                    device_id,
                ),
            )
            self.conn.commit()

    def update_runtime_capabilities(
        self, device_id: str, capabilities: dict[str, Any]
    ) -> tuple[str | None, str | None]:
        """Persist dynamic Agent capabilities and enforce the device-local ceiling.

        Returns (old_profile, new_profile) only when the server-side profile had
        to be reduced. A device can always locally remove authority immediately;
        increasing authority still requires an explicit operator action.
        """
        max_profile = local_max_profile(capabilities)
        with self.lock:
            row = self.conn.execute(
                "SELECT permission_profile FROM devices WHERE id=? AND revoked_at IS NULL",
                (device_id,),
            ).fetchone()
            if not row:
                return None, None
            current = str(row["permission_profile"])
            new_profile = current
            if PROFILE_RANK.get(current, 1) > PROFILE_RANK[max_profile]:
                new_profile = max_profile
            self.conn.execute(
                "UPDATE devices SET last_seen=?,capabilities_json=?,permission_profile=? WHERE id=? AND status='online' AND revoked_at IS NULL",
                (time.time(), json.dumps(capabilities), new_profile, device_id),
            )
            self.conn.commit()
        return (current, new_profile) if current != new_profile else (None, None)

    def heartbeat(self, device_id: str) -> None:
        with self.lock:
            self.conn.execute(
                "UPDATE devices SET status='online',last_seen=? WHERE id=? AND approved_at IS NOT NULL AND revoked_at IS NULL",
                (time.time(), device_id),
            )
            self.conn.commit()

    def mark_offline(self, device_id: str) -> None:
        with self.lock:
            self.conn.execute(
                "UPDATE devices SET status='offline' WHERE id=? AND status='online'",
                (device_id,),
            )
            self.conn.commit()

    def expire_stale_devices(self, cutoff_epoch: float) -> int:
        with self.lock:
            cur = self.conn.execute(
                "UPDATE devices SET status='offline' WHERE status='online' AND (last_seen IS NULL OR last_seen<?)",
                (cutoff_epoch,),
            )
            self.conn.commit()
            return cur.rowcount

    def create_selection(
        self, owner_id: str, device_id: str, ttl_seconds: int
    ) -> dict[str, Any]:
        selection_id = str(uuid.uuid4())
        now = time.time()
        with self.lock:
            self.conn.execute(
                "INSERT INTO selections(id,owner_id,device_id,created_at,expires_at) VALUES(?,?,?,?,?)",
                (selection_id, owner_id, device_id, now, now + ttl_seconds),
            )
            self.conn.commit()
        return {
            "selection_id": selection_id,
            "device_id": device_id,
            "expires_at": now + ttl_seconds,
        }

    def resolve_selection(self, owner_id: str, selection_id: str) -> str:
        now = time.time()
        with self.lock:
            row = self.conn.execute(
                "SELECT device_id FROM selections WHERE id=? AND owner_id=? AND expires_at>=?",
                (selection_id, owner_id, now),
            ).fetchone()
        if not row:
            raise KeyError("selection_not_found_or_expired")
        return str(row["device_id"])

    def recover_incomplete_jobs(self) -> int:
        """Mark jobs left running by a previous server process as interrupted.

        CommandCore cannot safely assume a pre-restart in-flight command is still
        controllable, so it never presents those rows as live after restart.
        """
        with self.lock:
            for row in self.conn.execute(
                "SELECT execution_id,event_json FROM activity_events"
            ).fetchall():
                event = json.loads(row["event_json"])
                if event.get("status") == "running":
                    event.update(
                        status="interrupted",
                        completed_at=time.time(),
                        duration_ms=max(
                            0, int((time.time() - event["started_at"]) * 1000)
                        ),
                        result_summary="Control plane restarted; local job state can be queried after reconnect",
                    )
                    self.conn.execute(
                        "UPDATE activity_events SET event_json=? WHERE execution_id=?",
                        (json.dumps(event), row["execution_id"]),
                    )
            cur = self.conn.execute(
                "UPDATE jobs SET status='interrupted',completed_at=?,error='control plane restarted while job was running' WHERE status='running'",
                (time.time(),),
            )
            self.conn.commit()
            return cur.rowcount

    def create_job(
        self, execution_id: str, owner_id: str, device_id: str, tool: str
    ) -> None:
        with self.lock:
            self.conn.execute(
                "INSERT INTO jobs(execution_id,owner_id,device_id,tool,status,created_at) VALUES(?,?,?,?,?,?)",
                (execution_id, owner_id, device_id, tool, "running", time.time()),
            )
            self.conn.commit()

    def finish_job(
        self, execution_id: str, status: str, exit_code: int | None, error: str | None
    ) -> None:
        status = (
            status
            if status
            in {
                "ok",
                "completed",
                "started",
                "error",
                "timeout",
                "canceled",
                "agent_disconnected",
                "interrupted",
            }
            else "error"
        )
        error = "Remote error details omitted from persisted history" if error else None
        with self.lock:
            self.conn.execute(
                "UPDATE jobs SET status=?,completed_at=?,exit_code=?,error=? WHERE execution_id=?",
                (status, time.time(), exit_code, error, execution_id),
            )
            self.conn.commit()

    def add_audit(
        self,
        *,
        user_id: str,
        client_id: str,
        device_id: str | None,
        tool: str,
        args_summary: str,
        execution_id: str | None,
        status: str,
        duration_ms: int,
        exit_code: int | None,
        risk_class: str,
    ) -> None:
        with self.lock:
            self.conn.execute(
                """INSERT INTO audit_events(timestamp,user_id,client_id,device_id,tool,args_summary,
                execution_id,status,duration_ms,exit_code,risk_class) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    now_iso(),
                    user_id,
                    client_id,
                    device_id,
                    tool,
                    args_summary,
                    execution_id,
                    status,
                    duration_ms,
                    exit_code,
                    risk_class,
                ),
            )
            self.conn.commit()

    def list_jobs(
        self,
        owner_id: str,
        *,
        limit: int = 100,
        active_only: bool = False,
        device_id: str | None = None,
    ) -> list[dict[str, Any]]:
        clauses = ["owner_id=?"]
        values: list[Any] = [owner_id]
        if active_only:
            clauses.append("status='running'")
        if device_id:
            clauses.append("device_id=?")
            values.append(device_id)
        values.append(limit)
        with self.lock:
            rows = self.conn.execute(
                f"SELECT * FROM jobs WHERE {' AND '.join(clauses)} ORDER BY created_at DESC LIMIT ?",
                values,
            ).fetchall()
        return [dict(r) for r in rows]

    def overview(self, owner_id: str) -> dict[str, int]:
        with self.lock:
            rows = self.conn.execute(
                "SELECT status,COUNT(*) AS n FROM devices WHERE owner_id=? GROUP BY status",
                (owner_id,),
            ).fetchall()
            active_jobs = self.conn.execute(
                "SELECT COUNT(*) AS n FROM jobs WHERE owner_id=? AND status='running'",
                (owner_id,),
            ).fetchone()["n"]
            active_enrollments = self.conn.execute(
                "SELECT COUNT(*) AS n FROM enrollment_tokens WHERE owner_id=? AND used_at IS NULL AND canceled_at IS NULL AND expires_at>=?",
                (owner_id, time.time()),
            ).fetchone()["n"]
            active_rollouts = self.conn.execute(
                "SELECT COUNT(*) AS n FROM fleet_rollouts WHERE owner_id=? AND status IN ('planned','running','paused')",
                (owner_id,),
            ).fetchone()["n"]
        counts = {str(r["status"]): int(r["n"]) for r in rows}
        total = sum(counts.values())
        return {
            "devices": total,
            "online": counts.get("online", 0),
            "offline": counts.get("offline", 0),
            "pending": counts.get("pending", 0),
            "revoked": counts.get("revoked", 0),
            "active_jobs": int(active_jobs),
            "active_enrollments": int(active_enrollments),
            "active_rollouts": int(active_rollouts),
        }

    def create_fleet_rollout(
        self,
        *,
        owner_id: str,
        created_by: str,
        target_version: str,
        manifest_url: str,
        device_ids: list[str],
        canary_count: int = 1,
        ring_size: int = 5,
        stop_on_failure: bool = True,
    ) -> dict[str, Any]:
        target_version = target_version.strip()
        manifest_url = manifest_url.strip()
        if not target_version:
            raise ValueError("target_version_required")
        if not manifest_url.startswith("https://"):
            raise ValueError("fleet_manifest_requires_https")
        ordered = list(dict.fromkeys(str(x) for x in device_ids if str(x)))
        if not ordered:
            raise ValueError("fleet_rollout_requires_devices")
        canary_count = max(1, min(int(canary_count), len(ordered)))
        ring_size = max(1, int(ring_size))
        with self.lock:
            rows = self.conn.execute(
                f"SELECT * FROM devices WHERE owner_id=? AND id IN ({','.join('?' for _ in ordered)})",
                [owner_id, *ordered],
            ).fetchall()
            found = {str(r["id"]): self._device(r) for r in rows}
            missing = [d for d in ordered if d not in found]
            if missing:
                raise KeyError(
                    f"fleet_devices_not_owned_or_missing:{','.join(missing)}"
                )
            for device_id in ordered:
                device = found[device_id]
                assert device is not None
                if device.get("revoked_at"):
                    raise ValueError(f"fleet_device_revoked:{device_id}")
                caps = device.get("capabilities") or {}
                if (
                    str(device.get("permission_profile")) != "FULL_CONTROL"
                    or local_max_profile(caps) != "FULL_CONTROL"
                ):
                    raise ValueError(f"fleet_device_requires_full_control:{device_id}")
                if not bool(caps.get("agent_update", False)):
                    raise ValueError(
                        f"fleet_device_update_capability_missing:{device_id}"
                    )
                if not bool(caps.get("agent_update_trust_configured", False)):
                    raise ValueError(
                        f"fleet_device_update_trust_not_configured:{device_id}"
                    )
            rollout_id = str(uuid.uuid4())
            now = time.time()
            self.conn.execute(
                """INSERT INTO fleet_rollouts(id,owner_id,target_version,manifest_url,status,current_ring,
                stop_on_failure,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (
                    rollout_id,
                    owner_id,
                    target_version,
                    manifest_url,
                    "planned",
                    0,
                    1 if stop_on_failure else 0,
                    created_by,
                    now,
                    now,
                ),
            )
            for index, device_id in enumerate(ordered):
                if index < canary_count:
                    ring = 0
                else:
                    ring = 1 + ((index - canary_count) // ring_size)
                self.conn.execute(
                    """INSERT INTO fleet_rollout_devices(rollout_id,device_id,ring,state,updated_at)
                    VALUES(?,?,?,?,?)""",
                    (rollout_id, device_id, ring, "pending", now),
                )
            self.conn.execute(
                "INSERT INTO fleet_rollout_events(rollout_id,timestamp,event,detail_json) VALUES(?,?,?,?)",
                (
                    rollout_id,
                    now,
                    "created",
                    json.dumps(
                        {
                            "target_version": target_version,
                            "device_count": len(ordered),
                        },
                        separators=(",", ":"),
                    ),
                ),
            )
            self.conn.commit()
        result = self.get_fleet_rollout(owner_id, rollout_id)
        assert result is not None
        return result

    def list_fleet_rollouts(
        self, owner_id: str, limit: int = 50
    ) -> list[dict[str, Any]]:
        with self.lock:
            rows = self.conn.execute(
                "SELECT * FROM fleet_rollouts WHERE owner_id=? ORDER BY created_at DESC LIMIT ?",
                (owner_id, max(1, min(int(limit), 200))),
            ).fetchall()
        return [self._fleet_rollout_summary(dict(row)) for row in rows]

    def _fleet_rollout_summary(self, rollout: dict[str, Any]) -> dict[str, Any]:
        rid = str(rollout["id"])
        with self.lock:
            rows = self.conn.execute(
                "SELECT state,COUNT(*) AS n FROM fleet_rollout_devices WHERE rollout_id=? GROUP BY state",
                (rid,),
            ).fetchall()
            total = self.conn.execute(
                "SELECT COUNT(*) AS n FROM fleet_rollout_devices WHERE rollout_id=?",
                (rid,),
            ).fetchone()["n"]
            max_ring = self.conn.execute(
                "SELECT COALESCE(MAX(ring),0) AS n FROM fleet_rollout_devices WHERE rollout_id=?",
                (rid,),
            ).fetchone()["n"]
        counts = {str(r["state"]): int(r["n"]) for r in rows}
        rollout = dict(rollout)
        rollout["stop_on_failure"] = bool(rollout.get("stop_on_failure"))
        rollout["device_count"] = int(total)
        rollout["max_ring"] = int(max_ring)
        rollout["state_counts"] = counts
        return rollout

    def get_fleet_rollout(
        self, owner_id: str, rollout_id: str
    ) -> dict[str, Any] | None:
        with self.lock:
            row = self.conn.execute(
                "SELECT * FROM fleet_rollouts WHERE id=? AND owner_id=?",
                (rollout_id, owner_id),
            ).fetchone()
            if not row:
                return None
            devices = self.conn.execute(
                """SELECT frd.*,d.display_name,d.hostname,d.agent_version,d.status AS device_status,
                d.capabilities_json,d.permission_profile,d.revoked_at
                FROM fleet_rollout_devices frd JOIN devices d ON d.id=frd.device_id
                WHERE frd.rollout_id=? ORDER BY frd.ring,d.display_name,d.id""",
                (rollout_id,),
            ).fetchall()
            events = self.conn.execute(
                "SELECT * FROM fleet_rollout_events WHERE rollout_id=? ORDER BY id DESC LIMIT 200",
                (rollout_id,),
            ).fetchall()
        result = self._fleet_rollout_summary(dict(row))
        result["devices"] = []
        for item in devices:
            d = dict(item)
            d["capabilities"] = json.loads(d.pop("capabilities_json") or "{}")
            result["devices"].append(d)
        result["events"] = []
        for event in events:
            e = dict(event)
            try:
                e["detail"] = json.loads(e.pop("detail_json") or "{}")
            except json.JSONDecodeError:
                e["detail"] = {}
            result["events"].append(e)
        return result

    def set_fleet_rollout_status(
        self,
        owner_id: str,
        rollout_id: str,
        status: str,
        *,
        last_error: str | None = None,
        current_ring: int | None = None,
    ) -> bool:
        allowed_status = {
            "planned",
            "running",
            "paused",
            "completed",
            "failed",
            "canceled",
        }
        if status not in allowed_status:
            raise ValueError("invalid_fleet_rollout_status")
        fields = ["status=?", "updated_at=?", "last_error=?"]
        values: list[Any] = [status, time.time(), last_error]
        if current_ring is not None:
            fields.append("current_ring=?")
            values.append(max(0, int(current_ring)))
        values.extend([rollout_id, owner_id])
        with self.lock:
            cur = self.conn.execute(
                f"UPDATE fleet_rollouts SET {','.join(fields)} WHERE id=? AND owner_id=?",
                values,
            )
            self.conn.commit()
            return cur.rowcount == 1

    def set_fleet_device_state(
        self,
        owner_id: str,
        rollout_id: str,
        device_id: str,
        state: str,
        *,
        stage_metadata_path: str | None = None,
        observed_version: str | None = None,
        last_error: str | None = None,
        event: str | None = None,
        detail: dict[str, Any] | None = None,
    ) -> bool:
        allowed_states = {
            "pending",
            "staging",
            "staged",
            "activating",
            "committed",
            "failed",
            "skipped",
            "rolled_back",
        }
        if state not in allowed_states:
            raise ValueError("invalid_fleet_device_state")
        now = time.time()
        with self.lock:
            owner = self.conn.execute(
                "SELECT 1 FROM fleet_rollouts WHERE id=? AND owner_id=?",
                (rollout_id, owner_id),
            ).fetchone()
            if not owner:
                return False
            cur = self.conn.execute(
                """UPDATE fleet_rollout_devices SET state=?,stage_metadata_path=COALESCE(?,stage_metadata_path),
                observed_version=COALESCE(?,observed_version),last_error=?,updated_at=?
                WHERE rollout_id=? AND device_id=?""",
                (
                    state,
                    stage_metadata_path,
                    observed_version,
                    last_error,
                    now,
                    rollout_id,
                    device_id,
                ),
            )
            if cur.rowcount and event:
                self.conn.execute(
                    "INSERT INTO fleet_rollout_events(rollout_id,device_id,timestamp,event,detail_json) VALUES(?,?,?,?,?)",
                    (
                        rollout_id,
                        device_id,
                        now,
                        event,
                        json.dumps(detail or {}, separators=(",", ":")),
                    ),
                )
            self.conn.commit()
            return cur.rowcount == 1

    def add_fleet_event(
        self,
        owner_id: str,
        rollout_id: str,
        event: str,
        *,
        device_id: str | None = None,
        detail: dict[str, Any] | None = None,
    ) -> bool:
        with self.lock:
            row = self.conn.execute(
                "SELECT 1 FROM fleet_rollouts WHERE id=? AND owner_id=?",
                (rollout_id, owner_id),
            ).fetchone()
            if not row:
                return False
            self.conn.execute(
                "INSERT INTO fleet_rollout_events(rollout_id,device_id,timestamp,event,detail_json) VALUES(?,?,?,?,?)",
                (
                    rollout_id,
                    device_id,
                    time.time(),
                    event,
                    json.dumps(detail or {}, separators=(",", ":")),
                ),
            )
            self.conn.commit()
            return True

    def cancel_fleet_rollout(self, owner_id: str, rollout_id: str) -> bool:
        now = time.time()
        with self.lock:
            row = self.conn.execute(
                "SELECT status FROM fleet_rollouts WHERE id=? AND owner_id=?",
                (rollout_id, owner_id),
            ).fetchone()
            if not row or row["status"] in {"completed", "canceled"}:
                return False
            self.conn.execute(
                "UPDATE fleet_rollouts SET status='canceled',updated_at=? WHERE id=? AND owner_id=?",
                (now, rollout_id, owner_id),
            )
            self.conn.execute(
                "UPDATE fleet_rollout_devices SET state='skipped',updated_at=? WHERE rollout_id=? AND state IN ('pending','staging','staged')",
                (now, rollout_id),
            )
            self.conn.execute(
                "INSERT INTO fleet_rollout_events(rollout_id,timestamp,event,detail_json) VALUES(?,?,?,?)",
                (rollout_id, now, "canceled", "{}"),
            )
            self.conn.commit()
            return True

    def recent_audit(
        self, owner_id: str, limit: int = 100, device_id: str | None = None
    ) -> list[dict[str, Any]]:
        with self.lock:
            if device_id:
                rows = self.conn.execute(
                    "SELECT * FROM audit_events WHERE user_id=? AND device_id=? ORDER BY id DESC LIMIT ?",
                    (owner_id, device_id, limit),
                ).fetchall()
            else:
                rows = self.conn.execute(
                    "SELECT * FROM audit_events WHERE user_id=? ORDER BY id DESC LIMIT ?",
                    (owner_id, limit),
                ).fetchall()
        return [dict(r) for r in rows]
