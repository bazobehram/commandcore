"""Agent-initiated enrollment. Public keys only; credentials never enter audit."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import secrets
import time
import uuid
from typing import Any

from .db import Database, now_iso
from .security import token_hash, verify_device_signature


def init_message(metadata: dict[str, Any]) -> bytes:
    return (
        "commandcore-enroll-init-v1\n"
        + json.dumps(
            metadata, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )
    ).encode()


class EnrollmentService:
    def __init__(self, db: Database, registry_owner: str, ttl: int = 600):
        self.db = db
        self.registry_owner = registry_owner
        self.ttl = min(max(ttl, 60), 600)

    def rate_limit(self, peer: str, bucket: str, limit: int = 20) -> None:
        # Peer addresses are hashed; no caller-controlled forwarding headers.
        key = hashlib.sha256((bucket + peer).encode()).hexdigest()
        window = int(time.time()) // 60
        with self.db.lock, self.db.conn:
            self.db.conn.execute(
                "DELETE FROM enrollment_limits WHERE window<?", (window - 2,)
            )
            self.db.conn.execute(
                "INSERT INTO enrollment_limits(key,window,count) VALUES(?,?,1) ON CONFLICT(key,window) DO UPDATE SET count=count+1",
                (key, window),
            )
            count = self.db.conn.execute(
                "SELECT count FROM enrollment_limits WHERE key=? AND window=?",
                (key, window),
            ).fetchone()[0]
        if count > limit:
            raise ValueError("rate_limited")

    def begin(self, metadata: dict[str, Any], proof: str) -> dict[str, Any]:
        public = metadata["public_key_b64"]
        try:
            valid_key = len(base64.b64decode(public, validate=True)) == 32
        except (ValueError, binascii.Error):
            valid_key = False
        if not valid_key or not verify_device_signature(
            public, proof, init_message(metadata)
        ):
            raise ValueError("invalid_identity_proof")
        if metadata["protocol_version"] != "1":
            raise ValueError("unsupported_agent_protocol")
        if metadata["local_ceiling"] not in {"READ_ONLY", "STANDARD"}:
            raise ValueError("enrollment_ceiling_requires_standard_or_read_only")
        chosen_id = metadata.get("device_id")
        chosen_hash = metadata.get("device_token_hash")
        if chosen_id is not None or chosen_hash is not None:
            try:
                valid_identity = (
                    str(uuid.UUID(chosen_id)) == chosen_id
                    and len(chosen_hash) == 64
                    and all(c in "0123456789abcdef" for c in chosen_hash)
                )
            except (ValueError, TypeError, AttributeError):
                valid_identity = False
            if not valid_identity:
                raise ValueError("invalid_local_device_identity")
        now = time.time()
        enrollment_id = str(uuid.uuid4())
        view = secrets.token_urlsafe(32)
        poll = secrets.token_urlsafe(32)
        alphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
        code = "".join(secrets.choice(alphabet) for _ in range(8))
        code = code[:4] + "-" + code[4:]
        with self.db.lock:
            self.db.conn.execute("BEGIN IMMEDIATE")
            try:
                if (
                    chosen_id
                    and self.db.conn.execute(
                        "SELECT 1 FROM devices WHERE id=?", (chosen_id,)
                    ).fetchone()
                ):
                    raise ValueError("identity_already_enrolled")
                if (
                    chosen_id
                    and self.db.conn.execute(
                        "SELECT 1 FROM pending_enrollments WHERE json_extract(metadata_json,'$.device_id')=? AND status IN ('pending','approved') AND expires_at>?",
                        (chosen_id, now),
                    ).fetchone()
                ):
                    raise ValueError("identity_enrollment_pending")
                if self.db.conn.execute(
                    "SELECT 1 FROM devices WHERE public_key_b64=?", (public,)
                ).fetchone():
                    raise ValueError("identity_already_enrolled")
                if self.db.conn.execute(
                    "SELECT 1 FROM pending_enrollments WHERE public_key_b64=? AND status IN ('pending','approved') AND expires_at>?",
                    (public, now),
                ).fetchone():
                    raise ValueError("identity_enrollment_pending")
                self.db.conn.execute(
                    "INSERT INTO pending_enrollments(id,view_hash,poll_hash,code,public_key_b64,metadata_json,created_at,expires_at,status) VALUES(?,?,?,?,?,?,?,?, 'pending')",
                    (
                        enrollment_id,
                        token_hash(view),
                        token_hash(poll),
                        code,
                        public,
                        json.dumps(metadata),
                        now,
                        now + self.ttl,
                    ),
                )
                self._audit("anonymous-agent", "enrollment.begin", enrollment_id)
                self.db.conn.commit()
            except Exception:
                self.db.conn.rollback()
                raise
        return {
            "id": enrollment_id,
            "view_token": view,
            "poll_token": poll,
            "verification_code": code,
            "expires_at": now + self.ttl,
            "interval": 3,
        }

    def _audit(
        self,
        subject: str,
        tool: str,
        enrollment_id: str,
        device_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.db.conn.execute(
            "INSERT INTO audit_events(timestamp,user_id,client_id,device_id,tool,args_summary,status,duration_ms,risk_class) VALUES(?,?,?,?,?,?, 'ok',0,'medium')",
            (
                now_iso(),
                subject,
                "enrollment-panel",
                device_id,
                tool,
                json.dumps({"enrollment_id": enrollment_id, **(details or {})}),
            ),
        )

    def _row(self, raw: str, kind: str = "view"):
        if len(raw) < 40 or len(raw) > 100:
            raise ValueError("invalid_enrollment")
        row = self.db.conn.execute(
            f"SELECT * FROM pending_enrollments WHERE {kind}_hash=?", (token_hash(raw),)
        ).fetchone()
        if not row or row["expires_at"] <= time.time() or row["status"] == "consumed":
            raise ValueError("invalid_expired_or_consumed_enrollment")
        return row

    @staticmethod
    def public(row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "metadata": json.loads(row["metadata_json"]),
            "verification_code": row["code"],
            "created_at": row["created_at"],
            "expires_at": row["expires_at"],
            "status": row["status"],
        }

    def review(self, raw: str, subject: str) -> dict[str, Any]:
        with self.db.lock, self.db.conn:
            row = self._row(raw)
            if row["reviewer"] and row["reviewer"] != subject:
                raise ValueError("enrollment_owned_by_another_reviewer")
            self.db.conn.execute(
                "UPDATE pending_enrollments SET reviewer=? WHERE id=? AND reviewer IS NULL",
                (subject, row["id"]),
            )
            return self.public(row)

    def list_pending(self, subject: str) -> list[dict[str, Any]]:
        with self.db.lock:
            return [
                self.public(r)
                for r in self.db.conn.execute(
                    "SELECT * FROM pending_enrollments WHERE reviewer=? AND status='pending' AND expires_at>? ORDER BY created_at DESC",
                    (subject, time.time()),
                )
            ]

    def decide(
        self,
        raw: str,
        subject: str,
        code: str,
        approve: bool,
        grant_to_me: bool,
        *,
        reviewed_id: bool = False,
    ) -> dict[str, Any]:
        with self.db.lock:
            self.db.conn.execute("BEGIN IMMEDIATE")
            try:
                if reviewed_id:
                    # Dashboard decisions require a prior token-authenticated review
                    # by this exact principal. An ID alone grants no access.
                    row = self.db.conn.execute(
                        "SELECT * FROM pending_enrollments WHERE id=? AND reviewer=?",
                        (raw, subject),
                    ).fetchone()
                    if not row or row["expires_at"] <= time.time():
                        raise ValueError("invalid_expired_or_consumed_enrollment")
                else:
                    row = self._row(raw)
                if (
                    row["status"] != "pending"
                    or row["reviewer"] != subject
                    or not secrets.compare_digest(code, row["code"])
                ):
                    raise ValueError("invalid_enrollment_decision")
                status = "approved" if approve else "rejected"
                self.db.conn.execute(
                    "UPDATE pending_enrollments SET status=?,grant_subject=? WHERE id=?",
                    (status, subject if approve and grant_to_me else None, row["id"]),
                )
                self._audit(
                    subject,
                    "enrollment." + status,
                    row["id"],
                    details={"grant_to_me": bool(approve and grant_to_me)},
                )
                self.db.conn.commit()
                return {"status": status}
            except Exception:
                self.db.conn.rollback()
                raise

    def claim(self, poll: str, proof: str) -> dict[str, Any]:
        with self.db.lock:
            self.db.conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._row(poll, "poll")
                message = f"commandcore-enroll-claim-v1\n{row['id']}\n{poll}".encode()
                if not verify_device_signature(row["public_key_b64"], proof, message):
                    raise ValueError("invalid_identity_proof")
                if row["status"] != "approved":
                    self.db.conn.rollback()
                    return {"status": row["status"]}
                if self.db.conn.execute(
                    "SELECT 1 FROM devices WHERE public_key_b64=?",
                    (row["public_key_b64"],),
                ).fetchone():
                    raise ValueError("identity_already_enrolled")
                meta = json.loads(row["metadata_json"])
                device_id = meta.get("device_id") or str(uuid.uuid4())
                device_token = (
                    None if meta.get("device_token_hash") else secrets.token_urlsafe(40)
                )
                credential_hash = meta.get("device_token_hash") or token_hash(
                    device_token
                )
                ceiling = meta["local_ceiling"]
                caps = dict(meta["capabilities"])
                caps.update(
                    local_max_permission_profile=ceiling,
                    configured_max_permission_profile=ceiling,
                )
                created = now_iso()
                self.db.conn.execute(
                    "INSERT INTO devices(id,display_name,hostname,platform,architecture,agent_version,agent_protocol_version,public_key_b64,device_token_hash,owner_id,status,capabilities_json,permission_profile,created_at,approved_at) VALUES(?,?,?,?,?,?,?,?,?,?, 'offline',?,?,?,?)",
                    (
                        device_id,
                        meta["display_name"],
                        meta["hostname"],
                        meta["platform"],
                        meta["architecture"],
                        meta["agent_version"],
                        meta["protocol_version"],
                        row["public_key_b64"],
                        credential_hash,
                        self.registry_owner,
                        json.dumps(caps),
                        ceiling,
                        created,
                        created,
                    ),
                )
                self.db.conn.execute(
                    "INSERT INTO device_managers(device_id,subject) VALUES(?,?)",
                    (device_id, row["reviewer"]),
                )
                if row["grant_subject"]:
                    self.db.conn.execute(
                        "INSERT INTO device_grants(device_id,subject,max_permission_profile,created_at,created_by) VALUES(?,?,?,?,?)",
                        (
                            device_id,
                            row["grant_subject"],
                            ceiling,
                            created,
                            row["reviewer"],
                        ),
                    )
                    self._audit(
                        row["reviewer"],
                        "enrollment.device.grant",
                        row["id"],
                        device_id,
                        {"subject": row["grant_subject"], "profile": ceiling},
                    )
                self.db.conn.execute(
                    "UPDATE pending_enrollments SET status='consumed',device_id=?,view_hash=NULL,poll_hash=NULL WHERE id=?",
                    (device_id, row["id"]),
                )
                self._audit(
                    row["reviewer"], "enrollment.consumed", row["id"], device_id
                )
                self.db.conn.commit()
                result = {
                    "status": "approved",
                    "device_id": device_id,
                    "permission_ceiling": ceiling,
                }
                if device_token is not None:
                    result["device_token"] = device_token
                else:
                    result["credential_source"] = "agent"
                return result
            except Exception:
                self.db.conn.rollback()
                raise
