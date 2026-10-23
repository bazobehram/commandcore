from __future__ import annotations

"""Pure authorization state machine for future ChatGPT-native collaboration.

This module DOES NOT grant approval from an MCP tool argument or chat text.
A trusted, authenticated user-interface endpoint must supply actor_attested=True
only after it has independently verified the human interaction.
"""

import json
from dataclasses import dataclass, replace
from hashlib import sha256
from hmac import compare_digest
from typing import Literal

Status = Literal["pending", "approved", "denied", "expired", "consumed"]
Decision = Literal["approve", "deny"]


@dataclass(frozen=True)
class Approval:
    request_id: str
    owner_subject: str
    device_id: str
    window_id: str
    expected_title: str
    process_id: int
    process_start: int
    draft_id: str
    draft_sha256: str
    action_digest: str
    created_at: int
    expires_at: int
    status: Status = "pending"
    decision_actor: str | None = None


def action_digest(
    *,
    device_id: str,
    window_id: str,
    title: str,
    process_id: int,
    process_start: int,
    draft_id: str,
    draft_sha256: str,
    input_x: int,
    input_y: int,
    send_key: str,
) -> str:
    payload = {
        "device_id": device_id,
        "window_id": window_id,
        "title": title,
        "process_id": process_id,
        "process_start": process_start,
        "draft_id": draft_id,
        "draft_sha256": draft_sha256,
        "input_x": input_x,
        "input_y": input_y,
        "send_key": send_key,
    }
    return sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


class AuthorizationDenied(ValueError):
    pass


def decide(
    request: Approval,
    *,
    decision: Decision,
    actor_subject: str,
    actor_attested: bool,
    now: int,
) -> Approval:
    if request.status != "pending":
        raise AuthorizationDenied("decision_not_pending")
    if now < request.created_at or now >= request.expires_at:
        raise AuthorizationDenied("approval_expired")
    if not actor_attested:
        raise AuthorizationDenied("trusted_user_interaction_required")
    if not actor_subject or actor_subject != request.owner_subject:
        raise AuthorizationDenied("wrong_authorization_subject")
    if decision not in ("approve", "deny"):
        raise AuthorizationDenied("invalid_decision")
    return replace(
        request,
        status="approved" if decision == "approve" else "denied",
        decision_actor=actor_subject,
    )


def consume(
    request: Approval, *, owner_subject: str, action_digest_value: str, now: int
) -> Approval:
    if request.status != "approved" or request.decision_actor != owner_subject:
        raise AuthorizationDenied("not_approved_for_owner")
    if now < request.created_at or now >= request.expires_at:
        raise AuthorizationDenied("approval_expired")
    if not compare_digest(request.action_digest, action_digest_value):
        raise AuthorizationDenied("action_binding_mismatch")
    return replace(request, status="consumed")


# The ledger is deliberately independent of the legacy local-Zenity delivery
# path. It never contains draft plaintext or issues device execution permits.
import sqlite3
import threading
import time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS collaboration_approvals (
    request_id TEXT PRIMARY KEY,
    owner_subject TEXT NOT NULL,
    device_id TEXT NOT NULL,
    window_id TEXT NOT NULL,
    expected_title TEXT NOT NULL,
    process_id INTEGER NOT NULL,
    process_start INTEGER NOT NULL,
    draft_id TEXT NOT NULL UNIQUE,
    draft_sha256 TEXT NOT NULL,
    action_digest TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    status TEXT NOT NULL CHECK(status IN
        ('pending','approved','denied','expired','consumed')),
    decision_actor TEXT,
    decided_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_collab_owner_pending
    ON collaboration_approvals(owner_subject,status,expires_at);
"""


class ApprovalLedger:
    """Transactional, owner-scoped proposals with no implicit delivery.

    The caller must independently authenticate the decision surface. This
    object does not attest the user and never signs an execution permit.
    """

    def __init__(self, db_path: str):
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(
            db_path, timeout=15, check_same_thread=False, isolation_level=None
        )
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(SCHEMA)

    def close(self) -> None:
        with self.lock:
            self.conn.close()

    @staticmethod
    def _approval(row: sqlite3.Row) -> Approval:
        values = {k: row[k] for k in Approval.__dataclass_fields__}
        return Approval(**values)

    def create(self, request: Approval) -> Approval:
        if request.status != "pending" or request.decision_actor is not None:
            raise AuthorizationDenied("proposal_must_be_pending")
        if not (
            request.request_id
            and request.owner_subject
            and request.device_id
            and request.draft_id
            and len(request.draft_sha256) == 64
            and len(request.action_digest) == 64
        ):
            raise AuthorizationDenied("invalid_proposal")
        if (
            request.created_at >= request.expires_at
            or request.expires_at - request.created_at > 600
        ):
            raise AuthorizationDenied("invalid_proposal_expiry")
        fields = (
            "request_id",
            "owner_subject",
            "device_id",
            "window_id",
            "expected_title",
            "process_id",
            "process_start",
            "draft_id",
            "draft_sha256",
            "action_digest",
            "created_at",
            "expires_at",
            "status",
            "decision_actor",
        )
        with self.lock:
            try:
                self.conn.execute(
                    f"INSERT INTO collaboration_approvals ({','.join(fields)}) "
                    f"VALUES ({','.join('?' for _ in fields)})",
                    tuple(getattr(request, f) for f in fields),
                )
            except sqlite3.IntegrityError as exc:
                raise AuthorizationDenied("duplicate_proposal_or_draft") from exc
        return request

    def get(self, *, owner_subject: str, request_id: str) -> Approval | None:
        if not owner_subject:
            raise AuthorizationDenied("owner_required")
        with self.lock:
            row = self.conn.execute(
                "SELECT * FROM collaboration_approvals "
                "WHERE owner_subject=? AND request_id=?",
                (owner_subject, request_id),
            ).fetchone()
            return self._approval(row) if row else None

    def list_pending(
        self, *, owner_subject: str, now: int | None = None, limit: int = 20
    ) -> list[Approval]:
        if not owner_subject:
            raise AuthorizationDenied("owner_required")
        if now is None:
            now = int(time.time())
        with self.lock:
            return [
                self._approval(r)
                for r in self.conn.execute(
                    "SELECT * FROM collaboration_approvals WHERE "
                    "owner_subject=? AND status='pending' AND expires_at>? "
                    "ORDER BY created_at DESC LIMIT ?",
                    (owner_subject, now, max(1, min(limit, 50))),
                ).fetchall()
            ]

    def decide(
        self,
        *,
        request_id: str,
        owner_subject: str,
        actor_subject: str,
        actor_attested: bool,
        decision: Decision,
        now: int,
    ) -> Approval:
        """Called ONLY after a trusted authenticated UI has verified its actor.

        An LLM-visible MCP tool MUST NOT expose actor_attested as an argument.
        """
        with self.lock:
            self.conn.execute("BEGIN IMMEDIATE")
            try:
                row = self.conn.execute(
                    "SELECT * FROM collaboration_approvals WHERE "
                    "owner_subject=? AND request_id=?",
                    (owner_subject, request_id),
                ).fetchone()
                if row is None:
                    raise AuthorizationDenied("approval_not_found")
                next_value = decide(
                    self._approval(row),
                    decision=decision,
                    actor_subject=actor_subject,
                    actor_attested=actor_attested,
                    now=now,
                )
                count = self.conn.execute(
                    "UPDATE collaboration_approvals SET status=?, "
                    "decision_actor=?,decided_at=? WHERE "
                    "request_id=? AND owner_subject=? AND status='pending'",
                    (next_value.status, actor_subject, now, request_id, owner_subject),
                ).rowcount
                if count != 1:
                    raise AuthorizationDenied("decision_race")
                self.conn.commit()
                return next_value
            except BaseException:
                self.conn.rollback()
                raise

    def consume(
        self, *, request_id: str, owner_subject: str, action_digest_value: str, now: int
    ) -> Approval:
        """Atomic ledger gate only. It does NOT authorize agent input."""
        with self.lock:
            self.conn.execute("BEGIN IMMEDIATE")
            try:
                row = self.conn.execute(
                    "SELECT * FROM collaboration_approvals WHERE "
                    "owner_subject=? AND request_id=?",
                    (owner_subject, request_id),
                ).fetchone()
                if row is None:
                    raise AuthorizationDenied("approval_not_found")
                next_value = consume(
                    self._approval(row),
                    owner_subject=owner_subject,
                    action_digest_value=action_digest_value,
                    now=now,
                )
                count = self.conn.execute(
                    "UPDATE collaboration_approvals SET status='consumed' "
                    "WHERE request_id=? AND owner_subject=? AND status='approved'",
                    (request_id, owner_subject),
                ).rowcount
                if count != 1:
                    raise AuthorizationDenied("consume_race")
                self.conn.commit()
                return next_value
            except BaseException:
                self.conn.rollback()
                raise
