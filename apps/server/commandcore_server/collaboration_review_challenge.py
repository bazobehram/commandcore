"""One-time preview-bound review challenges; not proof of human presence.

A trusted interactive user-authentication boundary must independently attest
the decision. Never expose this as an MCP authorization primitive.
"""
from __future__ import annotations
import hmac
import secrets
import sqlite3
import threading

from .collaboration_approval import AuthorizationDenied

class ReviewChallenges:
    def __init__(self, path: str):
        self.lock=threading.RLock()
        self.db=sqlite3.connect(path,check_same_thread=False,isolation_level=None)
        self.db.execute("""CREATE TABLE IF NOT EXISTS review_challenges (
           token_hash TEXT PRIMARY KEY, owner TEXT NOT NULL, request_id TEXT NOT NULL,
           action_digest TEXT NOT NULL, expires INTEGER NOT NULL, consumed INTEGER NOT NULL DEFAULT 0)""")

    def issue(self, *, owner: str, request_id: str, action_digest: str, now: int, max_expires_at: int | None = None) -> str:
        if (not owner or not request_id or len(request_id)>128
                or len(action_digest)!=64
                or any(c not in "0123456789abcdef" for c in action_digest)):
            raise AuthorizationDenied("invalid_challenge_binding")
        expires=min(now+90, max_expires_at) if max_expires_at is not None else now+90
        if expires <= now:
            raise AuthorizationDenied("challenge_expired")
        token=secrets.token_urlsafe(32)
        import hashlib
        digest=hashlib.sha256(token.encode()).hexdigest()
        with self.lock:
            # Atomic across processes, not just threads in one process.
            self.db.execute("BEGIN IMMEDIATE")
            try:
                self.db.execute(
                    "UPDATE review_challenges SET consumed=1 WHERE owner=? AND request_id=? AND consumed=0",
                    (owner, request_id))
                self.db.execute("INSERT INTO review_challenges VALUES(?,?,?,?,?,0)",
                                (digest,owner,request_id,action_digest,expires))
                self.db.execute("COMMIT")
            except BaseException:
                self.db.execute("ROLLBACK")
                raise
        return token

    def assert_pending(self, *, token: str, owner: str, request_id: str,
                       action_digest: str, now: int) -> None:
        """Read-only preflight; consume still performs the authoritative check."""
        import hashlib
        if not isinstance(token, str) or len(token)>256:
            raise AuthorizationDenied("challenge_invalid_or_expired")
        digest=hashlib.sha256(token.encode()).hexdigest()
        with self.lock:
            row=self.db.execute(
                "SELECT owner,request_id,action_digest,expires,consumed FROM review_challenges WHERE token_hash=?",
                (digest,)).fetchone()
        if not row or row[4] or now>=row[3] or not (
            hmac.compare_digest(owner,row[0]) and
            hmac.compare_digest(request_id,row[1]) and
            hmac.compare_digest(action_digest,row[2])
        ):
            raise AuthorizationDenied("challenge_invalid_or_expired")

    def consume(self, *, token: str, owner: str, request_id: str,
                action_digest: str, now: int) -> None:
        import hashlib
        if not isinstance(token,str) or len(token)>256:
            raise AuthorizationDenied("challenge_invalid_or_expired")
        digest=hashlib.sha256(token.encode()).hexdigest()
        with self.lock:
            row=self.db.execute("SELECT owner,request_id,action_digest,expires,consumed FROM review_challenges WHERE token_hash=?",(digest,)).fetchone()
            if not row or row[4] or now>=row[3] or not (
                hmac.compare_digest(owner,row[0]) and
                hmac.compare_digest(request_id,row[1]) and
                hmac.compare_digest(action_digest,row[2])
            ):
                raise AuthorizationDenied("challenge_invalid_or_expired")
            updated=self.db.execute("UPDATE review_challenges SET consumed=1 WHERE token_hash=? AND consumed=0",(digest,))
            if updated.rowcount!=1:raise AuthorizationDenied("challenge_replayed")

    def close(self):self.db.close()
