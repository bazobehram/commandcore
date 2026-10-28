"""Staging-only pre-enrolled WebAuthn credential registry and atomic counter check.

Registration ceremony and positive approval are intentionally NOT exposed.
"""
import sqlite3
import threading
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from .collaboration_approval import AuthorizationDenied
from .collaboration_webauthn_assertion import verify_assertion

class CredentialRegistry:
    def __init__(self, path):
        self.lock=threading.RLock()
        self.db=sqlite3.connect(path, isolation_level=None, check_same_thread=False)
        self.db.execute("""CREATE TABLE IF NOT EXISTS credentials(
          owner TEXT NOT NULL, credential_id TEXT NOT NULL, public_key BLOB NOT NULL,
          sign_count INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(owner,credential_id))""")
        # Fail closed on legacy cross-owner duplicates. SQLite CREATE UNIQUE
        # INDEX is atomic; do not silently delete or pick an owner.
        try:
            self.db.execute("CREATE UNIQUE INDEX IF NOT EXISTS credentials_unique_id ON credentials(credential_id)")
        except sqlite3.IntegrityError:
            self.db.close()
            raise AuthorizationDenied("credential_ownership_migration_required") from None

    def legacy_hex_id_candidates(self):
        """Read-only migration inventory; never mutate or guess credential owners."""
        import re
        with self.lock:
            rows=self.db.execute(
                "SELECT owner,credential_id FROM credentials ORDER BY owner,credential_id").fetchall()
        return [{"owner": owner, "credential_id": cid} for owner,cid in rows
                if re.fullmatch(r"[0-9a-fA-F]{2,2048}",cid) and len(cid)%2==0]

    def plan_legacy_id_migration(self, *, confirmed_legacy_ids):
        """Dry-run only. Explicit IDs are required; never infer their encoding."""
        import base64
        import re
        if not isinstance(confirmed_legacy_ids,(list,tuple,set)) or not all(
                isinstance(cid,str) and 0 < len(cid) <= 2048 for cid in confirmed_legacy_ids):
            raise AuthorizationDenied("migration_confirmation_required")
        if len(confirmed_legacy_ids) != len(set(confirmed_legacy_ids)):
            raise AuthorizationDenied("migration_duplicate_confirmation")
        with self.lock:
            rows=self.db.execute("SELECT owner,credential_id FROM credentials").fetchall()
        existing={cid for _,cid in rows}
        mapping=[]
        for owner,cid in rows:
            if cid not in confirmed_legacy_ids:
                continue
            if not re.fullmatch(r"(?:[0-9a-fA-F]{2})+",cid):
                raise AuthorizationDenied("migration_invalid_legacy_id")
            target=base64.urlsafe_b64encode(bytes.fromhex(cid)).rstrip(b"=").decode()
            if target in existing or any(entry["target"]==target for entry in mapping):
                raise AuthorizationDenied("migration_credential_id_collision")
            mapping.append({"owner":owner,"source":cid,"target":target})
        if set(confirmed_legacy_ids)!={item["source"] for item in mapping}:
            raise AuthorizationDenied("migration_unknown_or_ambiguous_id")
        return mapping

    def apply_legacy_id_migration(self, *, confirmed_legacy_ids, expected_plan):
        """Explicit opt-in, transactional migration; never exposed via HTTP/MCP."""
        if not isinstance(expected_plan,list):
            raise AuthorizationDenied("migration_plan_required")
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                actual=self.plan_legacy_id_migration(confirmed_legacy_ids=confirmed_legacy_ids)
                if actual!=expected_plan:
                    raise AuthorizationDenied("migration_plan_changed")
                for entry in actual:
                    updated=self.db.execute(
                        "UPDATE credentials SET credential_id=? WHERE owner=? AND credential_id=?",
                        (entry["target"],entry["owner"],entry["source"]))
                    if updated.rowcount!=1:
                        raise AuthorizationDenied("migration_plan_changed")
                self.db.execute("COMMIT")
                return len(actual)
            except BaseException:
                self.db.execute("ROLLBACK")
                raise

    def add_preverified(self, *, owner, credential_id, public_key_raw):
        # Never invoke this from an HTTP or MCP request: enrollment must be
        # independently authenticated in a future registration ceremony.
        if not owner or not credential_id or len(public_key_raw)!=32:
            raise AuthorizationDenied("credential_invalid")
        Ed25519PublicKey.from_public_bytes(public_key_raw)
        with self.lock:
            self.db.execute("INSERT INTO credentials(owner,credential_id,public_key) VALUES(?,?,?)",
                            (owner,credential_id,public_key_raw))

    def verify_and_update(self, *, owner, credential_id, authenticator_data,
                          client_data_json, signature, expected_challenge,
                          expected_origin, expected_rp_id):
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                row=self.db.execute("SELECT public_key,sign_count FROM credentials WHERE owner=? AND credential_id=?",
                                    (owner,credential_id)).fetchone()
                if row is None:
                    raise AuthorizationDenied("credential_not_enrolled")
                counter=verify_assertion(
                    public_key=Ed25519PublicKey.from_public_bytes(row[0]),
                    authenticator_data=authenticator_data, client_data_json=client_data_json,
                    signature=signature, expected_challenge=expected_challenge,
                    expected_origin=expected_origin, expected_rp_id=expected_rp_id,
                    previous_sign_count=row[1])
                self.db.execute("UPDATE credentials SET sign_count=? WHERE owner=? AND credential_id=?",
                                (counter,owner,credential_id))
                self.db.execute("COMMIT")
                return counter
            except BaseException:
                self.db.execute("ROLLBACK")
                raise

    def verify_and_consume(self, *, challenges, owner, request_id, action_digest,
                           token, now, credential_id, authenticator_data,
                           client_data_json, signature, expected_challenge,
                           expected_origin, expected_rp_id):
        import hashlib
        import hmac
        # One SQLite transaction must contain both tables. Never pretend a
        # pair of independently committed databases is atomic.
        own=self.db.execute("PRAGMA database_list").fetchone()[2]
        other=challenges.db.execute("PRAGMA database_list").fetchone()[2]
        if not own or own!=other:
            raise AuthorizationDenied("review_credential_storage_not_atomic")
        token_hash=hashlib.sha256(token.encode()).hexdigest()
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                row=self.db.execute(
                    "SELECT owner,request_id,action_digest,expires,consumed FROM review_challenges WHERE token_hash=?",
                    (token_hash,)).fetchone()
                if not row or row[4] or now>=row[3] or not (
                    hmac.compare_digest(row[0],owner) and
                    hmac.compare_digest(row[1],request_id) and
                    hmac.compare_digest(row[2],action_digest)):
                    raise AuthorizationDenied("challenge_invalid_or_expired")
                cred=self.db.execute(
                    "SELECT public_key,sign_count FROM credentials WHERE owner=? AND credential_id=?",
                    (owner,credential_id)).fetchone()
                if cred is None:
                    raise AuthorizationDenied("credential_not_enrolled")
                counter=verify_assertion(
                    public_key=Ed25519PublicKey.from_public_bytes(cred[0]),
                    authenticator_data=authenticator_data,client_data_json=client_data_json,
                    signature=signature,expected_challenge=expected_challenge,
                    expected_origin=expected_origin,expected_rp_id=expected_rp_id,
                    previous_sign_count=cred[1])
                self.db.execute(
                    "UPDATE credentials SET sign_count=? WHERE owner=? AND credential_id=?",
                    (counter,owner,credential_id))
                consumed=self.db.execute(
                    "UPDATE review_challenges SET consumed=1 WHERE token_hash=? AND consumed=0",
                    (token_hash,))
                if consumed.rowcount!=1:
                    raise AuthorizationDenied("challenge_replayed")
                self.db.execute("COMMIT")
                return counter
            except BaseException:
                self.db.execute("ROLLBACK")
                raise

    def close(self): self.db.close()
