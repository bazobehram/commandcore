"""Owner-scoped staging registration ceremony, no HTTP/MCP enrollment route."""
import json
import dataclasses
import enum
import base64
import sqlite3
import threading
from .collaboration_approval import AuthorizationDenied
from .collaboration_registration_fido2 import verify_registration

class RegistrationCeremonies:
    def __init__(self, path):
        self.db=sqlite3.connect(path,check_same_thread=False,isolation_level=None)
        self.lock=threading.RLock()
        self.db.execute("""CREATE TABLE IF NOT EXISTS registration_ceremonies(
            owner TEXT NOT NULL, challenge TEXT PRIMARY KEY, state TEXT NOT NULL,
            rp_id TEXT NOT NULL, origin TEXT NOT NULL, expires INTEGER NOT NULL,
            consumed INTEGER NOT NULL DEFAULT 0)""")

    def begin(self, *, owner, rp_id, origin, now):
        try:
            from fido2.server import Fido2Server
            from fido2.webauthn import (PublicKeyCredentialRpEntity,
                PublicKeyCredentialUserEntity,UserVerificationRequirement,
                PublicKeyCredentialParameters,PublicKeyCredentialType,ResidentKeyRequirement)
        except ImportError:
            raise AuthorizationDenied("fido2_dependency_missing") from None
        if not owner or not rp_id or origin != "https://"+rp_id:
            raise AuthorizationDenied("registration_identity_invalid")
        server=Fido2Server(PublicKeyCredentialRpEntity(id=rp_id,name="CommandCore"),
                           verify_origin=lambda presented: presented == origin)
        # The registry only accepts Ed25519/EdDSA (COSE alg -8).
        server.allowed_algorithms=[PublicKeyCredentialParameters(
            type=PublicKeyCredentialType.PUBLIC_KEY,alg=-8)]
        options,state=server.register_begin(
            PublicKeyCredentialUserEntity(id=owner.encode(),name=owner,display_name=owner),
            user_verification=UserVerificationRequirement.REQUIRED,
            resident_key_requirement=ResidentKeyRequirement.REQUIRED)
        serialized={"challenge":state["challenge"],"user_verification":"required"}
        with self.lock:
            self.db.execute("INSERT INTO registration_ceremonies VALUES(?,?,?,?,?,?,0)",
                (owner,serialized["challenge"],json.dumps(serialized),rp_id,origin,now+120))
        def serialize(value):
            if isinstance(value,bytes):
                return base64.urlsafe_b64encode(value).rstrip(b"=").decode()
            if isinstance(value,enum.Enum):
                return value.value
            raise TypeError("unsupported creation option")
        def browser_keys(value):
            if isinstance(value,dict):
                return {"".join(part.capitalize() if i else part
                        for i,part in enumerate(key.split("_"))):browser_keys(item)
                        for key,item in value.items() if item is not None}
            if isinstance(value,list):
                return [browser_keys(item) for item in value]
            return value
        options_json=browser_keys(json.loads(json.dumps(dataclasses.asdict(options),default=serialize)))
        return {"options":options_json,"challenge":serialized["challenge"],
                "expires_at":now+120}

    def finish_verified(self, *, owner, challenge, response, now):
        # Consume a ceremony on any attempt. Do not persist credentials here.
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                row=self.db.execute(
                    "SELECT state,rp_id,origin,expires,consumed FROM registration_ceremonies WHERE owner=? AND challenge=?",
                    (owner,challenge)).fetchone()
                if not row or row[4] or now>=row[3]:
                    raise AuthorizationDenied("registration_not_pending")
                self.db.execute("UPDATE registration_ceremonies SET consumed=1 WHERE owner=? AND challenge=?",
                                (owner,challenge))
                self.db.execute("COMMIT")
            except BaseException:
                self.db.execute("ROLLBACK")
                raise
        return verify_registration(rp_id=row[1],origin=row[2],state=json.loads(row[0]),response=response)

    def finish_and_enroll(self, *, registry, owner, challenge, response, now):
        """Fail closed unless the ceremony and credential DB are the same file.

        This staging-only adapter accepts only verified Ed25519 COSE keys.
        """
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from .collaboration_approval import AuthorizationDenied
        own=self.db.execute("PRAGMA database_list").fetchone()[2]
        other=registry.db.execute("PRAGMA database_list").fetchone()[2]
        if not own or own!=other:
            raise AuthorizationDenied("registration_storage_not_atomic")
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                row=self.db.execute(
                    "SELECT state,rp_id,origin,expires,consumed FROM registration_ceremonies WHERE owner=? AND challenge=?",
                    (owner,challenge)).fetchone()
                if not row or row[4] or now>=row[3]:
                    raise AuthorizationDenied("registration_not_pending")
                credential=verify_registration(
                    rp_id=row[1],origin=row[2],state=json.loads(row[0]),response=response)
                try:
                    cose=credential.public_key
                    key=cose[-2]
                    if (cose[1]!=1 or cose[3]!=-8 or cose[-1]!=6
                            or not isinstance(key,bytes) or len(key)!=32):
                        raise AuthorizationDenied("registration_key_algorithm_unsupported")
                    Ed25519PublicKey.from_public_bytes(key)
                except (KeyError,ValueError,TypeError):
                    raise AuthorizationDenied("registration_key_algorithm_unsupported") from None
                self.db.execute(
                    "INSERT INTO credentials(owner,credential_id,public_key) VALUES(?,?,?)",
                    (owner,base64.urlsafe_b64encode(credential.credential_id).rstrip(b"=").decode(),key))
                updated=self.db.execute(
                    "UPDATE registration_ceremonies SET consumed=1 WHERE owner=? AND challenge=? AND consumed=0",
                    (owner,challenge))
                if updated.rowcount!=1:
                    raise AuthorizationDenied("registration_replayed")
                self.db.execute("COMMIT")
                return {"credential_id":base64.urlsafe_b64encode(credential.credential_id).rstrip(b"=").decode(),"enrolled":True}
            except BaseException:
                self.db.execute("ROLLBACK")
                raise

    def close(self): self.db.close()
