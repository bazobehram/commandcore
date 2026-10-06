import base64
import json
from concurrent.futures import ThreadPoolExecutor

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from commandcore_server.db import Database
from commandcore_server.enrollment import EnrollmentService, init_message


@pytest.fixture
def enrollment(tmp_path):
    db = Database(str(tmp_path / "enrollment.sqlite3"))
    service = EnrollmentService(db, "registry")
    key = Ed25519PrivateKey.generate()
    metadata = dict(
        display_name="test-device",
        hostname="disposable",
        platform="Linux",
        architecture="x86_64",
        agent_version="candidate",
        protocol_version="1",
        public_key_b64=base64.b64encode(
            key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        ).decode(),
        capabilities={"filesystem": True},
        local_ceiling="STANDARD",
    )
    item = service.begin(
        metadata, base64.b64encode(key.sign(init_message(metadata))).decode()
    )
    proof = base64.b64encode(
        key.sign(
            f"commandcore-enroll-claim-v1\n{item['id']}\n{item['poll_token']}".encode()
        )
    ).decode()
    return db, service, key, metadata, item, proof


def approve(service, item, grant=True):
    service.review(item["view_token"], "operator")
    service.decide(
        item["view_token"], "operator", item["verification_code"], True, grant
    )


def test_local_credential_hash_bound_to_approved_identity(enrollment):
    import hashlib
    import secrets
    import uuid

    db, service, key, metadata, _, _ = enrollment
    other_key = Ed25519PrivateKey.generate()
    metadata = {
        **metadata,
        "public_key_b64": base64.b64encode(
            other_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        ).decode(),
        "device_id": str(uuid.uuid4()),
    }
    credential = secrets.token_urlsafe(40)
    metadata["device_token_hash"] = hashlib.sha256(credential.encode()).hexdigest()
    item = service.begin(
        metadata, base64.b64encode(other_key.sign(init_message(metadata))).decode()
    )
    collision_key = Ed25519PrivateKey.generate()
    collision = {
        **metadata,
        "public_key_b64": base64.b64encode(
            collision_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        ).decode(),
    }
    collision_proof = base64.b64encode(
        collision_key.sign(init_message(collision))
    ).decode()
    with pytest.raises(ValueError, match="identity_enrollment_pending"):
        service.begin(collision, collision_proof)
    approve(service, item)
    proof = base64.b64encode(
        other_key.sign(
            f"commandcore-enroll-claim-v1\n{item['id']}\n{item['poll_token']}".encode()
        )
    ).decode()
    result = service.claim(item["poll_token"], proof)
    assert result["credential_source"] == "agent"
    assert "device_token" not in result
    assert result["device_id"] == metadata["device_id"]
    stored_hash = db.conn.execute(
        "SELECT device_token_hash FROM devices WHERE id=?", (result["device_id"],)
    ).fetchone()[0]
    assert stored_hash == metadata["device_token_hash"]
    with pytest.raises(ValueError, match="identity_already_enrolled"):
        service.begin(collision, collision_proof)
    assert (
        credential
        not in db.conn.execute(
            "SELECT metadata_json FROM pending_enrollments WHERE id=?", (item["id"],)
        ).fetchone()[0]
    )
    with pytest.raises(ValueError):
        service.claim(item["poll_token"], proof)


@pytest.mark.parametrize(
    "chosen_id,chosen_hash",
    [
        ("invalid", "a" * 64),
        ("00000000-0000-0000-0000-000000000001", None),
        (None, "a" * 64),
    ],
)
def test_invalid_local_identity_refused(enrollment, chosen_id, chosen_hash):
    _, service, key, metadata, _, _ = enrollment
    metadata = {**metadata, "device_id": chosen_id, "device_token_hash": chosen_hash}
    with pytest.raises(ValueError, match="invalid_local_device_identity"):
        service.begin(
            metadata, base64.b64encode(key.sign(init_message(metadata))).decode()
        )


def test_enrollment_requires_identity_approval_and_explicit_grant(enrollment):
    db, service, key, metadata, item, proof = enrollment
    assert service.claim(item["poll_token"], proof) == {"status": "pending"}
    approve(service, item)
    result = service.claim(item["poll_token"], proof)
    device = db.get_device(result["device_id"])
    assert device["permission_profile"] == "STANDARD"
    assert device["capabilities"]["local_max_permission_profile"] == "STANDARD"
    assert [d["id"] for d in db.list_accessible_devices("operator")] == [
        result["device_id"]
    ]
    assert db.list_accessible_devices("stranger") == []
    with pytest.raises(ValueError, match="consumed"):
        service.claim(item["poll_token"], proof)
    with pytest.raises(ValueError, match="consumed"):
        service.review(item["view_token"], "operator")
    dump = json.dumps(
        [dict(r) for r in db.conn.execute("SELECT * FROM pending_enrollments")]
    )
    audit = json.dumps([dict(r) for r in db.conn.execute("SELECT * FROM audit_events")])
    for secret in (item["view_token"], item["poll_token"], result["device_token"]):
        assert secret not in dump + audit


def test_approval_without_checkbox_creates_no_user_access(enrollment):
    db, service, _, _, item, proof = enrollment
    approve(service, item, False)
    service.claim(item["poll_token"], proof)
    assert db.list_accessible_devices("operator") == []
    assert db.conn.execute("SELECT COUNT(*) FROM device_managers").fetchone()[0] == 1


def test_reviewer_code_and_identity_binding(enrollment):
    _, service, _, _, item, _ = enrollment
    service.review(item["view_token"], "operator")
    with pytest.raises(ValueError):
        service.review(item["view_token"], "other")
    with pytest.raises(ValueError):
        service.decide(item["view_token"], "operator", "AAAA-AAAA", True, True)
    with pytest.raises(ValueError):
        service.decide(
            item["view_token"], "other", item["verification_code"], True, True
        )
    bad_proof = base64.b64encode(Ed25519PrivateKey.generate().sign(b"wrong")).decode()
    with pytest.raises(ValueError, match="identity_proof"):
        service.claim(item["poll_token"], bad_proof)


def test_rejected_expired_malformed_and_duplicate(enrollment):
    db, service, key, metadata, item, proof = enrollment
    with pytest.raises(ValueError, match="pending"):
        service.begin(
            metadata, base64.b64encode(key.sign(init_message(metadata))).decode()
        )
    service.review(item["view_token"], "operator")
    service.decide(
        item["view_token"], "operator", item["verification_code"], False, True
    )
    assert service.claim(item["poll_token"], proof) == {"status": "rejected"}
    assert db.conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 0
    with db.conn:
        db.conn.execute("UPDATE pending_enrollments SET expires_at=0")
    with pytest.raises(ValueError, match="expired"):
        service.claim(item["poll_token"], proof)
    with pytest.raises(ValueError):
        service.review("short", "operator")


def test_claim_is_atomic_and_rate_limit_is_persistent(enrollment):
    db, service, _, _, item, proof = enrollment
    approve(service, item)

    def claim():
        try:
            return service.claim(item["poll_token"], proof)
        except ValueError:
            return None

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _: claim(), range(4)))
    assert sum(r is not None for r in results) == 1
    assert db.conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 1
    service.rate_limit("peer", "decision", 1)
    restarted = EnrollmentService(db, "registry")
    with pytest.raises(ValueError, match="rate_limited"):
        restarted.rate_limit("peer", "decision", 1)


def test_dashboard_decision_requires_prior_same_principal_review(enrollment):
    _, service, _, _, item, proof = enrollment

    def decide(subject):
        return service.decide(
            item["id"],
            subject,
            item["verification_code"],
            True,
            True,
            reviewed_id=True,
        )

    with pytest.raises(ValueError):
        decide("operator")
    service.review(item["view_token"], "operator")
    with pytest.raises(ValueError):
        decide("stranger")
    assert decide("operator") == {"status": "approved"}
    with pytest.raises(ValueError):
        decide("operator")
    service.claim(item["poll_token"], proof)
    with pytest.raises(ValueError):
        decide("operator")
