"""Offline signed permit contract tests; no remote approval or GUI actions."""
import base64
import json
import tempfile
import threading
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from commandcore_server.collaboration_approval import Approval, ApprovalLedger, AuthorizationDenied
from commandcore_server.collaboration_permit_issuer import DOMAIN, Issuer


class PermitIssuerTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.ledger = ApprovalLedger(str(Path(self.temp.name) / "ledger.db"))
        self.issuer = Issuer("issuer-A", "owner-A", Ed25519PrivateKey.generate())

    def tearDown(self):
        self.ledger.close()
        self.temp.cleanup()

    def proposal(self, identifier, *, owner="owner-A", approve=False):
        self.ledger.create(Approval(
            identifier, owner, "gx10", "0x1234", "Fixture", 50, 99,
            identifier, "a" * 64, "b" * 64, 100, 700))
        if approve:
            self.ledger.decide(
                request_id=identifier, owner_subject=owner, actor_subject=owner,
                actor_attested=True, decision="approve", now=110)

    def test_unapproved_and_cross_owner_fail_closed(self):
        self.proposal("pending")
        self.proposal("other", owner="owner-B", approve=True)
        for request in ("pending", "other"):
            with self.assertRaises(AuthorizationDenied):
                self.issuer.issue(self.ledger, request_id=request, now=111)

    def test_signed_payload_replay_and_expiry(self):
        self.proposal("approved", approve=True)
        envelope = self.issuer.issue(self.ledger, request_id="approved", now=111)
        permit = envelope["permit"]
        payload = DOMAIN + json.dumps(permit, separators=(",", ":"), ensure_ascii=False).encode()
        self.issuer.private_key.public_key().verify(
            base64.b64decode(envelope["signature_b64"]), payload)
        self.assertLessEqual(permit["expires_at"] - permit["issued_at"], 120)
        with self.assertRaises(AuthorizationDenied):
            self.issuer.issue(self.ledger, request_id="approved", now=112)

    def test_concurrent_single_issuance(self):
        self.proposal("race", approve=True)
        outcome = []
        def attempt():
            try:
                self.issuer.issue(self.ledger, request_id="race", now=111)
                outcome.append("issued")
            except AuthorizationDenied:
                outcome.append("denied")
        workers = [threading.Thread(target=attempt) for _ in range(12)]
        for thread in workers:
            thread.start()
        for thread in workers:
            thread.join()
        self.assertEqual(outcome.count("issued"), 1)
        self.assertEqual(outcome.count("denied"), 11)

    def test_expired_request_fails(self):
        self.proposal("expired", approve=True)
        with self.assertRaises(AuthorizationDenied):
            self.issuer.issue(self.ledger, request_id="expired", now=701)


if __name__ == "__main__":
    unittest.main()
