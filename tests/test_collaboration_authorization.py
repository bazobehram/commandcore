import os
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from commandcore_server.collaboration_approval import Approval, ApprovalLedger, AuthorizationDenied
from commandcore_server.collaboration_permit_issuer import Issuer
from commandcore_server.collaboration_authorization import TrustedAuthorization


class AuthorizationTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.ledger = ApprovalLedger(os.path.join(self.temp.name, "qa.db"))
        self.service = TrustedAuthorization(
            self.ledger, Issuer("trusted-issuer", "owner-A", Ed25519PrivateKey.generate()))
        self.ledger.create(Approval(
            "request", "owner-A", "gx10", "0x1", "QA", 42, 33, "draft",
            "a"*64, "b"*64, 100, 700,
        ))

    def tearDown(self):
        self.ledger.close()
        self.temp.cleanup()

    def test_unattested_rejected_without_state_change(self):
        with self.assertRaises(AuthorizationDenied):
            self.service.authorize_and_issue(
                request_id="request", owner_subject="owner-A", actor_attested=False, now=110)
        self.assertEqual(self.ledger.get(owner_subject="owner-A", request_id="request").status,"pending")

    def test_truthy_string_rejected_without_state_change(self):
        with self.assertRaises(AuthorizationDenied):
            self.service.authorize_and_issue(
                request_id="request", owner_subject="owner-A", actor_attested="true", now=110)
        self.assertEqual(self.ledger.get(owner_subject="owner-A",request_id="request").status,"pending")

    def test_wrong_owner_rejected_without_state_change(self):
        with self.assertRaises(AuthorizationDenied):
            self.service.authorize_and_issue(
                request_id="request", owner_subject="owner-B", actor_attested=True, now=110)
        self.assertEqual(self.ledger.get(owner_subject="owner-A", request_id="request").status,"pending")

    def test_denied_request_cannot_be_signed_even_with_attestation(self):
        self.ledger.decide(
            request_id="request", owner_subject="owner-A",
            actor_subject="owner-A", actor_attested=True,
            decision="deny", now=110)
        with self.assertRaises(AuthorizationDenied):
            self.service.authorize_and_issue(
                request_id="request", owner_subject="owner-A",
                actor_attested=True, now=111)
        with self.assertRaises(AuthorizationDenied):
            self.service.issuer.issue(self.ledger, request_id="request", now=111)
        self.assertEqual(
            self.ledger.get(owner_subject="owner-A", request_id="request").status,
            "denied")

    def test_expired_request_cannot_be_attested_later(self):
        with self.assertRaises(AuthorizationDenied):
            self.service.authorize_and_issue(
                request_id="request", owner_subject="owner-A",
                actor_attested=True, now=701)
        self.assertEqual(
            self.ledger.get(owner_subject="owner-A", request_id="request").status,
            "pending")

    def test_authorization_is_fail_closed_for_all_attestation_values(self):
        # Neither a truthy value nor a fabricated principal can authorize a permit.
        for actor in (None, False, True, 0, 1, "", "true", {"verified": True}, [True]):
            with self.subTest(actor=repr(actor)):
                with self.assertRaisesRegex(AuthorizationDenied, "human_authenticator_not_configured"):
                    self.service.authorize_and_issue(
                        request_id="request", owner_subject="owner-A",
                        actor_attested=actor, now=110)
                self.assertEqual(
                    self.ledger.get(owner_subject="owner-A", request_id="request").status,
                    "pending")

    @unittest.skip("credential-backed authenticator not provisioned")
    def test_attested_approved_signed_and_consumed(self):
        permit = self.service.authorize_and_issue(
            request_id="request", owner_subject="owner-A", actor_attested=True, now=110)
        self.assertEqual(permit["permit"]["owner_subject"], "owner-A")
        self.assertEqual(self.ledger.get(owner_subject="owner-A",request_id="request").status,"consumed")
        with self.assertRaises(AuthorizationDenied):
            self.service.authorize_and_issue(
                request_id="request", owner_subject="owner-A", actor_attested=True, now=111)

if __name__=="__main__":
    unittest.main()
