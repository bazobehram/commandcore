import asyncio
import os
import tempfile
import unittest
from unittest.mock import AsyncMock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from commandcore_server.collaboration_approval import Approval, ApprovalLedger, AuthorizationDenied
from commandcore_server.collaboration_permit_issuer import Issuer
from commandcore_server.collaboration_authorization import TrustedAuthorization
from commandcore_server.collaboration_trusted_dispatch import authorize_and_dispatch


class DispatchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.ledger = ApprovalLedger(os.path.join(self.tmp.name, "qa.db"))
        self.ledger.create(Approval("req", "owner", "gx10", "0x1", "QA", 42, 33,
                                    "draft", "a"*64, "b"*64, 100, 700))
        self.authority = TrustedAuthorization(
            self.ledger, Issuer("trusted", "owner", Ed25519PrivateKey.generate()))
        self.agents = type("Agents", (), {})()
        self.agents.dispatch = AsyncMock(return_value={"status": "declined"})
        self.agents.connections = {"gx10": object()}

    def tearDown(self):
        self.ledger.close()
        self.tmp.cleanup()

    def invoke(self, **kwargs):
        return asyncio.run(authorize_and_dispatch(
            authority=self.authority, agents=self.agents,
            device={"id":"gx10"}, request_id="req", owner_subject="owner",
            actor_attested=True, now=110, **kwargs))

    @unittest.skip("requires trusted enrolled authenticator")
    def test_signed_internal_dispatch(self):
        result = self.invoke()
        self.assertEqual(result["status"], "declined")
        call = self.agents.dispatch.await_args.kwargs
        self.assertEqual(call["tool"], "agents.deliver")
        self.assertEqual(call["arguments"]["draft_id"], "draft")
        self.assertIn("signature_b64", call["arguments"]["signed_permit"])
        self.assertEqual(self.ledger.get(owner_subject="owner",request_id="req").status,"consumed")

    @unittest.skip("requires trusted enrolled authenticator")
    def test_no_second_dispatch(self):
        self.invoke()
        with self.assertRaises(AuthorizationDenied): self.invoke()
        self.assertEqual(self.agents.dispatch.await_count, 1)

    def test_unattested_never_dispatches(self):
        with self.assertRaises(AuthorizationDenied):
            asyncio.run(authorize_and_dispatch(
                authority=self.authority, agents=self.agents,device={"id":"gx10"},
                request_id="req",owner_subject="owner",actor_attested=False,now=110))
        self.agents.dispatch.assert_not_awaited()

    def test_missing_connection_registry_rejected(self):
        del self.agents.connections
        with self.assertRaises(AuthorizationDenied):
            self.invoke()
        self.agents.dispatch.assert_not_awaited()
        self.assertEqual(self.ledger.get(owner_subject="owner", request_id="req").status, "pending")

    def test_null_connection_rejected(self):
        self.agents.connections = {"gx10": None}
        with self.assertRaises(AuthorizationDenied):
            self.invoke()
        self.agents.dispatch.assert_not_awaited()

    def test_offline_device_does_not_consume_approval(self):
        self.agents.connections = {}
        with self.assertRaises(AuthorizationDenied):
            self.invoke()
        self.agents.dispatch.assert_not_awaited()
        self.assertEqual(self.ledger.get(owner_subject="owner", request_id="req").status, "pending")

    def test_other_issuer_owner_does_not_consume_approval(self):
        self.authority = TrustedAuthorization(
            self.ledger, Issuer("trusted", "other", Ed25519PrivateKey.generate()))
        with self.assertRaises(AuthorizationDenied):
            self.invoke()
        self.agents.dispatch.assert_not_awaited()
        self.assertEqual(self.ledger.get(owner_subject="owner", request_id="req").status, "pending")

    def test_positive_boolean_fails_closed_without_credential(self):
        with self.assertRaises(AuthorizationDenied):
            self.invoke()
        self.agents.dispatch.assert_not_awaited()
        self.assertEqual(self.ledger.get(owner_subject="owner",request_id="req").status,"pending")

    def test_truthy_string_never_dispatches(self):
        with self.assertRaises(AuthorizationDenied):
            asyncio.run(authorize_and_dispatch(
                authority=self.authority, agents=self.agents, device={"id":"gx10"},
                request_id="req", owner_subject="owner", actor_attested="yes", now=110))
        self.agents.dispatch.assert_not_awaited()
        self.assertEqual(self.ledger.get(owner_subject="owner", request_id="req").status, "pending")

    def test_wrong_device_never_dispatches(self):
        with self.assertRaises(AuthorizationDenied):
            asyncio.run(authorize_and_dispatch(
                authority=self.authority, agents=self.agents,device={"id":"another"},
                request_id="req",owner_subject="owner",actor_attested=True,now=110))
        self.agents.dispatch.assert_not_awaited()

if __name__=="__main__":unittest.main()
