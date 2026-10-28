import asyncio,base64,hashlib,json,os,struct,tempfile,unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from commandcore_server.collaboration_approval import Approval,ApprovalLedger,AuthorizationDenied,action_digest
from commandcore_server.collaboration_review_challenge import ReviewChallenges
from commandcore_server.collaboration_webauthn_credentials import CredentialRegistry
from commandcore_server.collaboration_webauthn_review import verify_review_assertion
class ReviewTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory()
  self.ledger=ApprovalLedger(os.path.join(self.tmp.name,"ledger.db"))
  self.challenges=ReviewChallenges(os.path.join(self.tmp.name,"shared.db"))
  self.registry=CredentialRegistry(os.path.join(self.tmp.name,"shared.db"))
  self.key=Ed25519PrivateKey.generate()
  self.registry.add_preverified(owner="owner",credential_id="cred",public_key_raw=self.key.public_key().public_bytes(
   encoding=serialization.Encoding.Raw,format=serialization.PublicFormat.Raw))
  self.text="QA only";digest=hashlib.sha256(self.text.encode()).hexdigest()
  action=action_digest(device_id="gx10",window_id="0x4",title="QA",process_id=42,
   process_start=33,draft_id="draft",draft_sha256=digest,input_x=100,input_y=200,send_key="Return")
  self.ledger.create(Approval("req","owner","gx10","0x4","QA",42,33,"draft",digest,action,100,700))
  self.challenge=self.challenges.issue(owner="owner",request_id="req",action_digest=action,now=110)
  self.data={"draft_id":"draft","window_id":"0x4","title":"QA","pid":42,"process_start":33,
   "text":self.text,"input_x":100,"input_y":200,"send_key":"Return",
   "preview_only":True,"delivery_authorized":False}
  self.agents=SimpleNamespace(connections={"gx10":object()},
   dispatch=AsyncMock(return_value=SimpleNamespace(status="ok",result=self.data)))
  self.authdata=hashlib.sha256(b"panel.example.test").digest()+bytes([5])+struct.pack(">I",1)
 def tearDown(self):self.registry.close();self.challenges.close();self.ledger.close();self.tmp.cleanup()
 def run_review(self,**changed):
  challenge=changed.pop("review_challenge",self.challenge)
  client=json.dumps({"type":"webauthn.get","origin":"https://panel.example.test",
    "challenge":base64.urlsafe_b64encode(challenge.encode()).rstrip(b"=").decode()}).encode()
  params=dict(ledger=self.ledger,challenges=self.challenges,registry=self.registry,
   agents=self.agents,device={"id":"gx10"},owner_subject="owner",request_id="req",
   review_challenge=challenge,credential_id="cred",authenticator_data=self.authdata,
   client_data_json=client,signature=self.key.sign(self.authdata+hashlib.sha256(client).digest()),
   expected_origin="https://panel.example.test",expected_rp_id="panel.example.test",now=111)
  params.update(changed)
  return asyncio.run(verify_review_assertion(**params))
 def test_verified_review_never_authorizes_delivery(self):
  result=self.run_review()
  self.assertFalse(result["delivery_authorized"])
  self.assertEqual([x.kwargs["tool"] for x in self.agents.dispatch.await_args_list],["agents.preview"])
  self.assertEqual(self.ledger.get(owner_subject="owner",request_id="req").status,"pending")
 def test_tampered_draft_rejected_before_credential(self):
  self.data["input_x"]=101
  with self.assertRaises(AuthorizationDenied):self.run_review()
  self.assertEqual(self.registry.db.execute("SELECT sign_count FROM credentials").fetchone()[0],0)
 def test_wrong_owner_rejected(self):
  with self.assertRaises(AuthorizationDenied):self.run_review(owner_subject="intruder")
  self.agents.dispatch.assert_not_awaited()
 def test_revoked_challenge_does_not_advance_counter(self):
  self.challenges.issue(owner="owner",request_id="req",action_digest=
   self.ledger.get(owner_subject="owner",request_id="req").action_digest,now=111)
  with self.assertRaises(AuthorizationDenied):self.run_review()
  self.assertEqual(self.registry.db.execute("SELECT sign_count FROM credentials").fetchone()[0],0)
 def test_different_databases_fail_closed(self):
  alternate=CredentialRegistry(os.path.join(self.tmp.name,"separate.db"))
  try:
   with self.assertRaises(AuthorizationDenied):self.run_review(registry=alternate)
   self.assertEqual(self.challenges.db.execute("SELECT consumed FROM review_challenges").fetchone()[0],0)
   self.assertEqual(self.registry.db.execute("SELECT sign_count FROM credentials").fetchone()[0],0)
  finally:alternate.close()
 def test_verified_assertion_cannot_issue_positive_approval(self):
  from commandcore_server.collaboration_authorization import TrustedAuthorization
  from unittest.mock import Mock
  verified=self.run_review()
  self.assertTrue(verified["credential_verified"])
  self.assertFalse(verified["delivery_authorized"])
  issuer=Mock()
  gate=TrustedAuthorization(ledger=self.ledger,issuer=issuer)
  with self.assertRaisesRegex(AuthorizationDenied,"human_authenticator_not_configured"):
   gate.authorize_and_issue(request_id="req",owner_subject="owner",actor_attested=True,now=112)
  issuer.assert_not_called()
  self.assertEqual(self.ledger.get(owner_subject="owner",request_id="req").status,"pending")
 def test_invalid_signature_keeps_review_pending_and_counter_unchanged(self):
  with self.assertRaises(AuthorizationDenied):self.run_review(signature=b"x"*64)
  self.assertEqual(self.registry.db.execute("SELECT sign_count FROM credentials").fetchone()[0],0)
  self.assertEqual(self.challenges.db.execute("SELECT consumed FROM review_challenges").fetchone()[0],0)
  self.assertEqual(self.ledger.get(owner_subject="owner",request_id="req").status,"pending")
 def test_replay_rejected(self):
  self.run_review()
  with self.assertRaises(AuthorizationDenied):self.run_review()
if __name__=="__main__":unittest.main()
