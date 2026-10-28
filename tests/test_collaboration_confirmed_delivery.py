import asyncio,os,tempfile,unittest
from hashlib import sha256
from types import SimpleNamespace
from unittest.mock import AsyncMock
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from commandcore_server.collaboration_approval import Approval,ApprovalLedger,AuthorizationDenied,action_digest
from commandcore_server.collaboration_review_challenge import ReviewChallenges
from commandcore_server.collaboration_authorization import TrustedAuthorization
from commandcore_server.collaboration_permit_issuer import Issuer
from commandcore_server.collaboration_confirmed_delivery import confirm_review_and_dispatch
from commandcore_server.collaboration_review_session import prepare_review_challenge

class ConfirmationTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory()
  self.ledger=ApprovalLedger(os.path.join(self.tmp.name,"ledger.db"))
  self.challenges=ReviewChallenges(os.path.join(self.tmp.name,"tokens.db"))
  text="Disposable review"
  digest=sha256(text.encode()).hexdigest()
  action=action_digest(device_id="gx10",window_id="0x4",title="QA",process_id=42,
    process_start=33,draft_id="draft",draft_sha256=digest,input_x=100,input_y=200,send_key="Return")
  self.ledger.create(Approval("req","owner","gx10","0x4","QA",42,33,"draft",digest,action,100,700))
  self.data={"draft_id":"draft","window_id":"0x4","title":"QA","pid":42,"process_start":33,
    "text":text,"input_x":100,"input_y":200,"send_key":"Return",
    "preview_only":True,"delivery_authorized":False}
  self.agents=SimpleNamespace(connections={"gx10":object()})
  async def dispatch(**kw):
   if kw["tool"]=="agents.preview":
    return SimpleNamespace(status="ok",result=self.data)
   return SimpleNamespace(status="ok",result={"state":"declined","sent":False})
  self.agents.dispatch=AsyncMock(side_effect=dispatch)
  self.authority=TrustedAuthorization(self.ledger,Issuer("trusted","owner",Ed25519PrivateKey.generate()))
  self.device={"id":"gx10"}
  self.token=asyncio.run(prepare_review_challenge(ledger=self.ledger,challenges=self.challenges,
    agents=self.agents,device=self.device,owner_subject="owner",request_id="req",now=110))["challenge"]
  self.agents.dispatch.reset_mock()
 def tearDown(self):
  self.ledger.close();self.challenges.close();self.tmp.cleanup()
 def confirm(self,**changes):
  args=dict(authority=self.authority,challenges=self.challenges,agents=self.agents,
    device=self.device,owner_subject="owner",request_id="req",
    challenge=self.token,human_attested=True,now=111)
  args.update(changes)
  return asyncio.run(confirm_review_and_dispatch(**args))
 def test_fail_closed_does_not_consume_challenge_or_contact_agent(self):
  with self.assertRaises(AuthorizationDenied):self.confirm()
  self.assertEqual(self.ledger.get(owner_subject="owner",request_id="req").status,"pending")
  row=self.challenges.db.execute("SELECT consumed FROM review_challenges").fetchone()
  self.assertEqual(row,(0,))
  self.agents.dispatch.assert_not_awaited()
 def test_configured_boolean_cannot_authorize(self):
  with self.assertRaises(AuthorizationDenied):self.confirm()
  self.agents.dispatch.assert_not_awaited()
 def test_truthy_non_boolean_never_authorizes(self):
  with self.assertRaises(AuthorizationDenied):self.confirm(human_attested="true")
  self.agents.dispatch.assert_not_awaited()
 @unittest.skip("requires credential-backed human authenticator")
 def test_foreign_owner_cannot_confirm(self):
  with self.assertRaises(AuthorizationDenied):self.confirm(owner_subject="intruder")
  self.assertEqual([x.kwargs["tool"] for x in self.agents.dispatch.await_args_list].count("agents.deliver"),0)
 def test_unattested_fails_before_preview(self):
  with self.assertRaises(AuthorizationDenied):self.confirm(human_attested=False)
  self.agents.dispatch.assert_not_awaited()
 @unittest.skip("requires credential-backed human authenticator")
 def test_changed_action_rejected_without_delivery(self):
  self.data["input_x"]=101
  with self.assertRaises(AuthorizationDenied):self.confirm()
  self.assertEqual(self.agents.dispatch.await_count,1)
 @unittest.skip("requires credential-backed human authenticator")
 def test_replay_rejected(self):
  self.confirm()
  with self.assertRaises(AuthorizationDenied):self.confirm()
  self.assertEqual([x.kwargs["tool"] for x in self.agents.dispatch.await_args_list].count("agents.deliver"),1)
 @unittest.skip("requires credential-backed human authenticator")
 def test_expired_challenge_rejected(self):
  with self.assertRaises(AuthorizationDenied):self.confirm(now=201)
  self.assertEqual([x.kwargs["tool"] for x in self.agents.dispatch.await_args_list].count("agents.deliver"),0)
if __name__=="__main__":unittest.main()
