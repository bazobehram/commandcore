import asyncio,os,tempfile,unittest
from hashlib import sha256
from types import SimpleNamespace
from unittest.mock import AsyncMock
from commandcore_server.collaboration_approval import Approval,ApprovalLedger,AuthorizationDenied,action_digest
from commandcore_server.collaboration_review_challenge import ReviewChallenges
from commandcore_server.collaboration_review_session import prepare_review_challenge

class SessionTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory()
  self.ledger=ApprovalLedger(os.path.join(self.tmp.name,"ledger.sqlite"))
  self.challenges=ReviewChallenges(os.path.join(self.tmp.name,"challenge.sqlite"))
  text="Disposable review payload"
  digest=sha256(text.encode()).hexdigest()
  action=action_digest(device_id="gx10",window_id="0x4",title="QA",process_id=42,
   process_start=33,draft_id="draft",draft_sha256=digest,input_x=100,input_y=200,send_key="Return")
  self.ledger.create(Approval("req","owner","gx10","0x4","QA",42,33,"draft",digest,action,100,700))
  self.preview={"draft_id":"draft","window_id":"0x4","title":"QA","pid":42,"process_start":33,
   "text":text,"input_x":100,"input_y":200,"send_key":"Return",
   "preview_only":True,"delivery_authorized":False}
  self.agents=SimpleNamespace(connections={"gx10":object()},
    dispatch=AsyncMock(return_value=SimpleNamespace(status="ok",result=self.preview)))
 def tearDown(self):self.challenges.close();self.ledger.close();self.tmp.cleanup()
 def issue(self,**override):
  params=dict(ledger=self.ledger,challenges=self.challenges,agents=self.agents,
   device={"id":"gx10"},owner_subject="owner",request_id="req",now=110)
  params.update(override)
  return asyncio.run(prepare_review_challenge(**params))
 def test_valid_preview_issues_replay_protected_challenge(self):
  r=self.issue()
  self.assertFalse(r["delivery_authorized"])
  self.challenges.consume(token=r["challenge"],owner="owner",request_id="req",
   action_digest=r["action_sha256"],now=111)
  with self.assertRaises(AuthorizationDenied):
   self.challenges.consume(token=r["challenge"],owner="owner",request_id="req",
    action_digest=r["action_sha256"],now=112)
 def test_near_expiry_challenge_bound_to_approval(self):
  issued=self.issue(now=695)
  self.assertEqual(issued["expires_at"],700)
  with self.assertRaises(AuthorizationDenied):
   self.challenges.consume(token=issued["challenge"],owner="owner",
    request_id="req",action_digest=issued["action_sha256"],now=700)
 def test_modified_draft_cannot_mint_challenge(self):
  self.preview["input_x"]=101
  with self.assertRaises(AuthorizationDenied):self.issue()
  self.assertEqual(self.challenges.db.execute("SELECT count(*) FROM review_challenges").fetchone()[0],0)
 def test_foreign_owner_cannot_mint_challenge(self):
  with self.assertRaises(AuthorizationDenied):self.issue(owner_subject="intruder")
  self.agents.dispatch.assert_not_awaited()
 def test_offline_cannot_mint_challenge(self):
  self.agents.connections={}
  with self.assertRaises(AuthorizationDenied):self.issue()
  self.agents.dispatch.assert_not_awaited()
if __name__=="__main__":unittest.main()
