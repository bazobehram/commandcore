import os,tempfile,unittest
from concurrent.futures import ThreadPoolExecutor
from commandcore_server.collaboration_review_challenge import ReviewChallenges
from commandcore_server.collaboration_approval import AuthorizationDenied

class ChallengeTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory()
  self.store=ReviewChallenges(os.path.join(self.temp.name,"challenges.sqlite"))
  self.token=self.store.issue(owner="owner",request_id="req",action_digest="a"*64,now=100)
 def tearDown(self):self.store.close();self.temp.cleanup()
 def consume(self,**change):
  args=dict(token=self.token,owner="owner",request_id="req",action_digest="a"*64,now=101)
  args.update(change)
  self.store.consume(**args)
 def test_once(self):
  self.consume()
  with self.assertRaises(AuthorizationDenied):self.consume()
 def test_owner_binding(self):
  with self.assertRaises(AuthorizationDenied):self.consume(owner="other")
  self.consume()
 def test_action_binding(self):
  with self.assertRaises(AuthorizationDenied):self.consume(action_digest="b"*64)
  self.consume()
 def test_expiry(self):
  with self.assertRaises(AuthorizationDenied):self.consume(now=190)
 def test_non_hex_action_binding_rejected(self):
  with self.assertRaises(AuthorizationDenied):
   self.store.issue(owner="owner",request_id="bad",action_digest="Z"*64,now=100)
 def test_oversized_token_rejected(self):
  with self.assertRaises(AuthorizationDenied):self.consume(token="x"*10000)
 def test_new_challenge_revokes_previous_tab(self):
  newer=self.store.issue(owner="owner",request_id="req",action_digest="a"*64,now=102)
  with self.assertRaises(AuthorizationDenied):self.consume(now=103)
  self.store.consume(token=newer,owner="owner",request_id="req",action_digest="a"*64,now=103)
 def test_concurrent_two_connections_only_one_can_consume(self):
  other=ReviewChallenges(os.path.join(self.temp.name,"challenges.sqlite"))
  try:
   def attempt(store):
    try:
     store.consume(token=self.token,owner="owner",request_id="req",
                   action_digest="a"*64,now=101)
     return True
    except AuthorizationDenied:
     return False
   with ThreadPoolExecutor(max_workers=2) as pool:
    results=list(pool.map(attempt,(self.store,other)))
   self.assertEqual(results.count(True),1)
   self.assertEqual(results.count(False),1)
  finally:
   other.close()
 def test_unknown(self):
  with self.assertRaises(AuthorizationDenied):self.consume(token="other")
if __name__=="__main__":unittest.main()
