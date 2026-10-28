import base64,dataclasses,unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from commandcore_server.collaboration_human_assertion import HumanAssertion,assertion_bytes,verify_human_assertion
from commandcore_server.collaboration_approval import AuthorizationDenied
class AssertionTests(unittest.TestCase):
 def setUp(self):
  self.key=Ed25519PrivateKey.generate()
  self.a=HumanAssertion("owner","req","a"*64,"token",150,"credential",True,"")
  self.a=dataclasses.replace(self.a,signature_b64=base64.b64encode(self.key.sign(assertion_bytes(self.a))).decode())
 def check(self,a=None,**kwargs):
  p=dict(assertion=self.a if a is None else a,public_key=self.key.public_key(),
      expected_owner="owner",expected_request="req",expected_action="a"*64,
      expected_challenge="token",expected_credential="credential",now=110)
  p.update(kwargs)
  verify_human_assertion(**p)
 def test_signature_and_intent(self): self.check()
 def test_false_user_verification_rejected(self):
  with self.assertRaises(AuthorizationDenied): self.check(dataclasses.replace(self.a,user_verified=False))
 def test_wrong_owner_rejected(self):
  with self.assertRaises(AuthorizationDenied): self.check(expected_owner="intruder")
 def test_wrong_action_rejected(self):
  with self.assertRaises(AuthorizationDenied): self.check(expected_action="b"*64)
 def test_wrong_challenge_rejected(self):
  with self.assertRaises(AuthorizationDenied): self.check(expected_challenge="other")
 def test_expired_rejected(self):
  with self.assertRaises(AuthorizationDenied): self.check(now=150)
 def test_modified_signed_data_rejected(self):
  with self.assertRaises(AuthorizationDenied): self.check(dataclasses.replace(self.a,request_id="different"))
 def test_oversized_signature_rejected(self):
  with self.assertRaises(AuthorizationDenied):self.check(dataclasses.replace(self.a,signature_b64="A"*10000))
 def test_boolean_expiry_rejected(self):
  with self.assertRaises(AuthorizationDenied):self.check(dataclasses.replace(self.a,expires_at=True))
 def test_invalid_signature_length_rejected(self):
  with self.assertRaises(AuthorizationDenied):self.check(dataclasses.replace(self.a,signature_b64=base64.b64encode(b"x"*65).decode()))
 def test_wrong_public_key_rejected(self):
  with self.assertRaises(AuthorizationDenied): self.check(public_key=Ed25519PrivateKey.generate().public_key())
if __name__=="__main__":unittest.main()
