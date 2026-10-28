import base64, hashlib, json, struct, unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from commandcore_server.collaboration_webauthn_assertion import verify_assertion
from commandcore_server.collaboration_approval import AuthorizationDenied

class WebAuthnTests(unittest.TestCase):
 def setUp(self):
  self.private=Ed25519PrivateKey.generate()
  self.challenge=b"x"*32
  self.client=json.dumps({"type":"webauthn.get","origin":"https://panel.example.test",
    "challenge":base64.urlsafe_b64encode(self.challenge).rstrip(b"=").decode(),
    "crossOrigin":False}).encode()
  self.data=hashlib.sha256(b"panel.example.test").digest()+bytes([5])+struct.pack(">I",2)
 def verify(self, **changes):
  d=dict(public_key=self.private.public_key(),authenticator_data=self.data,
    client_data_json=self.client,signature=self.private.sign(self.data+hashlib.sha256(self.client).digest()),
    expected_challenge=self.challenge,expected_origin="https://panel.example.test",
    expected_rp_id="panel.example.test",previous_sign_count=1)
  d.update(changes)
  return verify_assertion(**d)
 def test_valid(self):self.assertEqual(self.verify(),2)
 def test_wrong_origin(self):
  with self.assertRaises(AuthorizationDenied):self.verify(expected_origin="https://elsewhere.test")
 def test_wrong_challenge(self):
  with self.assertRaises(AuthorizationDenied):self.verify(expected_challenge=b"y"*32)
 def test_wrong_rp(self):
  with self.assertRaises(AuthorizationDenied):self.verify(expected_rp_id="elsewhere.test")
 def test_without_user_verification(self):
  data=self.data[:32]+bytes([1])+self.data[33:]
  with self.assertRaises(AuthorizationDenied):self.verify(authenticator_data=data)
 def test_replay_counter(self):
  with self.assertRaises(AuthorizationDenied):self.verify(previous_sign_count=2)
 def test_zero_counter_after_positive_is_rejected(self):
  data=self.data[:33]+struct.pack(">I",0)
  signature=self.private.sign(data+hashlib.sha256(self.client).digest())
  with self.assertRaises(AuthorizationDenied):
   self.verify(authenticator_data=data,signature=signature)
 def test_reserved_flag_rejected(self):
  data=self.data[:32]+bytes([0x07])+self.data[33:]
  signature=self.private.sign(data+hashlib.sha256(self.client).digest())
  with self.assertRaises(AuthorizationDenied):
   self.verify(authenticator_data=data,signature=signature)
 def test_noncanonical_challenge_encoding_rejected(self):
  import json
  data=json.loads(self.client)
  data["challenge"]=data["challenge"]+"="
  with self.assertRaises(AuthorizationDenied):
   self.verify(client_data_json=json.dumps(data).encode())
 def test_wrong_signature(self):
  with self.assertRaises(AuthorizationDenied):self.verify(signature=b"a"*64)
 def test_duplicate_challenge_member_rejected(self):
  client=self.client.replace(b'"crossOrigin": false',b'"challenge":"invalid","crossOrigin": false')
  with self.assertRaises(AuthorizationDenied):self.verify(client_data_json=client)
 def test_non_boolean_cross_origin_rejected(self):
  client=self.client.replace(b'false',b'"false"')
  with self.assertRaises(AuthorizationDenied):self.verify(client_data_json=client)
 def test_cross_origin(self):
  client=self.client.replace(b'false',b'true')
  with self.assertRaises(AuthorizationDenied):self.verify(client_data_json=client)
if __name__=="__main__":unittest.main()
