import base64,json,unittest
from commandcore_server.collaboration_registration_preflight import verify_registration_client_data
from commandcore_server.collaboration_approval import AuthorizationDenied

class RegistrationPreflightTests(unittest.TestCase):
 def setUp(self):
  self.challenge=b'z'*32
  self.fields={"type":"webauthn.create","origin":"https://panel.example.test",
   "challenge":base64.urlsafe_b64encode(self.challenge).rstrip(b'=').decode(),
   "crossOrigin":False}
 def check(self, fields=None, raw=None, **kwargs):
  return verify_registration_client_data(client_data_json=raw if raw is not None else json.dumps(fields or self.fields).encode(),
   expected_challenge=self.challenge, expected_origin="https://panel.example.test",**kwargs)
 def test_valid(self):self.check()
 def test_wrong_origin(self):
  with self.assertRaises(AuthorizationDenied):self.check(fields={**self.fields,"origin":"https://evil.test"})
 def test_wrong_challenge(self):
  with self.assertRaises(AuthorizationDenied):self.check(fields={**self.fields,"challenge":"eW91"})
 def test_cross_origin(self):
  with self.assertRaises(AuthorizationDenied):self.check(fields={**self.fields,"crossOrigin":True})
 def test_wrong_type(self):
  with self.assertRaises(AuthorizationDenied):self.check(fields={**self.fields,"type":"webauthn.get"})
 def test_duplicate_key(self):
  data=json.dumps(self.fields).replace('"crossOrigin": false','"origin": "https://evil.test", "crossOrigin": false')
  with self.assertRaises(AuthorizationDenied):self.check(raw=data.encode())
 def test_short_challenge(self):
  with self.assertRaises(AuthorizationDenied):
   verify_registration_client_data(client_data_json=json.dumps(self.fields).encode(),
    expected_challenge=b'x',expected_origin="https://panel.example.test")
if __name__=="__main__":unittest.main()

class RegistrationHeaderTests(unittest.TestCase):
 def setUp(self):
  import hashlib
  from commandcore_server.collaboration_registration_preflight import verify_registration_authenticator_header
  self.verify=verify_registration_authenticator_header
  self.data=(hashlib.sha256(b"panel.example.test").digest()
   +bytes([0x45])+b"\x00"*4+b"\x00"*16+b"\x00\x02"+b"id"+b"key")
 def test_header(self):self.verify(authenticator_data=self.data,expected_rp_id="panel.example.test")
 def test_rp_mismatch(self):
  with self.assertRaises(AuthorizationDenied):self.verify(authenticator_data=self.data,expected_rp_id="other.test")
 def test_missing_uv(self):
  data=self.data[:32]+bytes([0x41])+self.data[33:]
  with self.assertRaises(AuthorizationDenied):self.verify(authenticator_data=data,expected_rp_id="panel.example.test")
 def test_extension_flag_not_silently_accepted(self):
  data=self.data[:32]+bytes([0xC5])+self.data[33:]
  with self.assertRaises(AuthorizationDenied):
   self.verify(authenticator_data=data,expected_rp_id="panel.example.test")
 def test_reserved_flag_rejected(self):
  data=self.data[:32]+bytes([0x47])+self.data[33:]
  with self.assertRaises(AuthorizationDenied):
   self.verify(authenticator_data=data,expected_rp_id="panel.example.test")
 def test_short_credential(self):
  with self.assertRaises(AuthorizationDenied):self.verify(authenticator_data=self.data[:-3],expected_rp_id="panel.example.test")
