import os,tempfile,unittest
from commandcore_server.collaboration_approval import AuthorizationDenied
from commandcore_server.collaboration_registration_ceremony import RegistrationCeremonies

class CeremonyTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory()
  self.ceremony=RegistrationCeremonies(os.path.join(self.tmp.name,"state.sqlite"))
 def tearDown(self):self.ceremony.close();self.tmp.cleanup()
 def test_begin_owner_scoped_and_uv_required(self):
  result=self.ceremony.begin(owner="owner",rp_id="panel.example.test",origin="https://panel.example.test",now=100)
  self.assertEqual(result["expires_at"],220)
  self.assertEqual([x["alg"] for x in result["options"]["publicKey"]["pubKeyCredParams"]],[-8])
  self.assertEqual(result["options"]["publicKey"]["authenticatorSelection"]["userVerification"],"required")
  self.assertEqual(result["options"]["publicKey"]["authenticatorSelection"]["residentKey"],"required")
  self.assertEqual(result["options"]["publicKey"]["challenge"],result["challenge"])
  self.assertEqual(self.ceremony.db.execute("SELECT json_extract(state,'$.user_verification') FROM registration_ceremonies").fetchone()[0],"required")
 def test_separate_credential_store_denied(self):
  from commandcore_server.collaboration_webauthn_credentials import CredentialRegistry
  registry=CredentialRegistry(os.path.join(self.tmp.name,"different.sqlite"))
  try:
   c=self.ceremony.begin(owner="owner",rp_id="panel.example.test",origin="https://panel.example.test",now=100)
   with self.assertRaises(AuthorizationDenied):
    self.ceremony.finish_and_enroll(registry=registry,owner="owner",challenge=c["challenge"],response={},now=101)
   self.assertEqual(registry.db.execute("SELECT count(*) FROM credentials").fetchone()[0],0)
  finally:registry.close()
 def test_atomic_enrollment_and_single_use_with_verified_fixture(self):
  from unittest.mock import patch
  from types import SimpleNamespace
  from commandcore_server.collaboration_webauthn_credentials import CredentialRegistry
  registry=CredentialRegistry(os.path.join(self.tmp.name,"state.sqlite"))
  c=self.ceremony.begin(owner="owner",rp_id="panel.example.test",origin="https://panel.example.test",now=100)
  verified=SimpleNamespace(credential_id=b"fixture-id",public_key={1:1,3:-8,-1:6,-2:b"k"*32})
  try:
   with patch("commandcore_server.collaboration_registration_ceremony.verify_registration",return_value=verified):
    result=self.ceremony.finish_and_enroll(registry=registry,owner="owner",challenge=c["challenge"],response={},now=101)
   self.assertTrue(result["enrolled"])
   self.assertEqual(registry.db.execute("SELECT count(*) FROM credentials").fetchone()[0],1)
   with self.assertRaises(AuthorizationDenied):
    self.ceremony.finish_and_enroll(registry=registry,owner="owner",challenge=c["challenge"],response={},now=102)
  finally:registry.close()
 def test_invalid_finish_and_enroll_consumes_challenge(self):
  from commandcore_server.collaboration_webauthn_credentials import CredentialRegistry
  registry=CredentialRegistry(os.path.join(self.tmp.name,"state.sqlite"))
  try:
   c=self.ceremony.begin(owner="owner",rp_id="panel.example.test",
                         origin="https://panel.example.test",now=100)
   with self.assertRaises(AuthorizationDenied):
    self.ceremony.finish_and_enroll(registry=registry,owner="owner",
       challenge=c["challenge"],response={},now=101)
   self.assertEqual(self.ceremony.db.execute(
       "SELECT consumed FROM registration_ceremonies WHERE challenge=?",
       (c["challenge"],)).fetchone()[0],1)
  finally:registry.close()
 def test_wrong_cose_curve_never_enrolls(self):
  from unittest.mock import patch
  from types import SimpleNamespace
  from commandcore_server.collaboration_webauthn_credentials import CredentialRegistry
  registry=CredentialRegistry(os.path.join(self.tmp.name,"state.sqlite"))
  c=self.ceremony.begin(owner="owner",rp_id="panel.example.test",origin="https://panel.example.test",now=100)
  invalid=SimpleNamespace(credential_id=b"fixture-id",public_key={1:1,3:-8,-1:4,-2:b"k"*32})
  try:
   with patch("commandcore_server.collaboration_registration_ceremony.verify_registration",return_value=invalid):
    with self.assertRaises(AuthorizationDenied):
     self.ceremony.finish_and_enroll(registry=registry,owner="owner",challenge=c["challenge"],response={},now=101)
   self.assertEqual(registry.db.execute("SELECT count(*) FROM credentials").fetchone()[0],0)
  finally:registry.close()
 def test_wrong_origin_rejected(self):
  with self.assertRaises(AuthorizationDenied):
   self.ceremony.begin(owner="owner",rp_id="panel.example.test",origin="https://other.test",now=100)
 def test_wrong_owner_cannot_finish(self):
  c=self.ceremony.begin(owner="owner",rp_id="panel.example.test",origin="https://panel.example.test",now=100)
  with self.assertRaises(AuthorizationDenied):
   self.ceremony.finish_verified(owner="intruder",challenge=c["challenge"],response={},now=101)
 def test_expired_cannot_finish(self):
  c=self.ceremony.begin(owner="owner",rp_id="panel.example.test",origin="https://panel.example.test",now=100)
  with self.assertRaises(AuthorizationDenied):
   self.ceremony.finish_verified(owner="owner",challenge=c["challenge"],response={},now=220)
 def test_malformed_attempt_exhausts_one_time_ceremony(self):
  c=self.ceremony.begin(owner="owner",rp_id="panel.example.test",origin="https://panel.example.test",now=100)
  with self.assertRaises(AuthorizationDenied):
   self.ceremony.finish_verified(owner="owner",challenge=c["challenge"],response={},now=101)
  with self.assertRaises(AuthorizationDenied):
   self.ceremony.finish_verified(owner="owner",challenge=c["challenge"],response={},now=102)
if __name__=="__main__":unittest.main()

class FullRegistrationIntegrationTests(unittest.TestCase):
 def test_fido2_none_attestation_enrolls_and_cannot_replay(self):
  import base64,hashlib,json,struct
  from fido2 import cbor
  from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
  from cryptography.hazmat.primitives import serialization
  from commandcore_server.collaboration_webauthn_credentials import CredentialRegistry
  with tempfile.TemporaryDirectory() as tmp:
   path=os.path.join(tmp,"shared.sqlite")
   ceremonies=RegistrationCeremonies(path)
   registry=CredentialRegistry(path)
   try:
    issued=ceremonies.begin(owner="owner",rp_id="panel.example.test",origin="https://panel.example.test",now=100)
    challenge=issued["challenge"]
    key=Ed25519PrivateKey.generate().public_key().public_bytes(
      encoding=serialization.Encoding.Raw,format=serialization.PublicFormat.Raw)
    cred_id=b"synthetic-credential-id"
    cose=cbor.encode({1:1,3:-8,-1:6,-2:key})
    auth=(hashlib.sha256(b"panel.example.test").digest()+bytes([0x45])
      +struct.pack(">I",0)+bytes(16)+len(cred_id).to_bytes(2,"big")+cred_id+cose)
    attestation=cbor.encode({"fmt":"none","authData":auth,"attStmt":{}})
    client_data=json.dumps({"type":"webauthn.create","challenge":challenge,
      "origin":"https://panel.example.test","crossOrigin":False}).encode()
    enc=lambda b:base64.urlsafe_b64encode(b).rstrip(b"=").decode()
    response={"id":enc(cred_id),"rawId":enc(cred_id),"type":"public-key",
      "response":{"clientDataJSON":enc(client_data),"attestationObject":enc(attestation)}}
    result=ceremonies.finish_and_enroll(registry=registry,owner="owner",
      challenge=challenge,response=response,now=101)
    self.assertTrue(result["enrolled"])
    self.assertEqual(registry.db.execute("SELECT public_key FROM credentials").fetchone()[0],key)
    with self.assertRaises(AuthorizationDenied):
     ceremonies.finish_and_enroll(registry=registry,owner="owner",
       challenge=challenge,response=response,now=102)
   finally:
    registry.close()
    ceremonies.close()
