"""Simulated WebAuthn lifecycle: real verifier, not a real user authenticator."""
import asyncio,base64,hashlib,json,os,struct,tempfile,unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from fido2 import cbor
from commandcore_server.collaboration_registration_ceremony import RegistrationCeremonies
from commandcore_server.collaboration_webauthn_credentials import CredentialRegistry
from commandcore_server.collaboration_review_challenge import ReviewChallenges
from commandcore_server.collaboration_webauthn_review import verify_review_assertion
from commandcore_server.collaboration_approval import Approval,ApprovalLedger,AuthorizationDenied,action_digest

def enc(value):
 return base64.urlsafe_b64encode(value).rstrip(b'=').decode()

class LifecycleTests(unittest.TestCase):
 def test_registration_then_signed_review_then_replay(self):
  with tempfile.TemporaryDirectory() as tmp:
   shared=os.path.join(tmp,"shared.sqlite")
   ceremony=RegistrationCeremonies(shared)
   registry=CredentialRegistry(shared)
   challenges=ReviewChallenges(shared)
   ledger=ApprovalLedger(os.path.join(tmp,"ledger.sqlite"))
   try:
    private=Ed25519PrivateKey.generate()
    pub=private.public_key().public_bytes(
     encoding=serialization.Encoding.Raw,format=serialization.PublicFormat.Raw)
    issued=ceremony.begin(owner="owner",rp_id="panel.example.test",origin="https://panel.example.test",now=100)
    cred_id=b"simulated-passkey"
    auth_registration=(hashlib.sha256(b"panel.example.test").digest()+bytes([0x45])
      +struct.pack(">I",0)+bytes(16)+len(cred_id).to_bytes(2,"big")+cred_id+
      cbor.encode({1:1,3:-8,-1:6,-2:pub}))
    client_registration=json.dumps({"type":"webauthn.create","origin":"https://panel.example.test",
      "challenge":issued["challenge"]}).encode()
    response={"id":enc(cred_id),"rawId":enc(cred_id),"type":"public-key",
      "response":{"clientDataJSON":enc(client_registration),
      "attestationObject":enc(cbor.encode({"fmt":"none","authData":auth_registration,"attStmt":{}}))}}
    enrolled=ceremony.finish_and_enroll(registry=registry,owner="owner",
      challenge=issued["challenge"],response=response,now=101)
    self.assertEqual(enrolled["credential_id"],enc(cred_id))
    draft="Simulated draft"
    digest=hashlib.sha256(draft.encode()).hexdigest()
    action=action_digest(device_id="gx10",window_id="0x4",title="QA",process_id=42,
      process_start=33,draft_id="draft",draft_sha256=digest,input_x=100,input_y=200,send_key="Return")
    ledger.create(Approval("req","owner","gx10","0x4","QA",42,33,"draft",digest,action,100,700))
    challenge=challenges.issue(owner="owner",request_id="req",action_digest=action,now=110)
    preview={"draft_id":"draft","window_id":"0x4","title":"QA","pid":42,
      "process_start":33,"text":draft,"input_x":100,"input_y":200,
      "send_key":"Return","preview_only":True,"delivery_authorized":False}
    agents=SimpleNamespace(connections={"gx10":object()},
      dispatch=AsyncMock(return_value=SimpleNamespace(status="ok",result=preview)))
    client=json.dumps({"type":"webauthn.get","origin":"https://panel.example.test",
      "challenge":enc(challenge.encode())}).encode()
    auth=hashlib.sha256(b"panel.example.test").digest()+bytes([0x05])+struct.pack(">I",1)
    args=dict(ledger=ledger,challenges=challenges,registry=registry,agents=agents,
     device={"id":"gx10"},owner_subject="owner",request_id="req",review_challenge=challenge,
     credential_id=enc(cred_id),authenticator_data=auth,client_data_json=client,
     signature=private.sign(auth+hashlib.sha256(client).digest()),
     expected_origin="https://panel.example.test",expected_rp_id="panel.example.test",now=111)
    result=asyncio.run(verify_review_assertion(**args))
    self.assertTrue(result["credential_verified"])
    self.assertFalse(result["delivery_authorized"])
    self.assertEqual(registry.db.execute("SELECT sign_count FROM credentials").fetchone()[0],1)
    with self.assertRaises(AuthorizationDenied):
     asyncio.run(verify_review_assertion(**args))
    self.assertEqual(ledger.get(owner_subject="owner",request_id="req").status,"pending")
   finally:
    ledger.close();challenges.close();registry.close();ceremony.close()
