import unittest
from commandcore_server.collaboration_approval import AuthorizationDenied
from commandcore_server.collaboration_registration_fido2 import verify_registration
class Fido2Tests(unittest.TestCase):
 def test_missing_registration_state_fails_closed(self):
  with self.assertRaises(AuthorizationDenied):
   verify_registration(rp_id="panel.example.test",origin="https://panel.example.test",state={},response={})
 def test_malformed_attestation_rejected(self):
  with self.assertRaises(AuthorizationDenied):
   verify_registration(rp_id="panel.example.test",origin="https://panel.example.test",
    state={"challenge":"eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHg","user_verification":"required"},
    response={"id":"test"})
if __name__=="__main__":unittest.main()
