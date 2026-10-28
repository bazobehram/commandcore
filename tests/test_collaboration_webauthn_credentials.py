import base64,hashlib,json,os,struct,tempfile,unittest
from concurrent.futures import ThreadPoolExecutor
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from commandcore_server.collaboration_webauthn_credentials import CredentialRegistry
from commandcore_server.collaboration_approval import AuthorizationDenied
class RegistryTest(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory()
  self.path=os.path.join(self.tmp.name,"credentials.sqlite")
  self.registry=CredentialRegistry(self.path)
  self.key=Ed25519PrivateKey.generate()
  self.registry.add_preverified(owner="owner",credential_id="cred",public_key_raw=self.key.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,format=serialization.PublicFormat.Raw))
  self.challenge=b"x"*32
  self.client=json.dumps({"type":"webauthn.get","origin":"https://panel.example.test",
    "challenge":base64.urlsafe_b64encode(self.challenge).rstrip(b"=").decode()}).encode()
  self.data=hashlib.sha256(b"panel.example.test").digest()+bytes([5])+struct.pack(">I",2)
 def tearDown(self):self.registry.close();self.tmp.cleanup()
 def submit(self,registry=None,**changes):
  params=dict(owner="owner",credential_id="cred",authenticator_data=self.data,
    client_data_json=self.client,signature=self.key.sign(self.data+hashlib.sha256(self.client).digest()),
    expected_challenge=self.challenge,expected_origin="https://panel.example.test",
    expected_rp_id="panel.example.test")
  params.update(changes)
  return (registry or self.registry).verify_and_update(**params)
 def test_valid_and_replay(self):
  self.assertEqual(self.submit(),2)
  with self.assertRaises(AuthorizationDenied):self.submit()
 def test_same_credential_cannot_be_enrolled_to_another_owner(self):
  import sqlite3
  key=self.key.public_key().public_bytes(
   encoding=serialization.Encoding.Raw,format=serialization.PublicFormat.Raw)
  with self.assertRaises(sqlite3.IntegrityError):
   self.registry.add_preverified(owner="intruder",credential_id="cred",public_key_raw=key)
 def test_legacy_cross_owner_duplicates_fail_closed(self):
  import sqlite3
  legacy=os.path.join(self.tmp.name,"legacy.sqlite")
  db=sqlite3.connect(legacy)
  db.execute("CREATE TABLE credentials(owner TEXT NOT NULL, credential_id TEXT NOT NULL, public_key BLOB NOT NULL, sign_count INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(owner,credential_id))")
  db.executemany("INSERT INTO credentials(owner,credential_id,public_key) VALUES(?,?,?)",
                 [("owner-a","shared",b"a"*32),("owner-b","shared",b"b"*32)])
  db.commit();db.close()
  with self.assertRaisesRegex(AuthorizationDenied,"credential_ownership_migration_required"):
   CredentialRegistry(legacy)
  db=sqlite3.connect(legacy)
  self.assertEqual(db.execute("SELECT count(*) FROM credentials").fetchone()[0],2)
  self.assertEqual(db.execute("SELECT count(*) FROM sqlite_master WHERE type='index' AND name='credentials_unique_id'").fetchone()[0],0)
  db.close()
 def test_legacy_hex_inventory_is_read_only(self):
  key=self.key.public_key().public_bytes(
   encoding=serialization.Encoding.Raw,format=serialization.PublicFormat.Raw)
  self.registry.add_preverified(owner="owner",credential_id="deadbeef",public_key_raw=key)
  before=self.registry.db.execute("SELECT owner,credential_id,sign_count FROM credentials ORDER BY credential_id").fetchall()
  self.assertEqual(self.registry.legacy_hex_id_candidates(),
                   [{"owner":"owner","credential_id":"deadbeef"}])
  after=self.registry.db.execute("SELECT owner,credential_id,sign_count FROM credentials ORDER BY credential_id").fetchall()
  self.assertEqual(before,after)
 def test_explicit_migration_success_and_replay_protection(self):
  raw=self.key.public_key().public_bytes(
   encoding=serialization.Encoding.Raw,format=serialization.PublicFormat.Raw)
  self.registry.add_preverified(owner="owner",credential_id="deadbeef",public_key_raw=raw)
  plan=self.registry.plan_legacy_id_migration(confirmed_legacy_ids=["deadbeef"])
  self.assertEqual(plan[0]["target"],"3q2-7w")
  self.assertEqual(self.registry.apply_legacy_id_migration(
    confirmed_legacy_ids=["deadbeef"],expected_plan=plan),1)
  with self.assertRaises(AuthorizationDenied):
   self.registry.apply_legacy_id_migration(confirmed_legacy_ids=["deadbeef"],expected_plan=plan)
 def test_collision_aborts_without_changes(self):
  raw=self.key.public_key().public_bytes(
   encoding=serialization.Encoding.Raw,format=serialization.PublicFormat.Raw)
  self.registry.add_preverified(owner="owner",credential_id="deadbeef",public_key_raw=raw)
  self.registry.add_preverified(owner="owner",credential_id="3q2-7w",public_key_raw=raw)
  before=self.registry.db.execute("SELECT credential_id FROM credentials ORDER BY credential_id").fetchall()
  with self.assertRaises(AuthorizationDenied):
   self.registry.plan_legacy_id_migration(confirmed_legacy_ids=["deadbeef"])
  self.assertEqual(before,self.registry.db.execute("SELECT credential_id FROM credentials ORDER BY credential_id").fetchall())
 def test_changed_plan_rolls_back_across_connections(self):
  raw=self.key.public_key().public_bytes(
   encoding=serialization.Encoding.Raw,format=serialization.PublicFormat.Raw)
  self.registry.add_preverified(owner="owner",credential_id="deadbeef",public_key_raw=raw)
  plan=self.registry.plan_legacy_id_migration(confirmed_legacy_ids=["deadbeef"])
  other=CredentialRegistry(self.path)
  try:
   other.add_preverified(owner="owner",credential_id="3q2-7w",public_key_raw=raw)
   before=self.registry.db.execute("SELECT credential_id FROM credentials ORDER BY credential_id").fetchall()
   with self.assertRaises(AuthorizationDenied):
    self.registry.apply_legacy_id_migration(confirmed_legacy_ids=["deadbeef"],expected_plan=plan)
   self.assertEqual(before,self.registry.db.execute("SELECT credential_id FROM credentials ORDER BY credential_id").fetchall())
  finally:other.close()
 def test_duplicate_confirmation_rejected(self):
  with self.assertRaises(AuthorizationDenied):
   self.registry.plan_legacy_id_migration(confirmed_legacy_ids=["deadbeef","deadbeef"])
 def test_wrong_owner(self):
  with self.assertRaises(AuthorizationDenied):self.submit(owner="intruder")
 def test_invalid_signature_does_not_advance(self):
  with self.assertRaises(AuthorizationDenied):self.submit(signature=b"x"*64)
  self.assertEqual(self.submit(),2)
 def test_concurrent_second_connection_only_one_succeeds(self):
  other=CredentialRegistry(self.path)
  try:
   def attempt(reg):
    try:return self.submit(registry=reg)==2
    except AuthorizationDenied:return False
   with ThreadPoolExecutor(max_workers=2) as pool:
    results=list(pool.map(attempt,(self.registry,other)))
   self.assertEqual(sorted(results),[False,True])
  finally:other.close()
if __name__=="__main__":unittest.main()
