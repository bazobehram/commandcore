import json, os
from commandcore_server.collaboration_registration_ceremony import RegistrationCeremonies
from commandcore_server.collaboration_webauthn_credentials import CredentialRegistry
from commandcore_server.collaboration_approval import AuthorizationDenied
d=json.load(open(os.environ['CC_NATIVE_REG_RESULT']))
db=os.environ['CC_NATIVE_REG_DB']
c=RegistrationCeremonies(db);r=CredentialRegistry(db)
try:
 result=c.finish_and_enroll(registry=r,owner='owner',challenge=d['challenge'],response=d['response'],now=101)
 assert result['enrolled']
 assert r.db.execute('SELECT count(*) FROM credentials').fetchone()[0] == 1
 try:
  c.finish_and_enroll(registry=r,owner='owner',challenge=d['challenge'],response=d['response'],now=102)
 except AuthorizationDenied:
  pass
 else:
  raise AssertionError('native registration replay was accepted')
 assert r.db.execute('SELECT count(*) FROM credentials').fetchone()[0] == 1
 print('NATIVE_REGISTRATION_SERVER_ENROLL_AND_REPLAY_DENIAL_PASS')
finally:r.close();c.close()
