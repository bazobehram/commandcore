import json, os, tempfile
from commandcore_server.collaboration_registration_ceremony import RegistrationCeremonies
db=os.environ['CC_NATIVE_REG_DB']
c=RegistrationCeremonies(db)
print(json.dumps(c.begin(owner="owner",rp_id="panel.example.test",origin="https://panel.example.test",now=100)))
c.close()
