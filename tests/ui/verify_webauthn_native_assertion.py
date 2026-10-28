"""Verify the actual Chrome virtual-authenticator assertion through server crypto."""
import json
from pathlib import Path
from cryptography.hazmat.primitives.serialization import load_der_public_key
from commandcore_server.collaboration_approval import AuthorizationDenied
from commandcore_server.collaboration_webauthn_assertion import verify_assertion

data=json.loads(Path('/tmp/cc-native-webauthn-assertion.json').read_text())
raw=lambda k:bytes(data[k])
args=dict(public_key=load_der_public_key(raw('publicKey')),
          authenticator_data=raw('authenticatorData'),
          client_data_json=raw('clientDataJSON'),signature=raw('signature'),
          expected_challenge=raw('challenge'),
          expected_origin='https://panel.example.test',
          expected_rp_id='panel.example.test',previous_sign_count=0)
assert verify_assertion(**args)>=0
for changes in ({'expected_origin':'https://attacker.example.test'},
                {'expected_challenge':bytes(32)},
                {'expected_rp_id':'attacker.example.test'}):
    try:
        verify_assertion(**(args|changes))
    except AuthorizationDenied:
        pass
    else:
        raise AssertionError(f'expected rejection: {changes}')
print('BROWSER_NATIVE_SERVER_SIGNATURE_BINDING_PASS')
