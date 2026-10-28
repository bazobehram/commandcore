"""WebAuthn registration client-data preflight only, not attestation verification.

A registration must NOT be persisted until authenticatorData, attestation,
credential algorithm, RP hash, UP/UV flags, and public key are verified by
a standards-conformant enrollment verifier.
"""
from __future__ import annotations
import json
from hmac import compare_digest
from .collaboration_approval import AuthorizationDenied
from .collaboration_webauthn_assertion import b64url_decode

def verify_registration_client_data(*, client_data_json: bytes,
                                    expected_challenge: bytes,
                                    expected_origin: str) -> None:
    if (not isinstance(client_data_json, bytes)
        or len(client_data_json)>8192
        or not isinstance(expected_challenge,bytes)
        or len(expected_challenge)<32
        or not expected_origin.startswith("https://")):
        raise AuthorizationDenied("registration_input_invalid")
    def unique(pairs):
        d={}
        for k,v in pairs:
            if k in d: raise ValueError("duplicate")
            d[k]=v
        return d
    try:
        data=json.loads(client_data_json,object_pairs_hook=unique)
    except (ValueError,UnicodeDecodeError):
        raise AuthorizationDenied("registration_client_data_invalid") from None
    if not isinstance(data,dict):
        raise AuthorizationDenied("registration_client_data_invalid")
    if (data.get("type")!="webauthn.create"
        or data.get("origin")!=expected_origin
        or data.get("crossOrigin",False) is not False
        or not compare_digest(b64url_decode(data.get("challenge")),expected_challenge)):
        raise AuthorizationDenied("registration_client_binding_invalid")

def verify_registration_authenticator_header(*, authenticator_data: bytes,
                                             expected_rp_id: str) -> None:
    """Validate registration header; NOT a substitute for COSE/CBOR attestation."""
    import hashlib
    if (not isinstance(authenticator_data, bytes)
            or len(authenticator_data)<55 or len(authenticator_data)>8192
            or not isinstance(expected_rp_id,str) or not expected_rp_id):
        raise AuthorizationDenied("registration_authenticator_invalid")
    if not compare_digest(authenticator_data[:32], hashlib.sha256(expected_rp_id.encode()).digest()):
        raise AuthorizationDenied("registration_rp_mismatch")
    flags=authenticator_data[32]
    # UP, UV, and attested credential data (AT) must be set.
    # Reject reserved bits and the extension flag (ED) until extension data
    # is parsed and verified by a standards-compliant registration library.
    if flags & 0x45 != 0x45 or flags & 0xBA:
        raise AuthorizationDenied("registration_user_verification_required")
    # AT layout: AAGUID (16 bytes), credentialIdLength (2 bytes), id, COSE key.
    credential_length=int.from_bytes(authenticator_data[53:55],"big")
    if credential_length<1 or credential_length>1024 or len(authenticator_data)<55+credential_length+1:
        raise AuthorizationDenied("registration_credential_data_invalid")
