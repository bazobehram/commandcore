"""WebAuthn assertion verification for pre-enrolled Ed25519 credentials only.

Enrollment and authentication ceremony remain separate, disabled release gates.
Caller must supply the server-recorded challenge (never one from client input).
"""
from __future__ import annotations
import base64
import hashlib
import json
import struct
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from .collaboration_approval import AuthorizationDenied

def b64url_decode(value: str) -> bytes:
    if not isinstance(value, str) or len(value)>16384:
        raise AuthorizationDenied("webauthn_invalid_encoding")
    try:
        decoded=base64.b64decode(value + "="*((-len(value))%4), altchars=b"-_", validate=True)
        # Reject noncanonical aliases and padding; browser credentials use
        # unpadded base64url, which must have exactly one representation.
        if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != value:
            raise AuthorizationDenied("webauthn_invalid_encoding")
        return decoded
    except (ValueError,base64.binascii.Error):
        raise AuthorizationDenied("webauthn_invalid_encoding") from None

def verify_assertion(*, public_key: Ed25519PublicKey, authenticator_data: bytes,
                     client_data_json: bytes, signature: bytes,
                     expected_challenge: bytes, expected_origin: str,
                     expected_rp_id: str, previous_sign_count: int) -> int:
    if (not expected_challenge or len(expected_challenge)<16
            or len(authenticator_data)<37 or len(authenticator_data)>4096
            or len(client_data_json)>8192 or len(signature)!=64
            or previous_sign_count<0):
        raise AuthorizationDenied("webauthn_invalid_assertion")
    def unique_members(pairs):
        result={}
        for key,value in pairs:
            if key in result:
                raise ValueError("duplicate WebAuthn client key")
            result[key]=value
        return result
    try:
        client=json.loads(client_data_json, object_pairs_hook=unique_members)
    except (ValueError, UnicodeDecodeError):
        raise AuthorizationDenied("webauthn_invalid_client_data") from None
    if not isinstance(client,dict):
        raise AuthorizationDenied("webauthn_invalid_client_data")
    if (client.get("type")!="webauthn.get" or client.get("origin")!=expected_origin
            or client.get("crossOrigin", False) is not False
            or b64url_decode(client.get("challenge"))!=expected_challenge):
        raise AuthorizationDenied("webauthn_client_binding_mismatch")
    if authenticator_data[:32]!=hashlib.sha256(expected_rp_id.encode()).digest():
        raise AuthorizationDenied("webauthn_rp_mismatch")
    flags=authenticator_data[32]
    # UP (user present) and UV (user verified) mandatory.
    if flags&0x05 != 0x05 or flags&0xFA:
        raise AuthorizationDenied("webauthn_user_verification_required")
    counter=struct.unpack(">I",authenticator_data[33:37])[0]
    # Authenticators that always report zero are permitted; once a positive
    # counter has been observed it must never reset or decrease.
    if previous_sign_count and counter<=previous_sign_count:
        raise AuthorizationDenied("webauthn_counter_replay")
    try:
        public_key.verify(signature,authenticator_data+hashlib.sha256(client_data_json).digest())
    except InvalidSignature:
        raise AuthorizationDenied("webauthn_signature_invalid") from None
    return counter
