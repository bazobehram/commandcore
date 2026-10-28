"""Staged standards-library WebAuthn registration verification.

No routes and no enrollment persistence. State MUST originate from a server
registration_begin ceremony and be kept owner-bound in trusted server storage.
"""
from .collaboration_approval import AuthorizationDenied

def verify_registration(*, rp_id: str, origin: str, state: dict, response: dict):
    try:
        from fido2.server import Fido2Server
        from fido2.webauthn import PublicKeyCredentialRpEntity, AttestationConveyancePreference
    except ImportError:
        raise AuthorizationDenied("fido2_dependency_missing") from None
    if (not isinstance(rp_id,str) or not rp_id
        or not isinstance(origin,str) or not origin.startswith("https://")
        or not isinstance(state,dict) or not isinstance(response,dict)
        or not state.get("challenge")
        or str(state.get("user_verification")) not in ("required","UserVerificationRequirement.REQUIRED")):
        raise AuthorizationDenied("registration_state_invalid")
    server=Fido2Server(
        PublicKeyCredentialRpEntity(id=rp_id,name="CommandCore"),
        attestation=AttestationConveyancePreference.NONE,
        verify_origin=lambda presented: presented == origin)
    try:
        auth_data=server.register_complete(state,response)
    except (ValueError,TypeError,KeyError,AssertionError):
        raise AuthorizationDenied("registration_verification_failed") from None
    credential=auth_data.credential_data
    if credential is None or not auth_data.is_user_verified():
        raise AuthorizationDenied("registration_user_verification_required")
    return credential
