from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

import jwt
from jwt import PyJWKClient

from .models import Principal

READ_SCOPE = "commandcore:read"
STANDARD_SCOPE = "commandcore:standard"
FULL_SCOPE = "commandcore:full"
ADMIN_SCOPE = "commandcore:admin"
ALL_SCOPES = (READ_SCOPE, STANDARD_SCOPE, FULL_SCOPE, ADMIN_SCOPE)


def parse_scopes(value: object) -> tuple[str, ...]:
    if isinstance(value, str):
        return tuple(x for x in value.split() if x)
    if isinstance(value, list):
        return tuple(str(x) for x in value if str(x))
    return ()


def scope_allows(scopes: Iterable[str], required: str) -> bool:
    scope_set = set(scopes)
    if required == ADMIN_SCOPE:
        return ADMIN_SCOPE in scope_set
    if required == READ_SCOPE:
        return bool(scope_set.intersection({READ_SCOPE, STANDARD_SCOPE, FULL_SCOPE}))
    if required == STANDARD_SCOPE:
        return bool(scope_set.intersection({STANDARD_SCOPE, FULL_SCOPE}))
    if required == FULL_SCOPE:
        return FULL_SCOPE in scope_set
    return False


@dataclass(frozen=True)
class OAuthSettings:
    issuer: str
    audience: str
    jwks_url: str
    algorithms: tuple[str, ...] = ("RS256", "ES256", "EdDSA")


class OAuthVerifier:
    """Validate OAuth access tokens issued by an external OAuth 2.1/OIDC server.

    CommandCore deliberately acts as a resource server, not a home-grown identity
    provider. Keys are resolved from the configured JWKS endpoint and standard
    issuer/audience/expiry checks are enforced by PyJWT.
    """

    def __init__(self, settings: OAuthSettings):
        self.settings = settings
        self.jwks = PyJWKClient(settings.jwks_url, cache_keys=True, lifespan=300)

    def verify(self, token: str) -> Principal:
        signing_key = self.jwks.get_signing_key_from_jwt(token)
        payload = jwt.decode(
            token,
            signing_key.key,
            algorithms=list(self.settings.algorithms),
            issuer=self.settings.issuer,
            audience=self.settings.audience,
            options={"require": ["exp", "sub", "iat"]},
        )
        subject = str(payload["sub"])
        scopes = parse_scopes(payload.get("scope") or payload.get("scp"))
        client_id = str(
            payload.get("client_id") or payload.get("azp") or "oauth-client"
        )
        return Principal(
            subject=subject,
            client_id=client_id,
            auth_kind="oauth2",
            scopes=scopes,
            issuer=self.settings.issuer,
        )
