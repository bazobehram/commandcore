"""Short-lived authenticated intent for a *separate* public Browser operator.

The API may issue this only after verifying an OAuth JWT. The token carries no
OAuth bearer credentials and is NOT an instruction to grant Docker privileges.
The operator must verify, consume a durable nonce and separately enforce worker
capacity, immutable ownership and physical attestation before provisioning.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import stat
import time
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path

from .auth import STANDARD_SCOPE, scope_allows
from .models import Principal

_AUDIENCE = "commandcore:public-browser-operator:v1"
_DOMAIN = b"commandcore-public-browser-intent-v1\0"
_TTL_SECONDS = 60
_CLOCK_SKEW_SECONDS = 5
_MAX_TOKEN_BYTES = 4096
_FIELDS = frozenset({"v", "aud", "iss", "sub", "cid", "jti", "iat", "exp"})


class BrowserProvisionIntentDenied(ValueError):
    """A request lacks a verified identity, safe signature or one-time nonce."""


@dataclass(frozen=True)
class VerifiedProvisionIntent:
    issuer: str
    subject: str
    client_id: str
    nonce: str


def _key(secret: bytes) -> bytes:
    if not isinstance(secret, bytes) or len(secret) < 32:
        raise BrowserProvisionIntentDenied(
            "dedicated provisioning intent key unavailable"
        )
    return secret


def _encoded(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _decoded(data: str) -> bytes:
    if (
        not data
        or len(data) > _MAX_TOKEN_BYTES
        or any(
            c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
            for c in data
        )
    ):
        raise BrowserProvisionIntentDenied("malformed provisioning intent")
    try:
        return base64.b64decode(
            data + "=" * (-len(data) % 4), altchars=b"-_", validate=True
        )
    except (ValueError, base64.binascii.Error) as exc:
        raise BrowserProvisionIntentDenied("malformed provisioning intent") from exc


def _identity(issuer: str, subject: str, client_id: str) -> None:
    if (
        not isinstance(issuer, str)
        or not issuer.startswith("https://")
        or len(issuer) > 512
        or any(c.isspace() for c in issuer)
        or not isinstance(subject, str)
        or not 1 <= len(subject) <= 512
        or any(ord(c) < 32 for c in subject)
        or not isinstance(client_id, str)
        or not 1 <= len(client_id) <= 256
        or client_id in {"unknown", "oauth-client"}
        or any(c.isspace() for c in client_id)
    ):
        raise BrowserProvisionIntentDenied("verified OAuth owner identity required")


def issue_provision_intent(
    principal: Principal, secret: bytes, *, now: int | None = None
) -> str:
    """Only the authenticated OAuth resource server calls this after JWT checks."""
    key = _key(secret)
    if principal.auth_kind != "oauth2" or not scope_allows(
        principal.scopes, STANDARD_SCOPE
    ):
        raise BrowserProvisionIntentDenied(
            "Browser provision requires verified STANDARD OAuth"
        )
    _identity(principal.issuer, principal.subject, principal.client_id)
    issued = int(time.time() if now is None else now)
    payload = {
        "v": 1,
        "aud": _AUDIENCE,
        "iss": principal.issuer,
        "sub": principal.subject,
        "cid": principal.client_id,
        "jti": secrets.token_hex(16),
        "iat": issued,
        "exp": issued + _TTL_SECONDS,
    }
    body = json.dumps(
        payload, separators=(",", ":"), sort_keys=True, ensure_ascii=False
    ).encode("utf-8")
    signature = hmac.new(key, _DOMAIN + body, hashlib.sha256).digest()
    return _encoded(body) + "." + _encoded(signature)


def verify_provision_intent(
    token: str, secret: bytes, expected_issuer: str, *, now: int | None = None
) -> VerifiedProvisionIntent:
    """Stateless authenticity check. Operator MUST also call nonce_ledger.consume."""
    key = _key(secret)
    if (
        not isinstance(token, str)
        or len(token) > _MAX_TOKEN_BYTES
        or token.count(".") != 1
    ):
        raise BrowserProvisionIntentDenied("malformed provisioning intent")
    body64, tag64 = token.split(".")
    body, actual = _decoded(body64), _decoded(tag64)
    expected = hmac.new(key, _DOMAIN + body, hashlib.sha256).digest()
    if len(actual) != len(expected) or not hmac.compare_digest(actual, expected):
        raise BrowserProvisionIntentDenied("invalid provisioning signature")
    try:
        data = json.loads(body)
    except (UnicodeDecodeError, ValueError) as exc:
        raise BrowserProvisionIntentDenied("invalid provisioning payload") from exc
    if (
        not isinstance(data, dict)
        or set(data) != _FIELDS
        or data["v"] != 1
        or data["aud"] != _AUDIENCE
    ):
        raise BrowserProvisionIntentDenied("invalid provisioning payload")
    _identity(data["iss"], data["sub"], data["cid"])
    if data["iss"] != expected_issuer:
        raise BrowserProvisionIntentDenied("provisioning issuer mismatch")
    current = int(time.time() if now is None else now)
    issued, expires, nonce = data["iat"], data["exp"], data["jti"]
    if (
        type(issued) is not int
        or type(expires) is not int
        or not isinstance(nonce, str)
        or len(nonce) != 32
        or any(c not in "0123456789abcdef" for c in nonce)
        or expires - issued != _TTL_SECONDS
        or issued > current + _CLOCK_SKEW_SECONDS
        or current >= expires
    ):
        raise BrowserProvisionIntentDenied("expired or invalid provisioning intent")
    return VerifiedProvisionIntent(data["iss"], data["sub"], data["cid"], nonce)


class ProvisionNonceLedger:
    """Operator-owned, persistent, one-use nonce store; holds no OAuth identities."""

    def __init__(self, path: str):
        self.path = Path(path)
        if not self.path.is_absolute() or self.path.is_symlink():
            raise BrowserProvisionIntentDenied("operator nonce ledger path unsafe")
        parent = self.path.parent.stat()
        if not stat.S_ISDIR(parent.st_mode) or parent.st_mode & 0o077:
            raise BrowserProvisionIntentDenied(
                "operator nonce ledger directory not private"
            )
        if not self.path.exists():
            flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(self.path, flags, 0o600)
            os.close(fd)
        st = self.path.lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_mode & 0o077:
            raise BrowserProvisionIntentDenied(
                "operator nonce ledger permissions unsafe"
            )
        self._identity = (st.st_dev, st.st_ino)
        with closing(self._connection()) as db, db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS used_intents (nonce TEXT PRIMARY KEY, consumed_at INTEGER NOT NULL)"
            )

    def _connection(self) -> sqlite3.Connection:
        st = self.path.lstat()
        if (
            not stat.S_ISREG(st.st_mode)
            or st.st_mode & 0o077
            or (st.st_dev, st.st_ino) != self._identity
        ):
            raise BrowserProvisionIntentDenied(
                "operator nonce ledger replaced or unsafe"
            )
        from urllib.parse import quote

        return sqlite3.connect(
            "file:" + quote(str(self.path), safe="/") + "?mode=rw", uri=True, timeout=5
        )

    def consume(
        self, intent: VerifiedProvisionIntent, *, now: int | None = None
    ) -> None:
        current = int(time.time() if now is None else now)
        try:
            with closing(self._connection()) as db, db:
                db.execute("BEGIN IMMEDIATE")
                # Keep recent IDs long enough to prevent short-lived replay.
                db.execute(
                    "DELETE FROM used_intents WHERE consumed_at < ?", (current - 86400,)
                )
                db.execute(
                    "INSERT INTO used_intents(nonce, consumed_at) VALUES (?,?)",
                    (intent.nonce, current),
                )
        except sqlite3.IntegrityError as exc:
            raise BrowserProvisionIntentDenied("provisioning intent replayed") from exc
        except sqlite3.Error as exc:
            raise BrowserProvisionIntentDenied(
                "operator nonce ledger unavailable"
            ) from exc


def verify_and_consume_provision_intent(
    token: str,
    secret: bytes,
    expected_issuer: str,
    nonce_ledger: ProvisionNonceLedger,
    *,
    now: int | None = None,
) -> VerifiedProvisionIntent:
    """Operator entrypoint: authentication AND persistent replay denial are inseparable."""
    intent = verify_provision_intent(token, secret, expected_issuer, now=now)
    nonce_ledger.consume(intent, now=now)
    return intent
