from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

SENSITIVE_KEYS = {
    "authorization",
    "password",
    "passwd",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "api_key",
    "apikey",
    "private_key",
    "credential",
    "cookie",
}
CONTENT_KEYS = {"data", "data_base64", "command", "patches", "env"}


def _content_summary(key: str, value: Any) -> Any:
    if key == "env" and isinstance(value, dict):
        return {"redacted": True, "keys": sorted(str(k) for k in value.keys())[:50]}
    if key == "patches" and isinstance(value, list):
        return {"redacted": True, "count": len(value)}
    if isinstance(value, str):
        digest = hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[
            :16
        ]
        return {"redacted": True, "length": len(value), "sha256_16": digest}
    return "<redacted-content>"


def token_hash(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def new_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def constant_time_token_equal(raw: str, expected_raw: str) -> bool:
    return hmac.compare_digest(raw.encode(), expected_raw.encode())


def verify_device_signature(
    public_key_b64: str, signature_b64: str, message: bytes
) -> bool:
    try:
        public_bytes = base64.b64decode(public_key_b64, validate=True)
        signature = base64.b64decode(signature_b64, validate=True)
        Ed25519PublicKey.from_public_bytes(public_bytes).verify(signature, message)
        return True
    except Exception:
        return False


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _b64url_decode(raw: str) -> bytes:
    return base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))


def issue_panel_session(
    *,
    secret: str,
    subject: str,
    ttl_seconds: int,
    scopes: tuple[str, ...] | None = None,
    auth_kind: str = "panel-cookie",
) -> str:
    """Issue a compact signed, server-verifiable panel session token.

    The supplied panel signing secret is never embedded in the cookie.
    Hardened deployments use a separate key from the recovery/bootstrap token.
    """
    payload = {
        "sub": subject,
        "iat": int(time.time()),
        "exp": int(time.time()) + int(ttl_seconds),
        "nonce": secrets.token_urlsafe(12),
        "v": 1,
        "auth_kind": auth_kind,
        "scopes": list(scopes) if scopes is not None else None,
    }
    body = _b64url_encode(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    )
    signature = _b64url_encode(
        hmac.new(secret.encode(), body.encode(), hashlib.sha256).digest()
    )
    return f"{body}.{signature}"


def verify_panel_session(*, secret: str, token: str) -> str | None:
    try:
        body, signature = token.split(".", 1)
        expected = _b64url_encode(
            hmac.new(secret.encode(), body.encode(), hashlib.sha256).digest()
        )
        if not hmac.compare_digest(signature, expected):
            return None
        payload = json.loads(_b64url_decode(body))
        if payload.get("v") != 1 or int(payload.get("exp", 0)) < int(time.time()):
            return None
        subject = payload.get("sub")
        return str(subject) if subject else None
    except Exception:
        return None


def panel_session_claims(*, secret: str, token: str) -> dict[str, Any] | None:
    if verify_panel_session(secret=secret, token=token) is None:
        return None
    return json.loads(_b64url_decode(token.split(".", 1)[0]))


def redact(value: Any, *, depth: int = 0) -> Any:
    if depth > 4:
        return "<truncated>"
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in value.items():
            lowered = key.lower()
            if lowered in SENSITIVE_KEYS or any(
                s in lowered for s in ("password", "secret", "token", "credential")
            ):
                out[key] = "<redacted>"
            elif lowered in CONTENT_KEYS:
                out[key] = _content_summary(lowered, item)
            else:
                out[key] = redact(item, depth=depth + 1)
        return out
    if isinstance(value, list):
        return [redact(x, depth=depth + 1) for x in value[:20]]
    if isinstance(value, str):
        return value if len(value) <= 400 else value[:400] + "…<truncated>"
    return value


def audit_summary(arguments: dict[str, Any]) -> str:
    return json.dumps(
        redact(arguments), ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )[:2000]
