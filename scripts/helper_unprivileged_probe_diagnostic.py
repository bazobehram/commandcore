"""Diagnose Linux helper IPC as the real Agent user without exposing secrets.

For disposable CI only: invoked under the same unprivileged UID as the Rust
network Agent. Reports permissions and verified probe response, never key data.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import socket
import stat
import time
import uuid
from pathlib import Path


def check() -> dict:
    sock_path = Path(os.environ["COMMANDCORE_HELPER_SOCKET"])
    secret_path = Path(os.environ["COMMANDCORE_HELPER_SECRET"])
    details = {"uid": os.getuid(), "gid": os.getgid()}
    for label, path in (("socket", sock_path), ("secret", secret_path)):
        try:
            info = path.stat()
            details[label] = {
                "exists": True,
                "mode": oct(stat.S_IMODE(info.st_mode)),
                "owner_uid": info.st_uid,
                "owner_gid": info.st_gid,
                "readable": os.access(path, os.R_OK),
                "writable": os.access(path, os.W_OK),
            }
        except OSError as exc:
            details[label] = {"error_type": type(exc).__name__}
    try:
        key = secret_path.read_bytes().strip()
        if len(key) < 32:
            raise ValueError("helper key too short")
        payload = {
            "action": "probe",
            "request_id": str(uuid.uuid4()),
            "timestamp": int(time.time()),
            "nonce": secrets.token_urlsafe(24),
        }
        canonical = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()
        payload["mac"] = hmac.new(key, canonical, hashlib.sha256).hexdigest()
        with socket.socket(socket.AF_UNIX) as client:
            client.settimeout(3)
            client.connect(str(sock_path))
            client.sendall(json.dumps(payload).encode() + b"\n")
            data = b""
            while not data.endswith(b"\n"):
                piece = client.recv(4096)
                if not piece or len(data) + len(piece) > 32_768:
                    raise RuntimeError("helper reply truncated or oversized")
                data += piece
        response = json.loads(data)
        # Deliberately return ONLY noncredential protocol fields.
        details["response"] = {
            k: response.get(k)
            for k in ("type", "available", "max_permission_profile", "error")
        }
    except Exception as exc:
        details["probe_error"] = {
            "type": type(exc).__name__,
            "errno": getattr(exc, "errno", None),
        }
    return details


if __name__ == "__main__":
    print(json.dumps(check(), sort_keys=True))
