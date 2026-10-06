from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import platform
import secrets
import socket
import sys
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from websockets.exceptions import WebSocketException

from . import __version__
from .capabilities import CAPABILITIES
from .helper_client import build_runtime_capabilities
from .state import AgentState, default_state_path, load, save


def enroll_url(args) -> int:
    url = urlsplit(args.token)
    if (
        url.username
        or url.password
        or url.query
        or url.fragment
        or url.path not in {"", "/"}
    ):
        print(
            "Use the server HTTPS origin, without credentials or query parameters.",
            file=sys.stderr,
        )
        return 2
    if url.scheme != "https" and not (
        args.insecure
        and url.scheme == "http"
        and url.hostname in {"127.0.0.1", "localhost", "::1"}
    ):
        print(
            "HTTPS is required; loopback HTTP is allowed only for development.",
            file=sys.stderr,
        )
        return 2
    base = urlunsplit((url.scheme, url.netloc, "", "", ""))
    state_path = Path(args.state).expanduser() if args.state else default_state_path()
    if state_path.exists():
        print(
            "This device already has an identity. Use status or rotate-key.",
            file=sys.stderr,
        )
        return 2
    pending_path = state_path.with_name("enrollment.pending.json")
    if pending_path.exists():
        state = load(pending_path)
        if state.control_url != base:
            print("Pending enrollment belongs to another server.", file=sys.stderr)
            return 2
    else:
        private = Ed25519PrivateKey.generate()
        private_b64 = base64.b64encode(
            private.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            )
        ).decode()
        public_b64 = base64.b64encode(
            private.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
        ).decode()
        state = AgentState(
            str(uuid.uuid4()),
            secrets.token_urlsafe(40),
            private_b64,
            public_b64,
            base,
            urlunsplit(
                ("wss" if url.scheme == "https" else "ws", url.netloc, "/agent", "", "")
            ),
            args.name or socket.gethostname(),
        )
        save(state, pending_path)
    private = Ed25519PrivateKey.from_private_bytes(
        base64.b64decode(state.private_key_b64)
    )
    ceiling = os.getenv("COMMANDCORE_AGENT_MAX_PERMISSION_PROFILE", "STANDARD").upper()
    if ceiling not in {"READ_ONLY", "STANDARD"}:
        print(
            "Enroll at STANDARD or READ_ONLY before explicit local FULL_CONTROL opt-in.",
            file=sys.stderr,
        )
        return 2
    try:
        if state.device_id and state.device_token and state.enrollment_id:
            from .cli import _connect_authenticated, run_agent

            async def resume_identity():
                try:
                    ws, _ = await _connect_authenticated(state, state.private_key_b64)
                except (
                    WebSocketException,
                    OSError,
                    TimeoutError,
                    ValueError,
                    KeyError,
                    RuntimeError,
                ):
                    return False
                await ws.close()
                return True

            if asyncio.run(resume_identity()):
                state.enrollment_id = None
                state.enrollment_poll_token = None
                state.enrollment_uri = None
                state.enrollment_code = None
                save(state, state_path)
                pending_path.unlink()
                print("[OK] Approved device identity recovered securely.", flush=True)
                if args.no_connect:
                    return 0
                args.once = False
                return asyncio.run(run_agent(args))
        capabilities = asyncio.run(build_runtime_capabilities(CAPABILITIES))
        if capabilities.get("local_max_permission_profile") == "READ_ONLY":
            ceiling = "READ_ONLY"
        meta = {
            "display_name": state.display_name,
            "hostname": socket.gethostname(),
            "platform": platform.system(),
            "architecture": platform.machine(),
            "agent_version": __version__,
            "protocol_version": "1",
            "public_key_b64": state.public_key_b64,
            "capabilities": capabilities,
            "local_ceiling": ceiling,
        }
        if state.device_id and state.device_token:
            meta.update(
                device_id=state.device_id,
                device_token_hash=hashlib.sha256(
                    state.device_token.encode()
                ).hexdigest(),
            )
        with httpx.Client(
            timeout=20,
            headers={"User-Agent": "CommandCore-Agent/" + __version__},
            follow_redirects=False,
        ) as client:
            if not state.enrollment_id or state.enrollment_expires_at <= time.time():
                proof = base64.b64encode(
                    private.sign(
                        (
                            "commandcore-enroll-init-v1\n"
                            + json.dumps(
                                meta,
                                sort_keys=True,
                                separators=(",", ":"),
                                ensure_ascii=False,
                            )
                        ).encode()
                    )
                ).decode()
                response = client.post(
                    base + "/api/enrollment/start", json={**meta, "proof": proof}
                )
                if response.status_code != 200:
                    print(
                        "Enrollment start rejected (HTTP "
                        + str(response.status_code)
                        + ").",
                        file=sys.stderr,
                    )
                    return 1
                data = response.json()
                state.enrollment_id = data["id"]
                state.enrollment_poll_token = data["poll_token"]
                state.enrollment_uri = data["verification_uri"]
                state.enrollment_code = data["verification_code"]
                state.enrollment_expires_at = data["expires_at"]
                save(state, pending_path)
            print(
                f"CommandCore\n\nDevice: {state.display_name}\nOS: {platform.system()}\nArchitecture: {platform.machine()}\nRequested local ceiling: {ceiling}\n\nOpen:\n{state.enrollment_uri}\n\nVerification code: {state.enrollment_code}\n\nWaiting for approval...",
                flush=True,
            )
            proof = base64.b64encode(
                private.sign(
                    f"commandcore-enroll-claim-v1\n{state.enrollment_id}\n{state.enrollment_poll_token}".encode()
                )
            ).decode()
            while time.time() < state.enrollment_expires_at:
                response = client.post(
                    base + "/api/enrollment/poll",
                    json={"poll_token": state.enrollment_poll_token, "proof": proof},
                )
                if response.status_code == 429:
                    time.sleep(5)
                    continue
                if response.status_code != 200:
                    print(
                        "Enrollment expired, consumed or rejected. Restart enrollment.",
                        file=sys.stderr,
                    )
                    return 1
                data = response.json()
                if data["status"] == "rejected":
                    print("Enrollment rejected by operator.", file=sys.stderr)
                    return 1
                if data["status"] == "approved":
                    if data.get("credential_source") == "agent":
                        if data["device_id"] != state.device_id:
                            raise ValueError("device identity mismatch")
                    else:
                        state.device_token = data["device_token"]
                    state.device_id = data["device_id"]
                    state.enrollment_poll_token = None
                    state.enrollment_uri = None
                    state.enrollment_code = None
                    state.enrollment_id = None
                    save(state, state_path)
                    pending_path.unlink()
                    print(
                        "[OK] Device approved\n[OK] Device identity established\n[OK] Permission ceiling: "
                        + data["permission_ceiling"],
                        flush=True,
                    )
                    if args.no_connect:
                        print("Start the installed Agent service to connect securely.")
                        return 0
                    from .cli import run_agent

                    args.once = False
                    return asyncio.run(run_agent(args))
                time.sleep(3)
        print("Enrollment expired. Run enrollment again.", file=sys.stderr)
        return 1
    except (httpx.HTTPError, ValueError, KeyError):
        print(
            "Enrollment unavailable; no credentials were logged. Retry to resume.",
            file=sys.stderr,
        )
        return 1
