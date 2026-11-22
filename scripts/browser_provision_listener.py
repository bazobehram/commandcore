#!/usr/bin/env python3
"""Dedicated public Browser operator Unix-socket intake (disabled by default).

Requires explicit host systemd deployment with private credentials, a pinned API
peer UID and separately reviewed worker relay/manifest. No TCP/HTTP port.
"""

from __future__ import annotations

import argparse
import os
import stat
import tempfile
from pathlib import Path

from browser_provision_from_intent import handle_request
from commandcore_server.browser_provision_intent import BrowserProvisionIntentDenied
from commandcore_server.browser_provision_ipc import serve_provision_intents


def private_secret(path: Path) -> bytes:
    if not path.is_absolute() or path.is_symlink():
        raise BrowserProvisionIntentDenied("operator credential path unsafe")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
        try:
            st = os.fstat(fd)
            if (
                not stat.S_ISREG(st.st_mode)
                or st.st_mode & 0o077
                or st.st_uid not in (0, os.geteuid())
                or st.st_size < 32
                or st.st_size > 4096
            ):
                raise BrowserProvisionIntentDenied("operator credential unsafe")
            data = os.read(fd, 4097)
            if len(data) != st.st_size:
                raise BrowserProvisionIntentDenied("operator credential truncated")
            return data
        finally:
            os.close(fd)
    except OSError as exc:
        raise BrowserProvisionIntentDenied("operator credential unreadable") from exc


def run_operator_listener(
    *,
    socket_path: str,
    state_dir: Path,
    expected_client_uid: int,
    issuer: str,
    allow_hosts: str,
    steel_image: str,
    boundary_image: str,
    intent_secret: bytes,
    binding_secret: str,
    max_connections: int | None = None,
) -> None:
    if not state_dir.is_absolute() or state_dir.is_symlink():
        raise BrowserProvisionIntentDenied("operator private state path invalid")
    state = state_dir.stat()
    if not stat.S_ISDIR(state.st_mode) or state.st_mode & 0o077:
        raise BrowserProvisionIntentDenied("operator private state permissions invalid")
    if (
        len(intent_secret) < 32
        or len(binding_secret) < 32
        or intent_secret == binding_secret.encode()
    ):
        raise BrowserProvisionIntentDenied("distinct operator keys required")

    def consume(token: str) -> None:
        # Only the verified peer can submit. The signed intent and durable
        # ledger are validated inside handle_request before Docker is called.
        fd, name = tempfile.mkstemp(prefix=".intent-", suffix=".req", dir=state_dir)
        file = Path(name)
        try:
            with os.fdopen(fd, "w", encoding="ascii") as dest:
                os.fchmod(dest.fileno(), 0o600)
                dest.write(token)
                dest.flush()
                os.fsync(dest.fileno())
            handle_request(
                request_file=file,
                state_dir=state_dir,
                issuer=issuer,
                allow_hosts=allow_hosts,
                steel_image=steel_image,
                boundary_image=boundary_image,
                intent_secret=intent_secret,
                binding_secret=binding_secret,
            )
        finally:
            file.unlink(missing_ok=True)

    serve_provision_intents(
        socket_path,
        expected_client_uid=expected_client_uid,
        consume=consume,
        max_connections=max_connections,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket-path", required=True)
    parser.add_argument("--state-dir", required=True, type=Path)
    parser.add_argument("--expected-client-uid", type=int, required=True)
    parser.add_argument("--issuer", required=True)
    parser.add_argument("--allow-hosts", required=True)
    parser.add_argument("--steel-image", required=True)
    parser.add_argument("--boundary-image", required=True)
    parser.add_argument("--intent-key-file", required=True, type=Path)
    parser.add_argument("--binding-key-file", required=True, type=Path)
    args = parser.parse_args()
    try:
        run_operator_listener(
            socket_path=args.socket_path,
            state_dir=args.state_dir,
            expected_client_uid=args.expected_client_uid,
            issuer=args.issuer,
            allow_hosts=args.allow_hosts,
            steel_image=args.steel_image,
            boundary_image=args.boundary_image,
            intent_secret=private_secret(args.intent_key_file),
            binding_secret=private_secret(args.binding_key_file).decode("ascii"),
        )
    except (BrowserProvisionIntentDenied, OSError, ValueError):
        parser.exit(2, "Browser provisioning operator startup refused\n")


if __name__ == "__main__":
    main()
