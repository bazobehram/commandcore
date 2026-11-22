#!/usr/bin/env python3
"""Operator-only one-shot signed Browser provision request consumer.

There is deliberately no HTTP endpoint, socket or API-to-Docker delegation here.
A future authenticated local IPC listener may stage a 0600 request for this
operator command; do not expose this CLI to web or untrusted users.
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import tempfile
import time
from pathlib import Path

from browser_worker_lifecycle import provision
from commandcore_server.browser_provision_intent import (
    BrowserProvisionIntentDenied,
    ProvisionNonceLedger,
    verify_and_consume_provision_intent,
)
from commandcore_server.browser_worker_orchestrator import WorkerQuarantined

_MAX_REQUEST = 4096


def _request_from_private_file(path: Path) -> str:
    if not path.is_absolute() or path.is_symlink():
        raise BrowserProvisionIntentDenied("untrusted local provision request")
    directory = path.parent.stat()
    if not stat.S_ISDIR(directory.st_mode) or directory.st_mode & 0o077:
        raise BrowserProvisionIntentDenied("untrusted local provision request")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_mode & 0o077
            or not 1 <= before.st_size <= _MAX_REQUEST
        ):
            raise BrowserProvisionIntentDenied("untrusted local provision request")
        data = os.read(fd, _MAX_REQUEST + 1)
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
        ):
            raise BrowserProvisionIntentDenied(
                "provision request replaced during reading"
            )
        if not data or len(data) > _MAX_REQUEST:
            raise BrowserProvisionIntentDenied("untrusted local provision request")
        try:
            return data.decode("ascii").strip()
        except UnicodeDecodeError as exc:
            raise BrowserProvisionIntentDenied(
                "untrusted local provision request"
            ) from exc
    finally:
        os.close(fd)


def handle_request(
    *,
    request_file: Path,
    state_dir: Path,
    issuer: str,
    allow_hosts: str,
    steel_image: str,
    boundary_image: str,
    intent_secret: bytes,
    binding_secret: str,
    now: int | None = None,
) -> str:
    """Consume verified one-time request then delegate to immutable owner provision."""
    if not state_dir.is_absolute() or state_dir.is_symlink():
        raise BrowserProvisionIntentDenied("operator state directory unsafe")
    state = state_dir.stat()
    if not stat.S_ISDIR(state.st_mode) or state.st_mode & 0o077:
        raise BrowserProvisionIntentDenied("operator state directory unsafe")
    if (
        len(intent_secret) < 32
        or len(binding_secret) < 32
        or intent_secret == binding_secret.encode()
    ):
        raise BrowserProvisionIntentDenied("distinct operator credentials required")
    token = _request_from_private_file(request_file)
    ledger = ProvisionNonceLedger(str(state_dir / "provision-intent-nonces.sqlite3"))
    try:
        owner = verify_and_consume_provision_intent(
            token, intent_secret, issuer, ledger, now=now
        )
    finally:
        ledger.close()
    temp_path = None
    try:
        fd, name = tempfile.mkstemp(
            dir=state_dir, prefix=".browser-owner-", suffix=".json"
        )
        temp_path = Path(name)
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            os.fchmod(output.fileno(), 0o600)
            json.dump(
                {
                    "issuer": owner.issuer,
                    "subject": owner.subject,
                    "client_id": owner.client_id,
                },
                output,
            )
            output.flush()
            os.fsync(output.fileno())
        return provision(
            state_dir,
            temp_path,
            allow_hosts,
            steel_image,
            boundary_image,
            binding_secret,
        )
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request-file", type=Path, required=True)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--issuer", required=True)
    parser.add_argument("--allow-hosts", required=True)
    parser.add_argument("--steel-image", required=True)
    parser.add_argument("--boundary-image", required=True)
    options = parser.parse_args()
    try:
        worker_id = handle_request(
            request_file=options.request_file,
            state_dir=options.state_dir,
            issuer=options.issuer,
            allow_hosts=options.allow_hosts,
            steel_image=options.steel_image,
            boundary_image=options.boundary_image,
            intent_secret=os.environ.get(
                "COMMANDCORE_BROWSER_PROVISION_REQUEST_KEY", ""
            ).encode(),
            binding_secret=os.environ.get("COMMANDCORE_BROWSER_WORKER_BINDING_KEY", ""),
            now=int(time.time()),
        )
        print("BROWSER_OPERATOR_WORKER_PROVISIONED", worker_id)
    except (BrowserProvisionIntentDenied, WorkerQuarantined, OSError, ValueError):
        parser.exit(2, "Browser operator provisioning refused\n")


if __name__ == "__main__":
    main()
