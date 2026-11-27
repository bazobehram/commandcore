"""Peer-authenticated local Unix transport for signed Browser provision intents.

No public HTTP listener, OAuth token forwarding, Docker socket in API, or
automatic opt-in is exposed by this module. The operator alone chooses images,
egress policy, caps and storage. Wire to real services only after deployment
review and signed-worker routing acceptance.
"""

from __future__ import annotations

import os
import socket
import stat
import struct
from collections.abc import Callable
from pathlib import Path

from .browser_provision_intent import BrowserProvisionIntentDenied
from .browser_worker_orchestrator import WorkerQuarantined

_MAX_REQUEST = 4096
_MAX_REPLY = 128
_TIMEOUT = 5.0
_ACK_TIMEOUT = 120.0


class BrowserProvisionTransportDenied(RuntimeError):
    """Local IPC identity, file permissions or protocol are untrusted."""


def _socket_path(path: str, *, must_exist: bool) -> Path:
    target = Path(path)
    if not target.is_absolute() or len(str(target).encode()) >= 108:
        raise BrowserProvisionTransportDenied("operator socket location invalid")
    try:
        directory = target.parent.stat()
        if not stat.S_ISDIR(directory.st_mode) or directory.st_mode & 0o027:
            raise BrowserProvisionTransportDenied("operator socket directory insecure")
        if must_exist:
            sockstat = target.lstat()
            if not stat.S_ISSOCK(sockstat.st_mode) or sockstat.st_mode & 0o007:
                raise BrowserProvisionTransportDenied("operator socket insecure")
        elif target.exists() or target.is_symlink():
            raise BrowserProvisionTransportDenied("operator socket already exists")
    except OSError as exc:
        raise BrowserProvisionTransportDenied("operator socket unavailable") from exc
    return target


def _peer_credentials(sock: socket.socket) -> tuple[int, int]:
    if not hasattr(socket, "SO_PEERCRED"):
        raise BrowserProvisionTransportDenied("kernel peer credentials unsupported")
    try:
        data = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        _pid, uid, gid = struct.unpack("3i", data)
        return uid, gid
    except (OSError, struct.error) as exc:
        raise BrowserProvisionTransportDenied("peer identity unavailable") from exc


def send_provision_intent(
    token: str, path: str, *, operator_uid: int, operator_gid: int | None = None
) -> str:
    """Authorized API process sends an already-JWT-verified, signed intent."""
    target = _socket_path(path, must_exist=True)
    if (
        operator_uid < 0
        or (operator_gid is not None and operator_gid < 0)
        or not isinstance(token, str)
    ):
        raise BrowserProvisionTransportDenied("operator peer or request invalid")
    try:
        request = token.encode("ascii")
    except UnicodeEncodeError as exc:
        raise BrowserProvisionTransportDenied("operator request must be ASCII") from exc
    if not 1 <= len(request) <= _MAX_REQUEST or b"\n" in request or b"\r" in request:
        raise BrowserProvisionTransportDenied("operator request too large or invalid")
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(_TIMEOUT)
            conn.connect(str(target))
            uid, gid = _peer_credentials(conn)
            if uid != operator_uid or (
                operator_gid is not None and gid != operator_gid
            ):
                raise BrowserProvisionTransportDenied("untrusted operator peer")
            conn.sendall(request)
            conn.shutdown(socket.SHUT_WR)
            # Admission timeout differs from the worker creation response.
            # After a timeout, outcome is unknown and must not auto-retry.
            conn.settimeout(_ACK_TIMEOUT)
            response = conn.recv(_MAX_REPLY + 1)
            if len(response) > _MAX_REPLY or response not in (
                b"ACCEPTED\n",
                b"DENIED\n",
            ):
                raise BrowserProvisionTransportDenied("invalid operator response")
            if response != b"ACCEPTED\n":
                raise BrowserProvisionTransportDenied(
                    "operator refused provision intent"
                )
            return "accepted"
    except (OSError, TimeoutError) as exc:
        raise BrowserProvisionTransportDenied("operator transport unavailable") from exc


def _remove_owned_socket(target: Path, pinned: os.stat_result) -> None:
    try:
        st = target.lstat()
        if (
            stat.S_ISSOCK(st.st_mode)
            and st.st_uid == os.geteuid()
            and (st.st_dev, st.st_ino) == (pinned.st_dev, pinned.st_ino)
        ):
            target.unlink()
    except OSError:
        pass


def serve_provision_intents(
    path: str,
    *,
    expected_client_uid: int,
    expected_client_gid: int | None = None,
    socket_gid: int | None = None,
    consume: Callable[[str], object],
    stop: Callable[[], bool] | None = None,
    max_connections: int | None = None,
) -> None:
    """Operator-side serial listener; consume must verify/replay-check before Docker.

    Never bind on a network interface. Peer UID is checked before reading data.
    A real operator must supply an authenticated handler, not a permissive stub.
    """
    if (
        expected_client_uid < 0
        or (expected_client_gid is not None and expected_client_gid < 0)
        or (socket_gid is not None and socket_gid < 0)
        or (max_connections is not None and max_connections < 1)
    ):
        raise BrowserProvisionTransportDenied("operator peer policy invalid")
    target = _socket_path(path, must_exist=False)
    accepted = 0
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        original_umask = os.umask(0o117)
        try:
            listener.bind(str(target))
        finally:
            os.umask(original_umask)
        pinned = target.lstat()
        try:
            if socket_gid is not None:
                os.chown(target, -1, socket_gid)
            os.chmod(target, 0o660)
            if socket_gid is not None and target.stat().st_gid != socket_gid:
                raise BrowserProvisionTransportDenied("operator socket group mismatch")
        except (OSError, BrowserProvisionTransportDenied):
            _remove_owned_socket(target, pinned)
            raise
        listener.listen(4)
        listener.settimeout(0.5)
        try:
            while (max_connections is None or accepted < max_connections) and not (
                stop and stop()
            ):
                try:
                    conn, _ = listener.accept()
                except TimeoutError:
                    continue
                accepted += 1
                with conn:
                    conn.settimeout(_TIMEOUT)
                    try:
                        uid, gid = _peer_credentials(conn)
                        if uid != expected_client_uid or (
                            expected_client_gid is not None
                            and gid != expected_client_gid
                        ):
                            raise BrowserProvisionTransportDenied("untrusted API peer")
                        parts = []
                        total = 0
                        while True:
                            chunk = conn.recv(min(1024, _MAX_REQUEST + 1 - total))
                            if not chunk:
                                break
                            parts.append(chunk)
                            total += len(chunk)
                            if total > _MAX_REQUEST:
                                raise BrowserProvisionTransportDenied(
                                    "oversize operator request"
                                )
                        request = b"".join(parts).decode("ascii")
                        if not request or "\n" in request or "\r" in request:
                            raise BrowserProvisionTransportDenied(
                                "invalid operator request"
                            )
                        consume(request)
                    except (
                        BrowserProvisionIntentDenied,
                        BrowserProvisionTransportDenied,
                        WorkerQuarantined,
                        UnicodeError,
                        OSError,
                        ValueError,
                    ):
                        reply = b"DENIED\n"
                    else:
                        reply = b"ACCEPTED\n"
                    try:
                        conn.sendall(reply)
                    except OSError:
                        pass
        finally:
            _remove_owned_socket(target, pinned)
