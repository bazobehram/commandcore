"""Actual Unix sockets, synthetic OAuth, no real worker/Docker provision."""

from __future__ import annotations

import os
import socket
import threading

import pytest
from commandcore_server.browser_provision_intent import (
    ProvisionNonceLedger,
    issue_provision_intent,
    verify_and_consume_provision_intent,
)
from commandcore_server.browser_provision_ipc import (
    BrowserProvisionTransportDenied,
    send_provision_intent,
    serve_provision_intents,
)
from commandcore_server.models import Principal

KEY = b"signed-local-transport-test-only-intent-key"
ISSUER = "https://example-issuer.invalid/"


def _signed(owner: str = "first") -> str:
    return issue_provision_intent(
        Principal(
            subject=owner,
            issuer=ISSUER,
            client_id="cli",
            auth_kind="oauth2",
            scopes=("commandcore:standard",),
        ),
        KEY,
    )


def _socket_server(tmp_path, consumer, listener_ready, *, peer_uid=None, count=1):
    tmp_path.chmod(0o700)
    path = tmp_path / "ipc.sock"
    failures = []

    def run():
        try:
            serve_provision_intents(
                str(path),
                expected_client_uid=os.getuid() if peer_uid is None else peer_uid,
                consume=consumer,
                max_connections=count,
            )
        except Exception as exc:  # noqa: BLE001 - thread exception capture
            failures.append(exc)

    task = threading.Thread(target=run, daemon=True)
    task.start()
    assert listener_ready.wait(timeout=5), failures
    assert path.exists(), failures
    return path, task, failures


def _finish(task, failures):
    task.join(timeout=7)
    assert not task.is_alive()
    assert not failures


def test_real_unix_socket_accepts_verified_intents_then_refuses_replays(
    tmp_path, listener_ready
):
    tmp_path.chmod(0o700)
    ledger = ProvisionNonceLedger(str(tmp_path / "nonces.sqlite3"))
    owners = []

    def consume(token):
        owners.append(
            verify_and_consume_provision_intent(token, KEY, ISSUER, ledger).subject
        )

    path, thread, failures = _socket_server(tmp_path, consume, listener_ready, count=3)
    token = _signed()
    assert (
        send_provision_intent(token, str(path), operator_uid=os.getuid()) == "accepted"
    )
    with pytest.raises(BrowserProvisionTransportDenied, match="refused"):
        send_provision_intent(token, str(path), operator_uid=os.getuid())
    assert (
        send_provision_intent(_signed("second"), str(path), operator_uid=os.getuid())
        == "accepted"
    )
    _finish(thread, failures)
    ledger.close()
    assert owners == ["first", "second"]
    assert not path.exists()


def test_wrong_server_uid_is_denied_before_sending_identity(tmp_path, listener_ready):
    calls = []
    path, thread, failures = _socket_server(tmp_path, calls.append, listener_ready)
    with pytest.raises(
        BrowserProvisionTransportDenied, match="untrusted operator peer"
    ):
        send_provision_intent(_signed(), str(path), operator_uid=os.getuid() + 1)
    _finish(thread, failures)
    assert calls == []


def test_wrong_client_uid_is_denied_before_calling_operator(tmp_path, listener_ready):
    calls = []
    path, thread, failures = _socket_server(
        tmp_path, calls.append, listener_ready, peer_uid=os.getuid() + 1
    )
    with pytest.raises(BrowserProvisionTransportDenied):
        send_provision_intent(_signed(), str(path), operator_uid=os.getuid())
    _finish(thread, failures)
    assert calls == []


def test_reject_oversize_bad_socket_and_symbolic_link(tmp_path, listener_ready):
    path, thread, failures = _socket_server(
        tmp_path, lambda _: pytest.fail("must not consume"), listener_ready, count=1
    )
    with pytest.raises(BrowserProvisionTransportDenied):
        send_provision_intent("a" * 5000, str(path), operator_uid=os.getuid())
    link = tmp_path / "link.sock"
    link.symlink_to(path)
    with pytest.raises(BrowserProvisionTransportDenied):
        send_provision_intent(_signed(), str(link), operator_uid=os.getuid())
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.connect(str(path))
        sock.sendall(b"x" * 4097)
        sock.shutdown(socket.SHUT_WR)
        assert sock.recv(128) == b"DENIED\n"
    _finish(thread, failures)


def test_world_writable_socket_directory_is_rejected(tmp_path):
    tmp_path.chmod(0o777)
    with pytest.raises(BrowserProvisionTransportDenied):
        serve_provision_intents(
            str(tmp_path / "ipc.sock"),
            expected_client_uid=os.getuid(),
            consume=lambda _: None,
            max_connections=1,
        )
    assert not (tmp_path / "ipc.sock").exists()


def test_wrong_operator_primary_group_is_denied(tmp_path, listener_ready):
    calls = []
    path, thread, failures = _socket_server(tmp_path, calls.append, listener_ready)
    with pytest.raises(
        BrowserProvisionTransportDenied, match="untrusted operator peer"
    ):
        send_provision_intent(
            _signed(), str(path), operator_uid=os.getuid(), operator_gid=os.getgid() + 1
        )
    _finish(thread, failures)
    assert calls == []


def test_wrong_api_primary_group_is_denied_before_operator(tmp_path, listener_ready):
    calls = []
    tmp_path.chmod(0o700)
    path = tmp_path / "ipc.sock"
    failures = []

    def serve():
        try:
            serve_provision_intents(
                str(path),
                expected_client_uid=os.getuid(),
                expected_client_gid=os.getgid() + 1,
                socket_gid=os.getgid(),
                consume=calls.append,
                max_connections=1,
            )
        except Exception as exc:  # noqa: BLE001 - propagate exception from test thread
            failures.append(exc)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    assert listener_ready.wait(timeout=5), failures
    assert path.exists(), failures
    with pytest.raises(BrowserProvisionTransportDenied):
        send_provision_intent(
            _signed(), str(path), operator_uid=os.getuid(), operator_gid=os.getgid()
        )
    _finish(thread, failures)
    assert calls == []


def test_failed_operator_socket_group_setup_leaves_no_stale_path(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    target = tmp_path / "ipc.sock"

    def denied_chgrp(*_args):
        raise PermissionError("synthetic group failure")

    monkeypatch.setattr(
        "commandcore_server.browser_provision_ipc.os.chown", denied_chgrp
    )
    with pytest.raises(PermissionError):
        serve_provision_intents(
            str(target),
            expected_client_uid=os.getuid(),
            socket_gid=os.getgid(),
            consume=lambda _: None,
            max_connections=1,
        )
    assert not target.exists()
