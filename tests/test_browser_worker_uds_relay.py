"""Real Linux UDS relay tests; no Docker or production network access."""

from __future__ import annotations

import asyncio
import os
import socket
import stat

import pytest
import websockets
from commandcore_server.browser_errors import BrowserError
from commandcore_server.browser_worker_uds_client import WorkerUnixClient
from commandcore_server.browser_worker_uds_relay import (
    WorkerRelayDenied,
    WorkerUnixRelay,
)

ID_A = "w-" + "a" * 18
ID_B = "w-" + "b" * 18


def _directory(tmp_path, worker):
    root = tmp_path / worker
    root.mkdir(mode=0o700)
    return root


def _new(worker, root, opener, *, uid=None, gid=None):
    return WorkerUnixRelay(
        worker,
        root,
        api_uid=os.getuid() if uid is None else uid,
        api_gid=os.getgid() if gid is None else gid,
        opener=opener,
    )


@pytest.mark.asyncio
async def test_two_worker_socket_isolation_and_http_policy_over_uds(tmp_path):
    tmp_path.chmod(0o700)

    async def backend_for(value):
        async def echo(reader, writer):
            await reader.readuntil(b"\r\n\r\n")
            payload = value.encode()
            writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Length: "
                + str(len(payload)).encode()
                + b"\r\nConnection: close\r\n\r\n"
                + payload
            )
            await writer.drain()
            writer.close()

        return await asyncio.start_server(echo, "127.0.0.1", 0)

    a = await backend_for("tenant-A")
    b = await backend_for("tenant-B")

    async def mk_open(server):
        async def open_fixed(port):
            assert port in (3000, 8080)
            return await asyncio.open_connection(
                "127.0.0.1", server.sockets[0].getsockname()[1]
            )

        return open_fixed

    ra = _new(ID_A, _directory(tmp_path, ID_A), await mk_open(a))
    rb = _new(ID_B, _directory(tmp_path, ID_B), await mk_open(b))
    await ra.start()
    await rb.start()
    try:
        for relay, expected in ((ra, "tenant-A"), (rb, "tenant-B")):
            client_relay = WorkerUnixClient(
                str(tmp_path),
                relay.worker_id,
                operator_uid=os.getuid(),
                operator_gid=os.getgid(),
            )
            for service in ("steel", "policy"):
                path = relay.directory / (service + ".sock")
                info = path.lstat()
                assert stat.S_ISSOCK(info.st_mode)
                assert stat.S_IMODE(info.st_mode) == 0o660
                async with client_relay.http_client(
                    policy=(service == "policy"), timeout=4
                ) as client:
                    response = await client.get(
                        "http://worker.internal/_commandcore/policy"
                        if service == "policy"
                        else "http://worker.internal/test"
                    )
                assert response.status_code == 200
                assert response.text == expected
    finally:
        await ra.close()
        await rb.close()
        a.close()
        b.close()
        await a.wait_closed()
        await b.wait_closed()
    for worker in (ID_A, ID_B):
        assert not list((tmp_path / worker).glob("*.sock"))


@pytest.mark.asyncio
async def test_websocket_cdp_bytes_transit_unchanged_over_worker_socket(tmp_path):
    async def echo(ws):
        async for frame in ws:
            await ws.send(frame)

    async with websockets.serve(echo, "127.0.0.1", 0) as backend:
        port = backend.sockets[0].getsockname()[1]

        async def open_fixed(service_port):
            assert service_port == 3000
            return await asyncio.open_connection("127.0.0.1", port)

        relay = _new(ID_A, _directory(tmp_path, ID_A), open_fixed)
        await relay.start()
        try:
            uri = "ws://worker.internal/devtools/browser/synthetic"
            client_relay = WorkerUnixClient(
                str(tmp_path),
                ID_A,
                operator_uid=os.getuid(),
                operator_gid=os.getgid(),
            )
            # The physical UDS transport provides the destination; this is
            # solely the CDP Host header, never a remote network connection.
            uri = "ws://127.0.0.1:3000/devtools/browser/synthetic"
            async with client_relay.websocket(uri) as conn:
                await conn.send('{"id":1,"method":"Browser.getVersion"}')
                assert await conn.recv() == '{"id":1,"method":"Browser.getVersion"}'
        finally:
            await relay.close()


@pytest.mark.asyncio
async def test_wrong_uid_or_gid_never_reaches_upstream(tmp_path):
    attempts = []

    async def would_open(_port):
        attempts.append(True)
        raise AssertionError("Unauthorized client should not reach upstream")

    root = _directory(tmp_path, ID_A)
    relay = _new(ID_A, root, would_open, uid=os.getuid() + 1)
    await relay.start()
    try:
        reader, writer = await asyncio.open_unix_connection(str(root / "steel.sock"))
        writer.write(b"GET / HTTP/1.1\r\nHost: local\r\n\r\n")
        await writer.drain()
        try:
            result = await asyncio.wait_for(reader.read(), 2)
        except ConnectionResetError:
            result = b""
        assert result == b""
        writer.close()
        try:
            await writer.wait_closed()
        except ConnectionResetError:
            pass
        assert attempts == []
    finally:
        await relay.close()


@pytest.mark.parametrize("worker", ["w-evil", "w-" + "a" * 19, "../x", "w-" + "z" * 18])
def test_refuse_invalid_worker_id(tmp_path, worker):
    with pytest.raises(WorkerRelayDenied):
        _new(worker, tmp_path, None)


@pytest.mark.asyncio
async def test_refuse_symlink_and_world_accessible_directory(tmp_path):
    root = _directory(tmp_path, ID_A)
    alias = tmp_path / "alias"
    alias.symlink_to(root)
    for candidate in (alias, root):
        if candidate == root:
            root.chmod(0o777)
        relay = _new(ID_A, candidate, None)
        with pytest.raises(WorkerRelayDenied):
            await relay.start()
        assert not list(root.glob("*.sock"))


@pytest.mark.asyncio
async def test_socket_collision_is_not_removed(tmp_path):
    root = _directory(tmp_path, ID_A)
    path = root / "steel.sock"
    with socket.socket(socket.AF_UNIX) as external:
        external.bind(str(path))
        relay = _new(ID_A, root, None)
        with pytest.raises(WorkerRelayDenied):
            await relay.start()
        assert path.exists()
        assert stat.S_ISSOCK(path.stat().st_mode)
    path.unlink()


@pytest.mark.asyncio
async def test_api_pins_relay_inode_and_rejects_replacement(tmp_path):
    async def upstream(_port):
        raise AssertionError("not needed")

    root = _directory(tmp_path, ID_A)
    first = _new(ID_A, root, upstream)
    await first.start()
    api = WorkerUnixClient(
        str(tmp_path), ID_A, operator_uid=os.getuid(), operator_gid=os.getgid()
    )
    assert api.socket("steel") == str(root / "steel.sock")
    # Keep the original listener FD alive: the kernel cannot reuse its inode.
    # A malicious pathname replacement must be refused and never removed by
    # an old relay when the original instance finally stops.
    (root / "steel.sock").unlink()
    (root / "policy.sock").unlink()
    second = _new(ID_A, root, upstream)
    await second.start()
    try:
        with pytest.raises(BrowserError, match="replaced"):
            api.socket("steel")
        await first.close()
        assert (root / "steel.sock").exists()
    finally:
        await first.close()
        await second.close()


def test_api_rejects_other_worker_or_wrong_operator_group(tmp_path):
    root = _directory(tmp_path, ID_A)
    with pytest.raises(BrowserError):
        WorkerUnixClient(
            str(tmp_path),
            "../other",
            operator_uid=os.getuid(),
            operator_gid=os.getgid(),
        )
    with pytest.raises(BrowserError, match="group mismatch"):
        WorkerUnixClient(
            str(tmp_path), ID_A, operator_uid=os.getuid(), operator_gid=os.getgid() + 1
        )
    api = WorkerUnixClient(
        str(tmp_path), ID_A, operator_uid=os.getuid(), operator_gid=os.getgid()
    )
    with pytest.raises(BrowserError, match="service denied"):
        api.socket("../b/policy")
    fake = root / "steel.sock"
    fake.write_text("not an actual Unix socket")
    fake.chmod(0o600)
    with pytest.raises(BrowserError, match="socket identity unsafe"):
        api.socket("steel")


def test_default_disabled_public_uds_relay_flag_is_not_implicit():
    from dataclasses import replace

    from commandcore_server.config import Settings

    settings = replace(
        Settings(),
        browser_enabled=True,
        browser_uds_relay_enabled=True,
        browser_dynamic_workers_enabled=False,
    )
    with pytest.raises(RuntimeError, match="Unix relay requires"):
        settings.validate()


@pytest.mark.asyncio
async def test_browser_gateway_cdp_and_policy_really_use_worker_uds(tmp_path):
    """The existing browser gateway uses sockets, never the host control alias."""
    from commandcore_server.browser_gateway import BrowserGateway

    async def ws_echo(ws):
        async for message in ws:
            await ws.send(message)

    async def policy_reply(reader, writer):
        request = await reader.readuntil(b"\r\n\r\n")
        assert request.startswith(b"GET /_commandcore/policy ")
        body = b'{"policy":"synthetic-operator-only"}'
        writer.write(
            b"HTTP/1.1 200 OK\r\nContent-Length: "
            + str(len(body)).encode()
            + b"\r\nConnection: close\r\n\r\n"
            + body
        )
        await writer.drain()
        writer.close()

    http_server = await asyncio.start_server(policy_reply, "127.0.0.1", 0)
    async with websockets.serve(ws_echo, "127.0.0.1", 0) as ws_server:
        ws_port = ws_server.sockets[0].getsockname()[1]
        policy_port = http_server.sockets[0].getsockname()[1]

        async def fixed_backend(service_port):
            return await asyncio.open_connection(
                "127.0.0.1", ws_port if service_port == 3000 else policy_port
            )

        relay = _new(ID_A, _directory(tmp_path, ID_A), fixed_backend)
        await relay.start()
        try:
            gateway = BrowserGateway(
                base_url=f"http://ccctl-{ID_A}:3000",
                cdp_url=f"ws://ccctl-{ID_A}:3000",
                allow_hosts=("example.com",),
            )
            gateway.control_relay = WorkerUnixClient(
                str(tmp_path),
                ID_A,
                operator_uid=os.getuid(),
                operator_gid=os.getgid(),
            )
            async with gateway._http_client(timeout=3, policy=True) as client:
                response = await client.get(
                    f"http://ccctl-{ID_A}:8080/_commandcore/policy"
                )
            assert response.json()["policy"] == "synthetic-operator-only"
            uri = await gateway._cdp_socket_uri("a" * 36)
            assert uri.startswith("ws://127.0.0.1:3000/")
            async with gateway._connect_ws(uri, open_timeout=3) as conn:
                await conn.send("synthetic CDP message")
                assert await conn.recv() == "synthetic CDP message"
            with pytest.raises(BrowserError, match="session ID"):
                await gateway._cdp_socket_uri("invalid")
        finally:
            await relay.close()
    http_server.close()
    await http_server.wait_closed()


@pytest.mark.asyncio
async def test_policy_socket_denies_connect_before_upstream(tmp_path):
    attempts = []

    async def forbidden(_port):
        attempts.append(True)
        raise AssertionError("CONNECT should not escape via policy socket")

    relay = _new(ID_A, _directory(tmp_path, ID_A), forbidden)
    await relay.start()
    try:
        reader, writer = await asyncio.open_unix_connection(
            str(relay.directory / "policy.sock")
        )
        writer.write(b"CONNECT google.com:443 HTTP/1.1\r\nHost: google.com\r\n\r\n")
        await writer.drain()
        try:
            data = await asyncio.wait_for(reader.read(), 2)
        except ConnectionResetError:
            data = b""
        assert data == b""
        assert not attempts
        writer.close()
        try:
            await writer.wait_closed()
        except ConnectionResetError:
            pass
    finally:
        await relay.close()


@pytest.mark.asyncio
async def test_policy_get_does_not_forward_pipelined_second_request(tmp_path):
    upstream_requests = []

    async def policy(reader, writer):
        raw = await reader.readuntil(b"\r\n\r\n")
        upstream_requests.append(raw)
        writer.write(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
        )
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(policy, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]

    async def upstream(_port):
        return await asyncio.open_connection("127.0.0.1", port)

    relay = _new(ID_A, _directory(tmp_path, ID_A), upstream)
    await relay.start()
    try:
        reader, writer = await asyncio.open_unix_connection(
            str(relay.directory / "policy.sock")
        )
        writer.write(
            b"GET /_commandcore/policy HTTP/1.1\r\nHost: worker\r\n\r\n"
            b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n"
        )
        await writer.drain()
        result = await asyncio.wait_for(reader.read(), 3)
        assert b"200 OK" in result
        assert len(upstream_requests) == 1
        assert b"CONNECT" not in upstream_requests[0]
        writer.close()
        try:
            await writer.wait_closed()
        except ConnectionResetError:
            pass
    finally:
        await relay.close()
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_relay_cli_sigterm_cleans_only_owned_sockets(tmp_path):
    import signal
    import sys

    root = _directory(tmp_path, ID_A)
    proc = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "commandcore_server.browser_worker_uds_relay",
        "--worker-id",
        ID_A,
        "--socket-dir",
        str(root),
        "--api-uid",
        str(os.getuid()),
        "--api-gid",
        str(os.getgid()),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        for _ in range(100):
            if (root / "steel.sock").exists() and (root / "policy.sock").exists():
                break
            if proc.returncode is not None:
                break
            await asyncio.sleep(0.02)
        assert proc.returncode is None
        assert (root / "steel.sock").exists()
        proc.send_signal(signal.SIGTERM)
        assert await asyncio.wait_for(proc.wait(), timeout=5) == 0
        assert not (root / "steel.sock").exists()
        assert not (root / "policy.sock").exists()
    finally:
        if proc.returncode is None:
            proc.kill()
            await proc.wait()
