"""Deterministic scheduler faults plus real verified TLS/Upgrade on loopback."""

import asyncio
import socket
import ssl
import datetime
from unittest.mock import patch

import pytest

from commandcore_agent import network
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from websockets.asyncio.server import serve


class Transport:
    def __init__(self, address):
        self.address = address
        self.closed = False

    async def close(self):
        self.closed = True


def addresses():
    return [
        (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", 443, 0, 0)),
        (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::2", 443, 0, 0)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443)),
    ]


def test_order_interleaves_and_deduplicates():
    v6, v6_second, v4 = addresses()
    assert network.interleave([v6, v6_second, v4, v6]) == [v6, v4, v6_second]
    assert network.interleave([v4, v6_second, v6]) == [v4, v6_second, v6]


def test_successful_loser_cleanup_does_not_wait_for_peer_close():
    async def scenario():
        class AbortTransport:
            aborted = False

            def abort(self):
                self.aborted = True

        class Opening:
            transport = AbortTransport()

            async def close(self):
                raise AssertionError("loser close handshake must not be awaited")

        loser = Opening()
        await asyncio.wait_for(network.dispose(loser), 0.05)
        assert loser.transport.aborted

    asyncio.run(scenario())


@pytest.mark.parametrize("blackholed", [None, socket.AF_INET6, socket.AF_INET, "first"])
def test_stagger_fallback_and_cancel(blackholed):
    async def scenario():
        candidates = network.interleave(addresses())
        if blackholed == socket.AF_INET:
            candidates = [candidates[1], candidates[0]]
        cancelled = []
        started = []

        async def attempt(address):
            started.append(address)
            if address[0] == blackholed or (
                blackholed == "first" and address == candidates[0]
            ):
                try:
                    await asyncio.Future()
                finally:
                    cancelled.append(address)
            return Transport(address)

        winner = await asyncio.wait_for(
            network.race(candidates, attempt, delay=0.01), 0.2
        )
        assert winner.address[0] != blackholed
        if blackholed is not None:
            assert cancelled == [candidates[0]]
        await winner.close()

    asyncio.run(scenario())


def test_both_unreachable_deadline_cancels_every_attempt():
    async def scenario():
        alive = set()

        async def attempt(address):
            alive.add(address)
            try:
                await asyncio.Future()
            finally:
                alive.remove(address)

        with pytest.raises(TimeoutError):
            await asyncio.wait_for(
                network.race(network.interleave(addresses()), attempt, delay=0.01), 0.06
            )
        assert not alive

    asyncio.run(scenario())


def test_tls_rejection_is_not_insecure_retry():
    async def scenario():
        seen = []

        async def attempt(address):
            seen.append(address)
            raise network.ConnectionFailure("tls", "certificate failure")

        with pytest.raises(network.ConnectionFailure, match="stage=tls"):
            await network.race(network.interleave(addresses()), attempt, delay=0.01)
        assert len(seen) == 3

    asyncio.run(scenario())


def test_dns_failure_stage():
    async def scenario():
        with patch.object(
            asyncio.get_running_loop(), "getaddrinfo", side_effect=socket.gaierror()
        ):
            with pytest.raises(network.ConnectionFailure, match="stage=dns"):
                await network.connect("wss://test.invalid/agent", {})

    asyncio.run(scenario())


def test_tcp_failure_stage():
    async def scenario():
        with (
            patch.object(
                asyncio.get_running_loop(), "getaddrinfo", return_value=[addresses()[2]]
            ),
            patch.object(
                asyncio.get_running_loop(),
                "sock_connect",
                side_effect=ConnectionRefusedError(),
            ),
        ):
            with pytest.raises(network.ConnectionFailure, match="stage=tcp"):
                await network.connect("ws://test.invalid/agent", {})

    asyncio.run(scenario())


def test_real_tls_certificate_failure():
    # A plaintext TLS peer cannot cause an insecure WebSocket retry.
    async def scenario():
        requests = []

        async def peer(reader, writer):
            requests.append(await reader.read(2048))
            writer.write(b"HTTP/1.1 200 OK\r\n\r\n")
            await writer.drain()
            writer.close()

        server = await asyncio.start_server(peer, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            with pytest.raises(network.ConnectionFailure, match="stage=tls"):
                await network.connect(f"wss://127.0.0.1:{port}/agent", {})
            assert requests and all(not x.startswith(b"GET") for x in requests)
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(scenario())


@pytest.mark.parametrize("fault", ["tcp_blackhole", "tls_failure"])
def test_verified_tls_hostname_upgrade_and_stalled_candidate(tmp_path, fault):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fixture.test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("fixture.test")]), critical=False
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / "fixture.crt"
    key_path = tmp_path / "fixture.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(cert_path, key_path)
    sni = []
    server_context.set_servername_callback(lambda _s, name, _c: sni.append(name))
    client_context = ssl.create_default_context(cafile=str(cert_path))

    async def scenario():
        bad_requests = []

        async def invalid_tls(reader, writer):
            bad_requests.append(await reader.read(2048))
            writer.write(b"HTTP/1.1 200 OK\r\n\r\n")
            await writer.drain()
            writer.close()

        async def handler(ws):
            assert ws.request.headers["Host"].startswith("fixture.test:")
            assert ws.request.headers["Authorization"] == "Device fixture:fixture"
            await ws.send("verified")
            await ws.wait_closed()

        bad = await asyncio.start_server(invalid_tls, "::1", 0)
        async with serve(handler, "127.0.0.1", 0, ssl=server_context) as server:
            port = server.sockets[0].getsockname()[1]
            loop = asyncio.get_running_loop()
            original_connect = loop.sock_connect
            cancelled = []

            async def blackhole(sock, address):
                if sock.family == socket.AF_INET6:
                    if fault == "tcp_blackhole":
                        try:
                            await asyncio.Future()
                        finally:
                            cancelled.append(True)
                    else:
                        await original_connect(
                            sock, ("::1", bad.sockets[0].getsockname()[1], 0, 0)
                        )
                else:
                    await original_connect(sock, address)

            resolved = [
                (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", port, 0, 0)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port)),
            ]
            with (
                patch.object(loop, "getaddrinfo", return_value=resolved),
                patch.object(loop, "sock_connect", side_effect=blackhole),
                patch.object(
                    network.ssl, "create_default_context", return_value=client_context
                ),
            ):
                ws = await network.connect(
                    f"wss://fixture.test:{port}/agent",
                    {"Authorization": "Device fixture:fixture"},
                )
                assert await ws.recv() == "verified"
                await ws.close()
                if fault == "tcp_blackhole":
                    assert cancelled == [True]
                else:
                    assert bad_requests and all(
                        not x.startswith(b"GET") for x in bad_requests
                    )
                assert (
                    client_context.verify_mode == ssl.CERT_REQUIRED
                    and client_context.check_hostname
                )
            assert sni == ["fixture.test"]
        bad.close()
        await bad.wait_closed()

    asyncio.run(scenario())
