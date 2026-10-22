"""Small fail-closed CONNECT proxy and Steel control relay for browser staging.

The proxy is intentionally HTTPS-only.  It resolves each requested host itself,
rejects the whole answer set if any address is non-global, and connects to the
validated numeric address so a second DNS lookup cannot change the destination.
Docker network isolation remains a required part of the enforcement boundary.
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import os
import re
import socket
from contextlib import suppress
from urllib.parse import urlsplit

POLICY_VERSION = "deny-private-v1"
MAX_HEADER_BYTES = 32_768
# Refuse excess in-flight socket clients before reading headers or resolving DNS.
# This is a per-worker availability budget, not a substitute for Docker limits.
MAX_ACTIVE_PROXY_CONNECTIONS = 48
# Budget untrusted HTTPS CONNECT sockets. One-way streams are valid: the
# inactivity timer resets on traffic in EITHER direction. A hard lifetime
# bounds slow trickle connections that would otherwise retain slots forever.
PROXY_TUNNEL_IDLE_SECONDS = 120
PROXY_TUNNEL_MAX_SECONDS = 900


class EgressDenied(Exception):
    pass


# "*" is an explicit PUBLIC-WEB mode, not unrestricted network access.
# Numeric destinations, private/reserved DNS names, and every DNS answer that
# is not globally routable remain blocked even for public-web mode.
NON_PUBLIC_SUFFIXES = (
    ".localhost",
    ".local",
    ".localdomain",
    ".internal",
    ".intranet",
    ".lan",
    ".home.arpa",
    ".test",
    ".invalid",
    ".onion",
    ".arpa",
)


def _public_dns_name(host: str) -> bool:
    if not isinstance(host, str):
        return False
    host = host.lower().rstrip(".")
    if (
        len(host) > 253
        or "." not in host
        or any(
            host == suffix.lstrip(".") or host.endswith(suffix)
            for suffix in NON_PUBLIC_SUFFIXES
        )
    ):
        return False
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        return False
    labels = host.split(".")
    return all(
        1 <= len(label) <= 63
        and bool(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label))
        for label in labels
    )


def _normalize_hosts(raw: str) -> tuple[str, ...]:
    hosts = tuple(
        sorted(
            {
                part.strip().lower().rstrip(".")
                for part in raw.split(",")
                if part.strip()
            }
        )
    )
    if hosts == ("*",):
        return hosts
    if (
        not hosts
        or "*" in hosts
        or any(
            not re.fullmatch(r"(?:\*\.)?[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", host)
            or not _public_dns_name(host.removeprefix("*."))
            for host in hosts
        )
    ):
        raise ValueError("BROWSER_EGRESS_ALLOW_HOSTS must be public DNS hosts or '*'")
    return hosts


def _host_allowed(host: str, allow_hosts: tuple[str, ...]) -> bool:
    host = host.lower().rstrip(".")
    if not _public_dns_name(host):
        return False
    if allow_hosts == ("*",):
        return True
    return any(
        host == allowed
        or (
            allowed.startswith("*.")
            and host.endswith(allowed[1:])
            and host != allowed[2:]
        )
        for allowed in allow_hosts
    )


def _connect_authority(authority: str) -> tuple[str, int]:
    try:
        parsed = urlsplit("//" + authority)
        host = (parsed.hostname or "").lower().rstrip(".")
        port = parsed.port
    except ValueError as exc:
        raise EgressDenied("invalid CONNECT authority") from exc
    if (
        not host
        or port != 443
        or parsed.username
        or parsed.password
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise EgressDenied("only DNS-name HTTPS destinations on port 443 are allowed")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise EgressDenied("IP-literal destinations are forbidden")
    if not re.fullmatch(r"[a-z0-9.-]+", host) or "." not in host:
        raise EgressDenied("invalid destination host")
    return host, port


async def _resolve_global(host: str, port: int) -> tuple[str, int]:
    try:
        rows = await asyncio.get_running_loop().getaddrinfo(
            host, port, type=socket.SOCK_STREAM
        )
    except OSError as exc:
        raise EgressDenied("destination DNS lookup failed") from exc
    addresses = {ipaddress.ip_address(row[4][0]) for row in rows}
    # Reject mixed public/private answers too. Selecting only a public member can
    # become unsafe when clients retry another answer or DNS changes underneath us.
    if not addresses or any(
        not address.is_global
        or address.is_multicast
        or address.is_unspecified
        or (address.version == 6 and (address.sixtofour or address.teredo))
        for address in addresses
    ):
        raise EgressDenied("destination DNS includes a non-global address")
    address = min(addresses, key=lambda item: (item.version, int(item)))
    return str(address), port


async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while data := await reader.read(65_536):
            writer.write(data)
            await writer.drain()
    finally:
        with suppress(Exception):
            writer.close()
            await writer.wait_closed()


async def _tunnel_proxy(
    browser_reader: asyncio.StreamReader,
    browser_writer: asyncio.StreamWriter,
    remote_reader: asyncio.StreamReader,
    remote_writer: asyncio.StreamWriter,
) -> None:
    """Bound a bidirectional tunnel by shared inactivity and absolute age.

    Traffic in either direction resets the *shared* idle budget. A separate
    lifetime limit prevents a slow-trickle peer occupying one of the limited
    proxy slots forever. On EOF, timeout or error all pumps are cancelled.
    """
    loop = asyncio.get_running_loop()
    started = loop.time()
    last_activity = started
    changed = asyncio.Event()

    async def copy(source: asyncio.StreamReader, target: asyncio.StreamWriter):
        nonlocal last_activity
        while data := await source.read(65_536):
            last_activity = loop.time()
            changed.set()
            target.write(data)
            await target.drain()

    async def watchdog():
        while True:
            # There are no awaits between calculating the limit and clearing
            # the event, so no producer can lose a notification.
            remaining = (
                min(
                    last_activity + PROXY_TUNNEL_IDLE_SECONDS,
                    started + PROXY_TUNNEL_MAX_SECONDS,
                )
                - loop.time()
            )
            if remaining <= 0:
                return
            changed.clear()
            try:
                await asyncio.wait_for(changed.wait(), timeout=remaining)
            except TimeoutError:
                # Another pump may have updated last_activity at the boundary.
                # Re-evaluate both deadlines rather than prematurely closing.
                continue

    tasks = (
        asyncio.create_task(copy(browser_reader, remote_writer)),
        asyncio.create_task(copy(remote_reader, browser_writer)),
        asyncio.create_task(watchdog()),
    )
    try:
        done, _pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            task.result()
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


async def _read_headers(reader: asyncio.StreamReader) -> bytes:
    try:
        return await reader.readuntil(b"\r\n\r\n")
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError) as exc:
        raise EgressDenied("invalid proxy request") from exc


class BrowserBoundary:
    def __init__(self, allow_hosts: tuple[str, ...], steel_host: str, steel_port: int):
        self.allow_hosts = allow_hosts
        self.steel_host = steel_host
        self.steel_port = steel_port
        self._active_proxy_connections = 0

    def policy(self) -> dict[str, object]:
        return {
            "policy": POLICY_VERSION,
            "allow_hosts": list(self.allow_hosts),
            "runtime_network_proof": "required",
        }

    async def proxy(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        # Check and increment without yielding to the event loop. Waiting on a
        # semaphore would retain unbounded idle connection objects instead.
        if self._active_proxy_connections >= MAX_ACTIVE_PROXY_CONNECTIONS:
            writer.write(
                b"HTTP/1.1 503 Service Unavailable\r\n"
                b"Content-Length: 0\r\nConnection: close\r\n\r\n"
            )
            with suppress(Exception):
                await writer.drain()
            writer.close()
            with suppress(Exception):
                await writer.wait_closed()
            return
        self._active_proxy_connections += 1
        upstream_writer: asyncio.StreamWriter | None = None
        established = False
        try:
            raw = await asyncio.wait_for(_read_headers(reader), timeout=5)
            if len(raw) > MAX_HEADER_BYTES:
                raise EgressDenied("proxy headers too large")
            first = raw.split(b"\r\n", 1)[0].decode("ascii", "strict")
            method, target, version = first.split(" ", 2)
            if method == "GET" and target == "/_commandcore/policy":
                body = json.dumps(self.policy(), separators=(",", ":")).encode()
                writer.write(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                    + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
                    + body
                )
                await writer.drain()
                return
            if method != "CONNECT" or version != "HTTP/1.1":
                raise EgressDenied("only CONNECT is supported")
            host, port = _connect_authority(target)
            if not _host_allowed(host, self.allow_hosts):
                raise EgressDenied("destination host is not allowlisted")
            address, port = await _resolve_global(host, port)
            upstream_reader, upstream_writer = await asyncio.wait_for(
                asyncio.open_connection(address, port), timeout=10
            )
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()
            established = True
            await _tunnel_proxy(reader, writer, upstream_reader, upstream_writer)
        except (EgressDenied, ValueError, UnicodeError, TimeoutError, OSError):
            # Once CONNECT returned 200, everything is opaque TLS/tunnel data.
            # Never inject an HTTP 403 into an established encrypted stream.
            if not established:
                writer.write(
                    b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
                with suppress(Exception):
                    await writer.drain()
        finally:
            self._active_proxy_connections -= 1
            if upstream_writer is not None:
                with suppress(Exception):
                    upstream_writer.close()
            with suppress(Exception):
                writer.close()
                await writer.wait_closed()

    async def relay(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            upstream_reader, upstream_writer = await asyncio.wait_for(
                asyncio.open_connection(self.steel_host, self.steel_port), timeout=5
            )
        except (TimeoutError, OSError):
            writer.close()
            return
        await asyncio.gather(
            _pipe(reader, upstream_writer), _pipe(upstream_reader, writer)
        )


async def _serve(args: argparse.Namespace) -> None:
    boundary = BrowserBoundary(
        _normalize_hosts(args.allow_hosts), args.steel_host, args.steel_port
    )
    proxy = await asyncio.start_server(boundary.proxy, args.bind, args.proxy_port)
    relay = await asyncio.start_server(boundary.relay, args.relay_bind, args.relay_port)
    async with proxy, relay:
        await asyncio.gather(proxy.serve_forever(), relay.serve_forever())


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--relay-bind", default="127.0.0.1")
    parser.add_argument("--proxy-port", type=int, default=8080)
    parser.add_argument("--relay-port", type=int, default=3000)
    parser.add_argument("--steel-host", default="steel")
    parser.add_argument("--steel-port", type=int, default=3000)
    parser.add_argument(
        "--allow-hosts", default=os.getenv("BROWSER_EGRESS_ALLOW_HOSTS", "")
    )
    asyncio.run(_serve(parser.parse_args()))


if __name__ == "__main__":
    main()
