"""Bounded dual-stack WebSocket opening; canonical URI and TLS trust are retained."""

from __future__ import annotations

import asyncio
import inspect
import socket
import ssl
import sys
from urllib.parse import urlsplit

import websockets
from websockets.exceptions import InvalidHandshake
from websockets.asyncio.client import ClientConnection

ATTEMPT_DELAY = 0.25
OPEN_TIMEOUT = 15.0


class ConnectionFailure(Exception):
    def __init__(self, stage: str, detail: str):
        self.stage = stage
        super().__init__(f"stage={stage}: {detail}")


def interleave(addresses):
    """Keep the resolver's preferred family and ordering within each family."""
    unique = list(dict.fromkeys(addresses))
    if not unique:
        return []
    first = [a for a in unique if a[0] == unique[0][0]]
    other = [a for a in unique if a[0] != unique[0][0]]
    result = []
    while first or other:
        if first:
            result.append(first.pop(0))
        if other:
            result.append(other.pop(0))
    return result


async def dispose(opening):
    # Losing openings haven't sent an Agent hello. Abort their transport rather
    # than waiting for a WebSocket close handshake with an unresponsive peer.
    transport = getattr(opening, "transport", None)
    if transport is not None:
        transport.abort()
    else:
        await opening.close()


async def race(addresses, attempt, *, delay=ATTEMPT_DELAY):
    """Race complete openings, accelerating the next attempt on a failure.

    The caller owns the overall deadline. Always drain cancelled tasks and
    close simultaneous successful losers, including when the caller cancels.
    """
    pending = set()
    winner = None
    errors = []
    iterator = iter(addresses)
    exhausted = False
    try:
        while pending or not exhausted:
            if not exhausted:
                try:
                    pending.add(asyncio.create_task(attempt(next(iterator))))
                except StopIteration:
                    exhausted = True
            if not pending:
                break
            done, pending = await asyncio.wait(
                pending,
                timeout=None if exhausted else delay,
                return_when=asyncio.FIRST_COMPLETED,
            )
            for task in done:
                try:
                    value = task.result()
                except Exception as exc:
                    errors.append(exc)
                else:
                    if winner is None:
                        winner = value
                    else:
                        await dispose(value)
            if winner is not None:
                return winner
        if errors:
            # Keep the original rejection accessible to revocation handling.
            raise errors[-1]
        raise ConnectionFailure("dns", "no viable addresses")
    finally:
        for task in pending:
            task.cancel()
        for result in await asyncio.gather(*pending, return_exceptions=True):
            if not isinstance(result, BaseException) and result is not winner:
                await dispose(result)
        if winner is not None and asyncio.current_task().cancelling():
            await dispose(winner)


async def connect(uri: str, headers: dict[str, str]):
    parsed = urlsplit(uri)
    host = parsed.hostname
    if parsed.scheme not in {"ws", "wss"} or not host:
        raise ConnectionFailure("dns", "invalid WebSocket endpoint")
    port = parsed.port or (443 if parsed.scheme == "wss" else 80)
    loop = asyncio.get_running_loop()
    stages = {}
    phase = "dns"
    try:
        async with asyncio.timeout(OPEN_TIMEOUT):
            try:
                addresses = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            except OSError as exc:
                raise ConnectionFailure("dns", "resolution failed") from exc
            addresses = interleave(addresses)
            phase = "tcp"

            async def attempt(address):
                family, kind, protocol, _, sockaddr = address
                sock = socket.socket(family, kind, protocol)
                sock.setblocking(False)
                stage = "tcp"
                stages[address] = stage
                opening_transport = None

                class OpeningConnection(ClientConnection):
                    def connection_made(self, transport):
                        nonlocal opening_transport
                        opening_transport = transport
                        # asyncio calls this only after its verified TLS handshake.
                        stages[address] = "upgrade"
                        super().connection_made(transport)

                try:
                    await loop.sock_connect(sock, sockaddr)
                    stage = "tls" if parsed.scheme == "wss" else "upgrade"
                    stages[address] = stage
                    options = dict(
                        sock=sock,
                        additional_headers=headers,
                        open_timeout=None,
                        ping_interval=20,
                        ping_timeout=20,
                        max_size=16 * 1024 * 1024,
                        create_connection=OpeningConnection,
                    )
                    if "proxy" in inspect.signature(websockets.connect).parameters:
                        options["proxy"] = (
                            None  # Explicit sockets use direct Agent transport.
                        )
                    if parsed.scheme == "wss":
                        options.update(
                            ssl=ssl.create_default_context(), server_hostname=host
                        )
                    ws = await websockets.connect(uri, **options)
                    sock = None  # Transport now owns the socket.
                    return ws
                except ssl.SSLError as exc:
                    print(
                        f"Agent opening attempt failed: stage=tls family={family.name}",
                        file=sys.stderr,
                        flush=True,
                    )
                    raise ConnectionFailure(
                        "tls", "handshake/certificate failure"
                    ) from exc
                except InvalidHandshake as exc:
                    status = getattr(
                        getattr(exc, "response", None), "status_code", None
                    )
                    failure = ConnectionFailure(
                        "authentication" if status in {401, 403} else "upgrade",
                        "WebSocket rejected",
                    )
                    failure.response = getattr(exc, "response", None)
                    raise failure from exc
                except OSError as exc:
                    print(
                        f"Agent opening attempt failed: stage={stages[address]} family={family.name}",
                        file=sys.stderr,
                        flush=True,
                    )
                    raise ConnectionFailure(stage, "connection failed") from exc
                finally:
                    if sock is not None:
                        if opening_transport is not None:
                            opening_transport.abort()
                        sock.close()

            return await race(addresses, attempt)
    except TimeoutError as exc:
        active = sorted(set(stages.values()))
        detail = "/".join(active) if active else phase
        raise ConnectionFailure(
            phase if not active else "opening", f"15s deadline; pending={detail}"
        ) from exc
