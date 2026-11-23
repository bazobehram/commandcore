"""Operator-side Unix-socket relay to one immutable Browser control network.

Standalone source-only building block. No Docker access, public TCP listener,
OAuth token handling, or API-to-every-worker-network connection. An operator
must pin this sidecar to exactly one verified control network before use.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import re
import signal
import socket
import stat
import struct
from collections.abc import Awaitable, Callable
from contextlib import suppress
from pathlib import Path

_WORKER_ID = re.compile(r"w-[0-9a-f]{18}\Z")
_MAX_ACTIVE = 32
_CONNECT_TIMEOUT = 5.0
_IDLE_SECONDS = 120
_MAX_AGE_SECONDS = 900
_READ_CHUNK = 65536
_SERVICES = {"steel": 3000, "policy": 8080}

UpstreamOpener = Callable[
    [int], Awaitable[tuple[asyncio.StreamReader, asyncio.StreamWriter]]
]


class WorkerRelayDenied(RuntimeError):
    """The requested socket/peer/worker is untrusted."""


def _verify_directory(path: Path) -> None:
    if not path.is_absolute() or path.is_symlink():
        raise WorkerRelayDenied("worker relay directory path invalid")
    try:
        parent = path.parent.stat()
        info = path.lstat()
    except OSError as exc:
        raise WorkerRelayDenied("worker relay directory unavailable") from exc
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_mode & 0o007
        or info.st_mode & 0o020
        or parent.st_mode & 0o022
    ):
        raise WorkerRelayDenied("worker relay directory permissions unsafe")
    if len(str(path / "policy.sock").encode()) >= 108:
        raise WorkerRelayDenied("worker relay socket path too long")
    for name in _SERVICES:
        candidate = path / (name + ".sock")
        if candidate.exists() or candidate.is_symlink():
            raise WorkerRelayDenied("worker relay socket path already exists")


def _peer(sock: socket.socket) -> tuple[int, int]:
    if not hasattr(socket, "SO_PEERCRED"):
        raise WorkerRelayDenied("Linux peer-credential checking is required")
    try:
        raw = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        _pid, uid, gid = struct.unpack("3i", raw)
        return uid, gid
    except (OSError, struct.error) as exc:
        raise WorkerRelayDenied("worker relay peer identity missing") from exc


async def _bridge(
    down: asyncio.StreamReader,
    down_writer: asyncio.StreamWriter,
    up: asyncio.StreamReader,
    up_writer: asyncio.StreamWriter,
) -> None:
    """Copy opaque HTTP/WebSocket bytes with backpressure and hard deadlines."""
    loop = asyncio.get_running_loop()
    beginning = loop.time()
    last_activity = beginning
    changed = asyncio.Event()

    async def pump(source: asyncio.StreamReader, dest: asyncio.StreamWriter) -> None:
        nonlocal last_activity
        while chunk := await source.read(_READ_CHUNK):
            dest.write(chunk)
            await dest.drain()
            last_activity = loop.time()
            changed.set()

    async def deadline() -> None:
        while True:
            remaining = (
                min(beginning + _MAX_AGE_SECONDS, last_activity + _IDLE_SECONDS)
                - loop.time()
            )
            if remaining <= 0:
                return
            changed.clear()
            try:
                await asyncio.wait_for(changed.wait(), timeout=remaining)
            except TimeoutError:
                continue

    tasks = [
        asyncio.create_task(pump(down, up_writer)),
        asyncio.create_task(pump(up, down_writer)),
        asyncio.create_task(deadline()),
    ]
    try:
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            task.result()
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


async def _policy_read_only(
    client: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    opener: UpstreamOpener,
) -> None:
    """Serve exactly one bounded policy GET; never tunnel CONNECT or pipelines."""
    try:
        request = await asyncio.wait_for(client.readuntil(b"\r\n\r\n"), timeout=5)
    except (
        asyncio.IncompleteReadError,
        asyncio.LimitOverrunError,
        TimeoutError,
    ) as exc:
        raise WorkerRelayDenied("invalid policy request") from exc
    if len(request) > 8192:
        raise WorkerRelayDenied("oversized policy request")
    lines = request[:-4].split(b"\r\n")
    if lines[0] != b"GET /_commandcore/policy HTTP/1.1":
        raise WorkerRelayDenied("relay policy socket is read-only GET")
    if any(
        line.lower().startswith((b"transfer-encoding:", b"content-length:"))
        for line in lines[1:]
    ):
        raise WorkerRelayDenied("policy request body denied")
    upstream: asyncio.StreamWriter | None = None
    try:
        remote, upstream = await asyncio.wait_for(
            opener(8080), timeout=_CONNECT_TIMEOUT
        )
        upstream.write(request)
        await upstream.drain()
        total = 0
        # The policy endpoint must send Connection: close. Do not forward any
        # subsequent client bytes, including pipelined CONNECT requests.
        while chunk := await asyncio.wait_for(remote.read(4096), timeout=5):
            total += len(chunk)
            if total > 16384:
                raise WorkerRelayDenied("policy response exceeds bound")
            writer.write(chunk)
            await writer.drain()
    finally:
        if upstream is not None:
            upstream.close()
            with suppress(OSError):
                await upstream.wait_closed()


class WorkerUnixRelay:
    """Per-worker fixed-target transport; identity authorization stays at API."""

    def __init__(
        self,
        worker_id: str,
        directory: Path,
        *,
        api_uid: int,
        api_gid: int,
        opener: UpstreamOpener | None = None,
    ) -> None:
        if (
            not isinstance(worker_id, str)
            or not _WORKER_ID.fullmatch(worker_id)
            or api_uid < 0
            or api_gid < 0
        ):
            raise WorkerRelayDenied("worker relay immutable identity invalid")
        self.worker_id = worker_id
        self.directory = directory
        self.api_uid = api_uid
        self.api_gid = api_gid
        self._opener = opener or self._open_fixed_upstream
        self._server: dict[str, asyncio.AbstractServer] = {}
        self._pinned: dict[str, tuple[int, int]] = {}
        self._active = 0

    async def _open_fixed_upstream(
        self, port: int
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        if port not in _SERVICES.values():
            raise WorkerRelayDenied("worker relay target port denied")
        # Sidecar must be attached only to this worker's verified control net.
        # The operator pins DNS alias to that worker's physical boundary.
        return await asyncio.wait_for(
            asyncio.open_connection("ccctl-" + self.worker_id, port),
            timeout=_CONNECT_TIMEOUT,
        )

    async def _handle(
        self, service: str, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        self._active += 1
        remote: asyncio.StreamWriter | None = None
        try:
            peer = writer.get_extra_info("socket")
            if (
                peer is None
                or _peer(peer) != (self.api_uid, self.api_gid)
                or self._active > _MAX_ACTIVE
            ):
                return
            if service == "policy":
                await _policy_read_only(reader, writer, self._opener)
                return
            up, remote = await asyncio.wait_for(
                self._opener(_SERVICES[service]), timeout=_CONNECT_TIMEOUT
            )
            await _bridge(reader, writer, up, remote)
        except (OSError, TimeoutError, WorkerRelayDenied, ConnectionError):
            pass  # Fail closed without forwarding partial errors or URLs.
        finally:
            self._active -= 1
            if remote is not None:
                remote.close()
                with suppress(OSError):
                    await remote.wait_closed()
            writer.close()
            with suppress(OSError):
                await writer.wait_closed()

    def _remove_owned_sockets(self) -> None:
        for name, identity in self._pinned.items():
            path = self.directory / (name + ".sock")
            try:
                info = path.lstat()
                if (
                    stat.S_ISSOCK(info.st_mode)
                    and info.st_uid == os.geteuid()
                    and (info.st_dev, info.st_ino) == identity
                ):
                    path.unlink()
            except OSError:
                pass

    async def start(self) -> None:
        _verify_directory(self.directory)
        try:
            for service in _SERVICES:
                path = self.directory / (service + ".sock")
                server = await asyncio.start_unix_server(
                    lambda reader, writer, kind=service: self._handle(
                        kind, reader, writer
                    ),
                    path=str(path),
                )
                self._server[service] = server
                info = path.lstat()
                self._pinned[service] = (info.st_dev, info.st_ino)
                os.chmod(path, 0o660)
                if path.stat().st_gid != self.directory.stat().st_gid:
                    os.chown(path, -1, self.directory.stat().st_gid)
                after = path.lstat()
                if (
                    not stat.S_ISSOCK(after.st_mode)
                    or after.st_mode & 0o007
                    or after.st_gid != self.directory.stat().st_gid
                ):
                    raise WorkerRelayDenied("worker relay socket permissions mismatch")
        except BaseException:
            await self.close()
            raise

    async def close(self) -> None:
        for server in self._server.values():
            server.close()
        for server in self._server.values():
            await server.wait_closed()
        self._server.clear()
        self._remove_owned_sockets()
        self._pinned.clear()

    async def serve_forever(self) -> None:
        if len(self._server) != len(_SERVICES):
            raise WorkerRelayDenied("worker relay not started")
        await asyncio.gather(
            *(server.serve_forever() for server in self._server.values())
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker-id", required=True)
    parser.add_argument("--socket-dir", required=True, type=Path)
    parser.add_argument("--api-uid", required=True, type=int)
    parser.add_argument("--api-gid", required=True, type=int)
    args = parser.parse_args()

    async def run() -> None:
        relay = WorkerUnixRelay(
            args.worker_id,
            args.socket_dir,
            api_uid=args.api_uid,
            api_gid=args.api_gid,
        )
        await relay.start()
        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        # An operator-managed Docker sidecar receives SIGTERM on orderly stop.
        # Gracefully remove only our exact pinned socket inodes.
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, stop.set)
        try:
            await stop.wait()
        finally:
            await relay.close()

    try:
        asyncio.run(run())
    except (OSError, ValueError, WorkerRelayDenied):
        parser.exit(2, "Browser worker control relay unavailable\n")


if __name__ == "__main__":
    main()
