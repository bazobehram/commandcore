"""API-side transport to an operator-owned per-worker Unix control relay.

Untrusted tool arguments cannot select a relay path, hostname or worker ID.
The Browser owner binding and signed physical attestation remain mandatory.
"""

from __future__ import annotations

import re
import stat
from pathlib import Path

import httpx
import websockets

from .browser_errors import BrowserError

_WORKER_ID = re.compile(r"w-[0-9a-f]{18}\Z")
_SOCKET_NAMES = {"steel", "policy"}


class WorkerUnixClient:
    def __init__(
        self, root: str, worker_id: str, *, operator_uid: int, operator_gid: int
    ):
        if (
            not isinstance(worker_id, str)
            or not _WORKER_ID.fullmatch(worker_id)
            or operator_uid < 0
            or operator_gid < 0
        ):
            raise BrowserError("invalid Browser relay configuration")
        self.root = Path(root)
        self.worker_id = worker_id
        self.operator_uid = operator_uid
        self.operator_gid = operator_gid
        self._pinned: dict[str, tuple[int, int]] = {}
        self._validate_dir()

    def _validate_dir(self) -> None:
        root = self.root
        path = root / self.worker_id
        try:
            if not root.is_absolute() or root.is_symlink() or path.is_symlink():
                raise BrowserError("Browser relay directory unsafe")
            ancestor = root.parent.stat()
            if not stat.S_ISDIR(ancestor.st_mode) or ancestor.st_mode & 0o022:
                raise BrowserError("Browser relay root parent writable by others")
            parent = root.lstat()
            child = path.lstat()
            for info in (parent, child):
                if (
                    not stat.S_ISDIR(info.st_mode)
                    or info.st_uid != self.operator_uid
                    or info.st_mode & 0o027
                ):
                    raise BrowserError("Browser relay directory permissions unsafe")
            if child.st_gid != self.operator_gid:
                raise BrowserError("Browser relay directory group mismatch")
        except OSError as exc:
            raise BrowserError("Browser relay directory missing") from exc

    def socket(self, service: str) -> str:
        if service not in _SOCKET_NAMES:
            raise BrowserError("Browser relay service denied")
        self._validate_dir()
        path = self.root / self.worker_id / (service + ".sock")
        try:
            info = path.lstat()
            if (
                not stat.S_ISSOCK(info.st_mode)
                or info.st_uid != self.operator_uid
                or info.st_gid != self.operator_gid
                or stat.S_IMODE(info.st_mode) != 0o660
            ):
                raise BrowserError("Browser relay socket identity unsafe")
            identity = (info.st_dev, info.st_ino)
            old = self._pinned.setdefault(service, identity)
            if old != identity:
                raise BrowserError("Browser relay socket replaced during session")
            return str(path)
        except OSError as exc:
            raise BrowserError("Browser relay socket unavailable") from exc

    def http_client(
        self, *, policy: bool = False, timeout: float = 15
    ) -> httpx.AsyncClient:
        name = "policy" if policy else "steel"
        return httpx.AsyncClient(
            transport=httpx.AsyncHTTPTransport(uds=self.socket(name), retries=0),
            trust_env=False,
            timeout=timeout,
        )

    def websocket(self, uri: str, **options):
        # uri is derived from the existing internal Steel CDP endpoint, not
        # from a tool-supplied URL or external navigation target.
        if not uri.startswith("ws://127.0.0.1:3000/"):
            raise BrowserError("invalid private relay WebSocket URI")
        return websockets.unix_connect(self.socket("steel"), uri=uri, **options)
