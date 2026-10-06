"""Bounded release downloads using curl's maintained Happy Eyeballs transport.

No shell, redirects, raw-IP URL rewriting, or certificate bypass. Error messages
contain stages and exit codes only; URLs may carry sensitive query parameters.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from functools import lru_cache
from urllib.parse import urlsplit


class DownloadFailure(RuntimeError):
    pass


@lru_cache(maxsize=4)
def _require_supported_curl(executable: str) -> None:
    process = subprocess.Popen(
        [executable, "--disable", "--version"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    try:
        raw, _ = process.communicate(timeout=2)
    except subprocess.TimeoutExpired as exc:
        process.kill()
        process.communicate()
        raise DownloadFailure(
            "download stage=configuration: curl_version_timeout"
        ) from exc
    found = re.search(rb"^curl (\d+)\.(\d+)\.(\d+)", raw)
    if process.returncode or not found or tuple(map(int, found.groups())) < (8, 4, 0):
        raise DownloadFailure("download stage=configuration: curl_8_4_required")


def download(
    url: str,
    destination: Path,
    *,
    max_bytes: int,
    timeout: float = 60,
    allow_loopback: bool = False,
) -> None:
    parsed = urlsplit(url)
    loopback = (
        allow_loopback
        and parsed.scheme == "http"
        and parsed.hostname in {"127.0.0.1", "localhost", "::1"}
    )
    if (
        (parsed.scheme != "https" and not loopback)
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.fragment
    ):
        raise ValueError("download_requires_https_without_credentials")
    executable = shutil.which("curl.exe" if os.name == "nt" else "curl")
    if not executable:
        raise DownloadFailure("download stage=configuration: curl_required")
    _require_supported_curl(executable)
    command = [
        executable,
        "--disable",
        "--globoff",
        "--proto",
        "=http" if loopback else "=https",
        "--tlsv1.2",
        "--happy-eyeballs-timeout-ms",
        "250",
        "--connect-timeout",
        str(min(15, timeout)),
        "--max-time",
        str(timeout),
        "--max-filesize",
        str(max_bytes),
        "--fail",
        "--silent",
        "--user-agent",
        "CommandCore-release-downloader/1",
        "--write-out",
        "%{time_namelookup} %{time_connect} %{time_appconnect}",
        "--output",
        str(destination),
        "--url",
        url,
    ]
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 2,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        destination.unlink(missing_ok=True)
        raise DownloadFailure("download stage=deadline: overall_timeout") from exc
    if result.returncode:
        destination.unlink(missing_ok=True)
        stage = {
            5: "DNS",
            6: "DNS",
            7: "TCP",
            22: "HTTP",
            28: "deadline",
            35: "TLS",
            51: "TLS",
            58: "TLS",
            60: "TLS",
            77: "TLS",
            63: "HTTP_size",
            92: "HTTP",
        }.get(result.returncode, "transport")
        if result.returncode == 28 and result.stdout:
            try:
                dns, tcp, tls = map(float, result.stdout.split())
                stage = (
                    "DNS"
                    if dns == 0
                    else "TCP"
                    if tcp == 0
                    else "TLS"
                    if parsed.scheme == "https" and tls == 0
                    else "HTTP"
                )
            except (TypeError, ValueError):
                pass
        suffix = " deadline" if result.returncode == 28 else ""
        raise DownloadFailure(
            f"download stage={stage}: curl_exit={result.returncode}{suffix}"
        )
    if destination.stat().st_size > max_bytes:
        destination.unlink(missing_ok=True)
        raise DownloadFailure("download stage=HTTP_size: size_limit")


def download_bytes(
    url: str, *, max_bytes: int, timeout: float = 60, allow_loopback: bool = False
) -> bytes:
    with tempfile.TemporaryDirectory(prefix="commandcore-download-") as directory:
        path = Path(directory) / "payload"
        download(
            url,
            path,
            max_bytes=max_bytes,
            timeout=timeout,
            allow_loopback=allow_loopback,
        )
        return path.read_bytes()
