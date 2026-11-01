"""Fast disposable Windows CI gates for local users and credential execution.

No native build, installer, external network, or personal device is required.
The same PowerShell driver is used by the signed installer acceptance job.
"""

from __future__ import annotations

import http.server
import os
import re
import secrets
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from windows_signed_installer_smoke import create_tls_files


def fixture_env() -> dict[str, str]:
    env = os.environ.copy()
    env["COMMANDCORE_CI_USER_PASSWORD"] = "Cc!" + secrets.token_urlsafe(18).replace(
        "-", "a"
    ).replace("_", "b")
    return env


def run_driver(
    driver: Path,
    root: Path,
    mode: str,
    *,
    timeout: int,
    origin: str = "https://localhost",
) -> bool:
    env = fixture_env()
    name = "cc" + secrets.token_hex(5)
    result = subprocess.run(
        [
            "pwsh.exe",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(driver),
            "-UserName",
            name,
            "-FixtureRoot",
            str(root),
            "-Origin",
            origin,
            mode,
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    env.pop("COMMANDCORE_CI_USER_PASSWORD", None)
    if result.returncode == 0:
        return True
    # Fixed diagnostic codes only; no raw stdout/stderr, user, path or password.
    for key in (
        "CI_INSTALL_STAGE",
        "CI_USER_CREATE_CATEGORY",
        "CI_USER_CREATE_HRESULT",
        "CI_USER_CREATE_ERROR_CLASS",
        "CI_USER_CREATE_ERROR_ID",
        "CI_USER_CREATE_EXCEPTION_TYPE",
        "CI_USER_CREATE_MESSAGE_HINT",
        "CI_TASK_LAST_RESULT",
        "CI_TASK_STATE",
        "CI_TASK_DIAGNOSTIC",
        "CI_HTTPS_PREFLIGHT_CURL_EXIT",
        "CI_HTTPS_CURL_BACKEND",
        "CI_HTTPS_CURL_SOURCE",
    ):
        found = re.findall(rf"(?m)^{key}:([-A-Za-z0-9_]+)\s*$", result.stdout)
        if found:
            print("FAIL: " + key + "=" + found[-1])
    return False


def main() -> int:
    if os.name != "nt" or os.environ.get("CI") != "true":
        print("NOT_RUN: disposable Windows CI runner required")
        return 2
    root = Path(os.environ["PROGRAMDATA"])
    driver = Path(__file__).resolve().with_name("windows_signed_installer_driver.ps1")
    if not run_driver(driver, root, "-OnlyAccount", timeout=30):
        return 1
    print("PASS: disposable Windows local-account creation/cleanup")
    with tempfile.TemporaryDirectory(
        prefix="commandcore-task-preflight-", dir=root
    ) as tmp:
        fixture = Path(tmp)
        (fixture / "installers").mkdir()
        (fixture / "result").mkdir()
        shutil.copyfile(
            Path(__file__).resolve().with_name("windows_task_preflight_worker.ps1"),
            fixture / "installers" / "worker.ps1",
        )
        if not run_driver(driver, fixture, "-OnlyCredential", timeout=40):
            return 1
    print("PASS: disposable Windows standard-user credential process/cleanup")
    # A real localhost HTTPS server isolates Schannel/curl failures from the
    # signed installer and avoids rebuilding the native Rust Agent to diagnose.
    with (
        tempfile.TemporaryDirectory(
            prefix="commandcore-https-preflight-", dir=root
        ) as fixture_name,
        tempfile.TemporaryDirectory(prefix="commandcore-https-private-") as tls_name,
    ):
        fixture = Path(fixture_name)
        feed = fixture / "feed"
        feed.mkdir()
        (fixture / "installers").mkdir()
        (fixture / "result").mkdir()
        (feed / "test.txt").write_text("commandcore-ci-https-ok", encoding="utf-8")
        shutil.copyfile(
            Path(__file__).resolve().with_name("windows_https_preflight_worker.ps1"),
            fixture / "installers" / "worker.ps1",
        )
        ca_path, cert_path, key_path = create_tls_files(Path(tls_name))
        handler = lambda *args, **kwargs: SilentHandler(
            *args, directory=str(feed), **kwargs
        )
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cert_path), str(key_path))
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thumbprint = (
            x509.load_pem_x509_certificate(ca_path.read_bytes())
            .fingerprint(hashes.SHA1())
            .hex()
        )
        trusted = False
        thread.start()
        try:
            add = subprocess.run(
                ["certutil.exe", "-addstore", "-f", "Root", str(ca_path)],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            if add.returncode != 0:
                print("FAIL: localhost_tls_trust_setup")
                return 1
            trusted = True
            origin = f"https://localhost:{server.server_port}"
            if not run_driver(
                driver, fixture, "-OnlyCredential", timeout=40, origin=origin
            ):
                return 1
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
            if trusted:
                subprocess.run(
                    ["certutil.exe", "-delstore", "Root", thumbprint],
                    capture_output=True,
                    timeout=15,
                    check=False,
                )
    print("PASS: standard-user localhost HTTPS curl transport")
    return 0


class SilentHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *_args) -> None:
        pass


if __name__ == "__main__":
    sys.exit(main())
