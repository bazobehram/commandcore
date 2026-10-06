"""Real curl HTTPS packet-blackhole acceptance in marked disposable namespace."""

import hashlib
import base64
import http.server
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from commandcore_agent.download import DownloadFailure, download_bytes
from dual_stack_reconnect_smoke import RESOLVER


def main():
    assert Path("/run/commandcore-disposable-network").is_file(), (
        "Refusing host network fault injection"
    )
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "resolver.c").write_text(
            RESOLVER.replace(
                "if (!name ||",
                'if(name && !strcmp(name,"commandcore-dns-failure.test")) return EAI_NONAME;\n if (!name ||',
            )
        )
        subprocess.run(
            [
                "gcc",
                "-shared",
                "-fPIC",
                "-o",
                str(root / "resolver.so"),
                str(root / "resolver.c"),
                "-ldl",
            ],
            check=True,
        )
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                str(root / "key"),
                "-out",
                str(root / "cert"),
                "-days",
                "1",
                "-subj",
                "/CN=commandcore-dual-stack.test",
                "-addext",
                "subjectAltName=DNS:commandcore-dual-stack.test",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(root / "cert", root / "key")
        payloads = {}

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                assert (
                    self.headers["Host"].split(":")[0] == "commandcore-dual-stack.test"
                )
                payload = payloads.get(self.path, b"verified alternate-family download")
                self.send_response(200)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):
                pass

        class V6(http.server.ThreadingHTTPServer):
            address_family = socket.AF_INET6

        servers = [http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)]
        port = servers[0].server_port
        servers.append(V6(("::1", port), Handler))
        for server in servers:
            server.socket = context.wrap_socket(server.socket, server_side=True)
            threading.Thread(target=server.serve_forever, daemon=True).start()
        os.environ["LD_PRELOAD"] = str(root / "resolver.so")
        os.environ["CURL_CA_BUNDLE"] = str(root / "cert")
        os.environ["NO_PROXY"] = "*"
        os.environ.pop("RES_OPTIONS", None)

        def rule(tool, action):
            subprocess.run(
                [
                    tool,
                    action,
                    "OUTPUT",
                    "-p",
                    "tcp",
                    "--dport",
                    str(port),
                    "-j",
                    "DROP",
                ],
                check=True,
            )

        try:
            for first4, blocked in [
                (False, None),
                (False, "ip6tables"),
                (True, "iptables"),
            ]:
                if first4:
                    os.environ["CANARY_FIRST_IPV4"] = "1"
                else:
                    os.environ.pop("CANARY_FIRST_IPV4", None)
                if blocked:
                    rule(blocked, "-A")
                try:
                    started = time.monotonic()
                    raw = download_bytes(
                        f"https://commandcore-dual-stack.test:{port}/artifact",
                        max_bytes=1024,
                        timeout=5,
                    )
                    assert raw == b"verified alternate-family download"
                    elapsed = time.monotonic() - started
                    assert elapsed < 3
                    print(
                        json.dumps(
                            {
                                "scenario": blocked or "both_reachable",
                                "status": "PASS",
                                "seconds": round(elapsed, 3),
                                "sha256": hashlib.sha256(raw).hexdigest(),
                            }
                        ),
                        flush=True,
                    )
                finally:
                    if blocked:
                        rule(blocked, "-D")
            # Exercise the actual installer fetch function with signed fixtures.
            assert os.getuid() == 0, (
                "installer privilege-drop fixture requires disposable root"
            )
            root.chmod(0o755)
            (root / "key").chmod(0o600)
            signing = Ed25519PrivateKey.generate()
            public = base64.b64encode(
                signing.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            ).decode()
            binary = b"#!/bin/sh\nexit 0\n"
            manifest = {
                "schema_version": 1,
                "product": "commandcore-agent",
                "version": "1.0.0-test",
                "implementation": "rust",
                "artifacts": [
                    {
                        "platform": "linux",
                        "architecture": "x86_64",
                        "kind": "executable",
                        "url": f"https://commandcore-dual-stack.test:{port}/agent",
                        "sha256": hashlib.sha256(binary).hexdigest(),
                        "size": len(binary),
                    }
                ],
            }
            manifest["signature"] = base64.b64encode(
                signing.sign(
                    json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
                )
            ).decode()
            payloads.update(
                {"/agent": binary, "/manifest.json": json.dumps(manifest).encode()}
            )
            for blocked in ["ip6tables", "iptables"]:
                home = root / ("home-" + blocked)
                home.mkdir()
                os.chown(home, 65534, 65534)
                fixture_env = {
                    **os.environ,
                    "HOME": str(home),
                    "COMMANDCORE_RELEASE_PUBLIC_KEY_B64": public,
                }

                def normal_user():
                    os.setgroups([])
                    os.setgid(65534)
                    os.setuid(65534)

                rule(blocked, "-A")
                try:
                    p = subprocess.run(
                        [
                            "sh",
                            str(
                                Path(__file__).resolve().parents[1] / "install/linux.sh"
                            ),
                            "--manifest",
                            f"https://commandcore-dual-stack.test:{port}/manifest.json",
                            "--no-service",
                            "--no-enroll",
                        ],
                        env=fixture_env,
                        preexec_fn=normal_user,
                        capture_output=True,
                        text=True,
                        timeout=20,
                    )
                    assert p.returncode == 0, p.stderr
                    assert "Implementation: rust" in p.stdout
                    assert (
                        home
                        / ".local/share/commandcore-agent/current/commandcore-agent"
                    ).read_bytes() == binary
                    print(
                        json.dumps(
                            {
                                "scenario": "actual_installer_"
                                + blocked
                                + "_blackhole",
                                "status": "PASS",
                                "signature_hash_checked": True,
                            }
                        ),
                        flush=True,
                    )
                finally:
                    rule(blocked, "-D")
            for tool in ["iptables", "ip6tables"]:
                rule(tool, "-A")
            started = time.monotonic()
            try:
                try:
                    download_bytes(
                        f"https://commandcore-dual-stack.test:{port}/",
                        max_bytes=1024,
                        timeout=2,
                    )
                except DownloadFailure as error:
                    assert "deadline" in str(error)
                else:
                    raise AssertionError("both blackholed accepted")
                assert time.monotonic() - started < 4.5
                print(
                    json.dumps(
                        {"scenario": "both_blackholed_bounded", "status": "PASS"}
                    ),
                    flush=True,
                )
            finally:
                for tool in ["iptables", "ip6tables"]:
                    rule(tool, "-D")
            os.environ["CURL_CA_BUNDLE"] = "/etc/ssl/certs/ca-certificates.crt"
            try:
                download_bytes(
                    f"https://commandcore-dual-stack.test:{port}/",
                    max_bytes=1024,
                    timeout=3,
                )
            except DownloadFailure as error:
                assert "TLS" in str(error)
            else:
                raise AssertionError("untrusted TLS accepted")
            print(
                json.dumps(
                    {"scenario": "TLS_verification_fail_closed", "status": "PASS"}
                ),
                flush=True,
            )
            for url, stage in [
                ("https://commandcore-dns-failure.test/", "DNS"),
                ("https://127.0.0.1:1/", "TCP"),
            ]:
                try:
                    download_bytes(url, max_bytes=1024, timeout=2)
                except DownloadFailure as error:
                    assert "stage=" + stage in str(error)
                else:
                    raise AssertionError("failed transport accepted")
                print(
                    json.dumps({"scenario": stage + "_failure", "status": "PASS"}),
                    flush=True,
                )
        finally:
            for server in servers:
                server.shutdown()
                server.server_close()


if __name__ == "__main__":
    main()
