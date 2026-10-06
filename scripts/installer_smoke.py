"""Linux installer integrity and rollback checks in a disposable root container.

The installer itself runs as uid/gid 65534. Signing keys exist only in memory.
Service failure injection uses a fixture systemctl; no host service is changed.
"""

from __future__ import annotations

import base64
import hashlib
import http.server
import json
import os
import shutil
import subprocess
import tempfile
import threading
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def main():
    if os.name != "posix" or os.getuid() != 0:
        raise SystemExit("Run inside a disposable Linux root container")
    root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="commandcore-installer-test-") as temp:
        base = Path(temp)
        os.chmod(base, 0o755)
        installer = base / "linux.sh"
        shutil.copyfile(root / "install/linux.sh", installer)
        installer.chmod(0o755)
        web = base / "web"
        web.mkdir(mode=0o755)

        class Quiet(http.server.SimpleHTTPRequestHandler):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, directory=str(web), **kwargs)

            def log_message(self, *args):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Quiet)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        origin = f"http://127.0.0.1:{server.server_port}"
        key = Ed25519PrivateKey.generate()
        public = base64.b64encode(
            key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        ).decode()
        binary = b"#!/bin/sh\nprintf 'isolated installer fixture\\n'\n"
        (web / "agent").write_bytes(binary)

        def manifest(version="1.0.0-rc1", signer=key):
            data = {
                "schema_version": 1,
                "product": "commandcore-agent",
                "version": version,
                "artifacts": [
                    {
                        "platform": "linux",
                        "architecture": "x86_64",
                        "kind": "executable",
                        "url": origin + "/agent",
                        "sha256": hashlib.sha256(binary).hexdigest(),
                        "size": len(binary),
                    }
                ],
            }
            canonical = json.dumps(
                data, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ).encode()
            data["signature"] = base64.b64encode(signer.sign(canonical)).decode()
            (web / "manifest.json").write_text(json.dumps(data))

        fixture = base / "fixture-bin"
        fixture.mkdir(mode=0o755)
        ctl = fixture / "systemctl"
        ctl.write_text(
            '#!/bin/sh\ncase "$*" in *daemon-reload*) exit 1;; *) exit 0;; esac\n'
        )
        ctl.chmod(0o755)
        linger = fixture / "loginctl"
        linger.write_text('#!/bin/sh\nprintf "yes\\n"\n')
        linger.chmod(0o755)

        def home(name):
            path = base / name
            path.mkdir(mode=0o700)
            os.chown(path, 65534, 65534)
            return path

        def run(path, *extra, expected=True, namespace=False, uninstall=False):
            env = dict(
                os.environ,
                HOME=str(path),
                XDG_CONFIG_HOME=str(path / ".config"),
                XDG_DATA_HOME=str(path / ".local/share"),
                COMMANDCORE_RELEASE_PUBLIC_KEY_B64=public,
                PATH=str(fixture) + ":" + os.environ["PATH"],
            )
            if namespace:
                env.update(
                    COMMANDCORE_AGENT_SERVICE_NAME="commandcore-agent-acceptance.service",
                    COMMANDCORE_AGENT_BIN_DIR=str(path / "private-bin"),
                    COMMANDCORE_SYSTEMD_CONFIG_HOME=str(path / "service-config"),
                )

            def drop():
                os.setgroups([])
                os.setgid(65534)
                os.setuid(65534)

            command = (
                ["sh", str(root / "install/uninstall-linux.sh")]
                if uninstall
                else [
                    "sh",
                    str(installer),
                    "--manifest",
                    origin + "/manifest.json",
                    "--test-loopback",
                    "--no-enroll",
                    *extra,
                ]
            )
            result = subprocess.run(
                command,
                env=env,
                preexec_fn=drop,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            assert (result.returncode == 0) == expected, result.stderr
            return result

        try:
            manifest(signer=Ed25519PrivateKey.generate())
            wrong = home("wrong-key")
            run(wrong, "--no-service", expected=False)
            assert not (wrong / ".local/share/commandcore-agent").exists()
            manifest()
            (web / "agent").write_bytes(binary + b"tampered")
            tamper = home("tampered")
            run(tamper, "--no-service", expected=False)
            assert not (tamper / ".local/share/commandcore-agent").exists()
            (web / "agent").write_bytes(binary)
            unrelated = home("unrelated")
            unit = unrelated / ".config/systemd/user/commandcore-agent.service"
            unit.parent.mkdir(parents=True)
            unit.write_text("unrelated service\n")
            # Grant fixture ownership so refusal tests service identity, not Unix access.
            for path in [
                unit.parent.parent.parent,
                unit.parent.parent,
                unit.parent,
                unit,
            ]:
                os.chown(path, 65534, 65534)
            run(unrelated, "--no-service", expected=False)
            assert unit.read_text() == "unrelated service\n"
            installed = home("installed")
            run(installed, "--no-service")
            current = installed / ".local/share/commandcore-agent/current"
            assert current.readlink() == Path("releases/1.0.0-rc1")
            run(installed, "--no-service")  # Idempotent same-version install.
            identity = installed / ".config/commandcore/agent.json"
            identity.write_text('{"fixture":"identity-preserved"}')
            os.chown(identity, 65534, 65534)
            manifest("1.0.0-rc2")
            run(installed, "--upgrade", expected=False)  # Inject daemon-reload failure.
            assert current.readlink() == Path("releases/1.0.0-rc1")
            assert identity.read_text() == '{"fixture":"identity-preserved"}'
            manifest("1.0.0-rc.2")
            isolated = home("isolated-namespace")
            run(isolated, "--no-service", namespace=True)
            isolated_identity = isolated / ".config/commandcore/agent.json"
            isolated_identity.write_text('{"fixture":"preserved-on-uninstall"}')
            os.chown(isolated_identity, 65534, 65534)
            metadata = json.loads(
                (
                    isolated / ".local/share/commandcore-agent/installation.json"
                ).read_text()
            )
            assert metadata["service_name"] == "commandcore-agent-acceptance.service"
            assert (isolated / "private-bin/commandcore-agent").is_symlink()
            manifest("1.0.0-rc.10")
            failed = run(isolated, "--upgrade", namespace=True, expected=False)
            assert "Upgrade must be newer" not in failed.stderr
            # Remove the service failure injection before testing normal uninstall.
            ctl.write_text("#!/bin/sh\nexit 0\n")
            run(isolated, uninstall=True)
            assert not (isolated / ".local/share/commandcore-agent").exists()
            assert not (isolated / "private-bin/commandcore-agent").exists()
            assert (
                isolated_identity.read_text() == '{"fixture":"preserved-on-uninstall"}'
            )
            print(
                json.dumps(
                    {
                        "status": "PASS",
                        "checks": [
                            "wrong-signing-key",
                            "tampered-artifact",
                            "unrelated-service-preserved",
                            "signed-user-install",
                            "idempotent-reinstall",
                            "service-failure-rollback",
                            "identity-preserved",
                            "isolated-namespace",
                            "numeric-prerelease-order",
                            "uninstall-preserves-identity",
                        ],
                        "scope": "installer integrity; fixture executable and service, no enrollment claim",
                    }
                )
            )
        finally:
            server.shutdown()


if __name__ == "__main__":
    main()
