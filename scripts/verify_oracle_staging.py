#!/usr/bin/env python3
"""Static Oracle Free staging configuration gate; never deploys resources."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile


def validate(compose: Path) -> None:
    if not compose.is_file():
        raise ValueError("Oracle Compose file missing")
    with tempfile.TemporaryDirectory(prefix="commandcore-oracle-audit-") as directory:
        tmp = Path(directory)
        (tmp / "compose.yml").write_bytes(compose.read_bytes())
        (tmp / ".env.oracle").touch(mode=0o600)
        env = dict(os.environ)
        env["COMMANDCORE_IMAGE"] = "ghcr.io/example/commandcore@sha256:" + "a" * 64
        result = subprocess.run(
            ["docker", "compose", "-f", str(tmp / "compose.yml"), "config", "--format", "json"],
            check=True, text=True, capture_output=True, env=env,
        )
        config = json.loads(result.stdout)
    services = config.get("services", {})
    if len(services) != 1 or "commandcore" not in services:
        raise ValueError("Unexpected Oracle services")
    service = services["commandcore"]
    if "@sha256:" not in service.get("image", ""):
        raise ValueError("Oracle image must be immutable")
    if not service.get("healthcheck"):
        raise ValueError("Oracle health check is mandatory")
    if not service.get("volumes"):
        raise ValueError("Persistent volume is mandatory")
    if any(port.get("host_ip") != "127.0.0.1" for port in service.get("ports", [])):
        raise ValueError("Public port exposure forbidden before TLS proxy review")
    if not service.get("ports"):
        raise ValueError("Loopback port mapping is required")
    if "env_file:" not in compose.read_text() or ".env.oracle" not in compose.read_text():
        raise ValueError("Isolated environment file required")
    print("ORACLE_STAGING_STATIC_PASS")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("compose", type=Path)
    args = parser.parse_args()
    validate(args.compose)
