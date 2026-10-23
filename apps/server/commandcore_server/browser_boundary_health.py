"""Local-only proxy policy and control-relay health, never external browsing."""

from __future__ import annotations

import argparse
import json
import socket
from urllib.request import ProxyHandler, build_opener

from .browser_egress import POLICY_VERSION, _normalize_hosts


def check(relay_host: str, allow_hosts: str) -> None:
    opener = build_opener(ProxyHandler({}))
    with opener.open(
        "http://127.0.0.1:8080/_commandcore/policy", timeout=2
    ) as response:
        if response.status != 200:
            raise ValueError("boundary policy unavailable")
        data = json.loads(response.read(4097))
    if data.get("policy") != POLICY_VERSION or tuple(
        data.get("allow_hosts", ())
    ) != _normalize_hosts(allow_hosts):
        raise ValueError("boundary policy mismatch")
    # Relay binds the private control interface, not loopback in production.
    with socket.create_connection((relay_host, 3000), timeout=2):
        pass


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--relay-host", required=True)
    p.add_argument("--allow-hosts", required=True)
    args = p.parse_args()
    try:
        check(args.relay_host, args.allow_hosts)
    except (OSError, ValueError):
        p.exit(1, "Browser boundary health unavailable\n")


if __name__ == "__main__":
    main()
