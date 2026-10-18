#!/usr/bin/env python3
"""Read-only post-deployment health and local MCP contract verification."""

from __future__ import annotations
import argparse
import json
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def verify(url: str, expected: str, timeout: float = 5.0) -> dict:
    with urllib.request.urlopen(url, timeout=timeout) as response:
        data = json.load(response)
    if not isinstance(data, dict) or data.get("status") != "ok":
        raise ValueError("Unhealthy or malformed server response")
    if data.get("version") != expected:
        raise ValueError(
            f"Version mismatch: expected {expected}, received {data.get('version')!r}"
        )
    return {"status": "pass", "version": expected}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--health-url", default="http://127.0.0.1:8787/healthz")
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--output", help="Optional JSON evidence output file")
    args = parser.parse_args()
    evidence = {
        "health_url": args.health_url,
        "expected_version": args.expected_version,
    }
    try:
        gate = subprocess.run(
            [sys.executable, str(ROOT / "scripts/mcp_release_gate.py")],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=15,
        )
        if gate.returncode:
            raise ValueError("MCP tool contract gate failed: " + gate.stdout.strip())
        evidence["contract"] = gate.stdout.strip()
        evidence.update(verify(args.health_url, args.expected_version))
    except (
        OSError,
        ValueError,
        urllib.error.URLError,
        json.JSONDecodeError,
        subprocess.TimeoutExpired,
    ) as exc:
        evidence["status"] = "fail"
        evidence["error"] = str(exc)
    if args.output:
        Path(args.output).write_text(json.dumps(evidence, indent=2) + "\n")
    print(json.dumps(evidence, indent=2))
    return 0 if evidence["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
