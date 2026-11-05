"""Read-only live OAuth discovery acceptance for a public CommandCore deployment.

This command never authenticates, requests tokens, or modifies server state.
Run after deploying a reviewed build, not as an unconditional PR CI gate.
"""

from __future__ import annotations

import argparse
import json
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

EXPECTED_SCOPES = ("commandcore:read", "commandcore:standard", "commandcore:full")


def verify_discovery(base_url: str, *, timeout: float = 10) -> dict[str, object]:
    parsed = urlsplit(base_url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in ("", "/")
    ):
        raise ValueError("Base URL must be an HTTPS origin without credentials or path")

    origin = base_url.rstrip("/")
    endpoint = origin + "/.well-known/oauth-protected-resource/mcp"
    # No Authorization header; this is public resource metadata only.
    request = Request(
        endpoint,
        headers={
            "Accept": "application/json",
            "User-Agent": "CommandCore-Readiness/1.0",
        },
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            if response.url != endpoint:
                raise ValueError("OAuth metadata redirected unexpectedly")
            if response.status != 200:
                raise ValueError(f"OAuth metadata HTTP {response.status}")
            body = response.read(8193)
    except (HTTPError, URLError) as exc:
        raise ValueError(f"OAuth metadata unreachable: {exc}") from exc

    if len(body) > 8192:
        raise ValueError("OAuth metadata response exceeds size limit")
    try:
        metadata = json.loads(body)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid OAuth metadata JSON") from exc
    if not isinstance(metadata, dict):
        raise TypeError("OAuth metadata must be an object")
    if metadata.get("resource") != origin + "/mcp":
        raise ValueError("OAuth resource identifier does not match public MCP origin")
    providers = metadata.get("authorization_servers")
    if (
        not isinstance(providers, list)
        or not providers
        or any(
            not isinstance(item, str)
            or urlsplit(item).scheme != "https"
            or not urlsplit(item).hostname
            for item in providers
        )
    ):
        raise ValueError("OAuth authorization_servers must contain HTTPS issuers")
    scopes = metadata.get("scopes_supported")
    if scopes != list(EXPECTED_SCOPES):
        raise ValueError(
            "Unexpected public OAuth scopes; expected read, standard, full only"
        )
    if metadata.get("bearer_methods_supported") != ["header"]:
        raise ValueError("Unexpected OAuth bearer transport")
    return {
        "resource": metadata["resource"],
        "scopes": scopes,
        "authorization_server_count": len(providers),
        "status": "PASS",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "base_url", help="Public HTTPS origin, e.g. https://example.org"
    )
    args = parser.parse_args()
    try:
        result = verify_discovery(args.base_url)
    except (ValueError, TypeError) as exc:
        print(json.dumps({"status": "FAIL", "reason": str(exc)}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
