"""Credential-free edge vs OAuth diagnostic; no device control or secrets."""
from __future__ import annotations

import argparse
import json
import urllib.error
import urllib.parse
import urllib.request

MCP_PAYLOAD = json.dumps(
    {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
).encode()


def classify(status: int, challenge: bool, body: bytes) -> str:
    if status == 403 and b"error-1010" in body:
        return "cloudflare_error_1010"
    if status == 401 and challenge:
        return "oauth_challenge_present"
    if status == 401:
        return "unauthenticated_denied_no_challenge"
    if status == 200:
        return "unexpected_anonymous_success"
    return "other_response"


def probe(url: str, user_agent: str, timeout: float) -> dict:
    req = urllib.request.Request(
        url,
        data=MCP_PAYLOAD,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "User-Agent": user_agent,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            code, headers, body = (
                response.status, response.headers, response.read(2048)
            )
    except urllib.error.HTTPError as exc:
        code, headers, body = exc.code, exc.headers, exc.read(2048)
    except (urllib.error.URLError, TimeoutError, OSError):
        return {"status": None, "classification": "network_failure"}
    return {
        "status": code,
        "classification": classify(
            code, bool(headers.get("WWW-Authenticate")), body
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--origin", required=True, help="HTTPS origin only")
    parser.add_argument("--timeout", type=float, default=10)
    args = parser.parse_args()
    parts = urllib.parse.urlsplit(args.origin)
    if not (
        parts.scheme == "https"
        and parts.hostname
        and not parts.username
        and not parts.password
        and not parts.query
        and not parts.fragment
        and parts.path in ("", "/")
    ):
        parser.error("--origin must be an HTTPS origin without path or credentials")
    url = args.origin.rstrip("/") + "/mcp/core"
    for name, user_agent in (
        ("python", "Python-urllib/3"),
        ("curl-like", "curl/8.0.1"),
    ):
        result = probe(url, user_agent, args.timeout)
        print(json.dumps({"client": name, **result}, sort_keys=True))
    print(
        "User-Agent comparison alone does not identify the Cloudflare rule. "
        "Review edge security events privately."
    )


if __name__ == "__main__":
    main()
