"""Manual M1 isolation probe for two disposable real OAuth test accounts.

Tokens and disposable device IDs come only from environment variables; this
probe never prints those values, JWTs, selections, raw responses or exceptions.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable

DENIED = {
    "device_not_found",
    "permission_denied",
    "selection_not_found_or_expired",
    "insufficient_scope",
}


class ProbeFailure(Exception):
    """An acceptance prerequisite or invariant failed; details stay private."""


class RejectRedirects(urllib.request.HTTPRedirectHandler):
    """Never forward an OAuth bearer token through an HTTP redirect."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def https_origin(value: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    if not (
        parsed.scheme == "https"
        and parsed.hostname
        and not parsed.username
        and not parsed.password
        and parsed.path in ("", "/")
        and not parsed.query
        and not parsed.fragment
    ):
        raise ProbeFailure("invalid_origin")
    return value.rstrip("/")


def call_remote(origin: str, token: str, tool: str, args: dict[str, Any]) -> dict:
    """Fail closed on HTTP, Cloudflare and invalid MCP responses."""
    payload = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": tool, "arguments": args},
        }
    ).encode("utf-8")
    req = urllib.request.Request(
        origin + "/mcp/core",
        data=payload,
        headers={
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "User-Agent": "CommandCore-M1-Acceptance/1.0",
        },
        method="POST",
    )
    try:
        with urllib.request.build_opener(RejectRedirects()).open(
            req, timeout=12
        ) as response:
            if response.status != 200:
                raise ProbeFailure("unexpected_http_status")
            raw = response.read(1024 * 1024 + 1)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise ProbeFailure("transport_failed") from exc
    if len(raw) > 1024 * 1024:
        raise ProbeFailure("oversized_response")
    try:
        envelope = json.loads(raw)
        result = envelope["result"]
        if not isinstance(result, dict) or not isinstance(result["isError"], bool):
            raise ProbeFailure("invalid_tool_result")
        data = result.get("structuredContent")
        if not isinstance(data, dict):
            raise ProbeFailure("missing_structured_content")
        if result["isError"]:
            code = data.get("error")
            if not isinstance(code, str):
                raise ProbeFailure("invalid_error_code")
            return {"ok": False, "code": code}
        return {"ok": True, "data": data}
    except (ValueError, TypeError, KeyError) as exc:
        raise ProbeFailure("invalid_rpc_envelope") from exc


def success(call: Callable, token: str, tool: str, args: dict) -> dict:
    result = call(token, tool, args)
    if result.get("ok") is not True or not isinstance(result.get("data"), dict):
        raise ProbeFailure("expected_success")
    return result["data"]


def denied(call: Callable, token: str, tool: str, args: dict) -> None:
    result = call(token, tool, args)
    if result.get("ok") is not False or result.get("code") not in DENIED:
        raise ProbeFailure("expected_explicit_denial")


def validate_accounts(call: Callable, a: str, b: str, da: str, db: str) -> None:
    if not a or not b or a == b or not da or not db or da == db:
        raise ProbeFailure("invalid_two_account_fixture")
    who_a = success(call, a, "auth.whoami", {})
    who_b = success(call, b, "auth.whoami", {})
    if not (
        isinstance(who_a.get("subject"), str)
        and who_a["subject"]
        and isinstance(who_b.get("subject"), str)
        and who_b["subject"]
        and who_a["subject"] != who_b["subject"]
        and isinstance(who_a.get("issuer"), str)
        and who_a["issuer"]
        and who_a["issuer"] == who_b.get("issuer")
    ):
        raise ProbeFailure("identities_not_independent")
    for who, own, foreign in ((who_a, da, db), (who_b, db, da)):
        scopes = who.get("oauth_scopes")
        if not isinstance(scopes, list) or "commandcore:read" not in scopes:
            raise ProbeFailure("missing_read_scope")
        if "commandcore:standard" in scopes or "commandcore:full" in scopes:
            raise ProbeFailure("test_accounts_must_be_read_only")
        grants = who.get("device_grants")
        if not isinstance(grants, list):
            raise ProbeFailure("missing_grants")
        ids = {item.get("device_id") for item in grants if isinstance(item, dict)}
        if own not in ids or foreign in ids:
            raise ProbeFailure("grants_not_isolated")
    for token, own, foreign in ((a, da, db), (b, db, da)):
        listed = success(call, token, "devices.list", {}).get("devices")
        if not isinstance(listed, list):
            raise ProbeFailure("invalid_device_list")
        ids = {item.get("id") for item in listed if isinstance(item, dict)}
        if own not in ids or foreign in ids:
            raise ProbeFailure("list_not_isolated")


def run_checks(
    call: Callable, a: str, b: str, da: str, db: str
) -> list[tuple[str, bool]]:
    """A01-A06 subset; use only on disposable devices with READ_ONLY scopes."""
    outcomes = []

    def check(label: str, task: Callable) -> None:
        try:
            task()
        except (ProbeFailure, KeyError, TypeError, ValueError):
            outcomes.append((label, False))
        else:
            outcomes.append((label, True))

    check("A01_A02", lambda: validate_accounts(call, a, b, da, db))
    if not outcomes[-1][1]:
        return outcomes
    check(
        "A03",
        lambda: (
            denied(call, a, "devices.info", {"device_id": db}),
            denied(call, a, "system.info", {"device_id": db}),
        ),
    )
    check(
        "A04",
        lambda: (
            denied(call, b, "devices.info", {"device_id": da}),
            denied(call, b, "system.info", {"device_id": da}),
        ),
    )

    def selection_isolation() -> None:
        a_sel = success(call, a, "devices.select", {"device": da}).get("selection_id")
        b_sel = success(call, b, "devices.select", {"device": db}).get("selection_id")
        if not isinstance(a_sel, str) or not isinstance(b_sel, str):
            raise ProbeFailure("selection_missing")
        denied(call, a, "devices.info", {"selection_id": b_sel})
        denied(call, b, "devices.info", {"selection_id": a_sel})

    check("A05", selection_isolation)
    check(
        "A06",
        lambda: (
            denied(call, a, "shell.exec", {"device_id": da, "command": "true"}),
            denied(call, b, "shell.exec", {"device_id": db, "command": "true"}),
        ),
    )
    return outcomes


def main() -> int:
    required = (
        "COMMANDCORE_TEST_ORIGIN",
        "COMMANDCORE_TEST_A_TOKEN",
        "COMMANDCORE_TEST_B_TOKEN",
        "COMMANDCORE_TEST_A_DEVICE_ID",
        "COMMANDCORE_TEST_B_DEVICE_ID",
    )
    if any(not os.environ.get(key) for key in required):
        print(
            "NOT_RUN: disposable test origin, two OAuth tokens and device IDs required"
        )
        return 2
    try:
        origin = https_origin(os.environ["COMMANDCORE_TEST_ORIGIN"])

        def caller(token: str, tool: str, args: dict) -> dict:
            return call_remote(origin, token, tool, args)

        outcomes = run_checks(
            caller,
            os.environ["COMMANDCORE_TEST_A_TOKEN"],
            os.environ["COMMANDCORE_TEST_B_TOKEN"],
            os.environ["COMMANDCORE_TEST_A_DEVICE_ID"],
            os.environ["COMMANDCORE_TEST_B_DEVICE_ID"],
        )
    except Exception:
        # Never print an exception that could contain a bearer token or URL.
        print("FAIL: MCP transport, protocol, or unexpected probe error (redacted)")
        return 1
    for label, passed in outcomes:
        print(label, "PASS" if passed else "FAIL")
    print("Scope: A01-A06 only; NOT complete M1 release acceptance")
    return 0 if outcomes and all(passed for _, passed in outcomes) else 1


if __name__ == "__main__":
    sys.exit(main())
