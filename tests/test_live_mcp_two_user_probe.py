"""Offline, credential-free tests of the M1 live OAuth acceptance probe."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

SOURCE = Path(__file__).resolve().parents[1] / "scripts/live_mcp_two_user_probe.py"
spec = importlib.util.spec_from_file_location("live_mcp_two_user_probe", SOURCE)
assert spec is not None and spec.loader is not None
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


def fake_client(*, leak: bool = False, unsafe_shell: bool = False):
    def call(token, name, args):
        is_a = token == "token-a"
        own = "device-a" if is_a else "device-b"
        foreign = "device-b" if is_a else "device-a"
        if name == "auth.whoami":
            return {
                "ok": True,
                "data": {
                    "subject": "subject-a" if is_a else "subject-b",
                    "issuer": "https://example.test/",
                    "oauth_scopes": ["commandcore:read"],
                    "device_grants": [{"device_id": own}],
                },
            }
        if name == "devices.list":
            return {"ok": True, "data": {"devices": [{"id": own}]}}
        if name == "devices.select":
            if args["device"] != own:
                return {"ok": False, "code": "device_not_found"}
            return {
                "ok": True,
                "data": {"selection_id": "sel-a" if is_a else "sel-b"},
            }
        if name == "shell.exec":
            if unsafe_shell:
                return {"ok": True, "data": {"stdout": ""}}
            return {"ok": False, "code": "insufficient_scope"}
        if name in {"devices.info", "system.info"}:
            if args.get("device_id") == foreign and leak:
                return {"ok": True, "data": {"device": {"id": foreign}}}
            foreign_selection = "sel-b" if is_a else "sel-a"
            if (
                args.get("device_id") == foreign
                or args.get("selection_id") == foreign_selection
            ):
                return {"ok": False, "code": "device_not_found"}
            return {"ok": True, "data": {"device": {"id": own}}}
        raise AssertionError("unknown test tool")

    return call


def test_expected_two_account_isolation():
    assert probe.run_checks(
        fake_client(), "token-a", "token-b", "device-a", "device-b"
    ) == [
        ("A01_A02", True),
        ("A03", True),
        ("A04", True),
        ("A05", True),
        ("A06", True),
    ]


def test_cross_user_device_visibility_is_a_failure():
    results = probe.run_checks(
        fake_client(leak=True), "token-a", "token-b", "device-a", "device-b"
    )
    assert ("A03", False) in results
    assert ("A04", False) in results


def test_read_only_shell_regression_is_detected():
    results = probe.run_checks(
        fake_client(unsafe_shell=True), "token-a", "token-b", "device-a", "device-b"
    )
    assert ("A06", False) in results


def test_identical_tokens_fail_without_device_calls():
    assert probe.run_checks(
        fake_client(), "token-a", "token-a", "device-a", "device-b"
    ) == [("A01_A02", False)]


@pytest.mark.parametrize(
    "origin",
    [
        "http://example.test",
        "https://user:pass@example.test",
        "https://example.test/path",
        "https://example.test?q=x",
    ],
)
def test_unsafe_origins_are_rejected(origin):
    with pytest.raises(probe.ProbeFailure):
        probe.https_origin(origin)


def test_https_origin_is_normalized():
    assert probe.https_origin("https://example.test/") == "https://example.test"


def test_remote_request_identifies_client_without_logging_token(monkeypatch, capsys):
    import json

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, _limit):
            return json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {
                        "isError": False,
                        "structuredContent": {"ready": True},
                    },
                }
            ).encode()

    def fake_urlopen(request, timeout):
        assert timeout == 12
        assert request.get_header("User-agent") == "CommandCore-M1-Acceptance/1.0"
        assert request.get_header("Authorization") == "Bearer fixture-token"
        return Response()

    class FakeOpener:
        def open(self, request, timeout):
            return fake_urlopen(request, timeout)

    def fake_build_opener(handler):
        assert isinstance(handler, probe.RejectRedirects)
        return FakeOpener()

    monkeypatch.setattr(probe.urllib.request, "build_opener", fake_build_opener)
    result = probe.call_remote(
        "https://example.test", "fixture-token", "auth.whoami", {}
    )
    assert result == {"ok": True, "data": {"ready": True}}
    assert "fixture-token" not in capsys.readouterr().out


def test_redirects_are_rejected_instead_of_forwarding_bearer():
    handler = probe.RejectRedirects()
    assert (
        handler.redirect_request(
            None, None, 302, "Found", {}, "https://other.example/"
        )
        is None
    )


def test_denial_code_must_match_the_security_boundary():
    def scope_only(_token, _tool, _args):
        return {"ok": False, "code": "insufficient_scope"}
    with pytest.raises(probe.ProbeFailure):
        probe.denied(
            scope_only, "test-token", "devices.info", {}, probe.FOREIGN_DENIED
        )

    def missing_device(_token, _tool, _args):
        return {"ok": False, "code": "device_not_found"}
    with pytest.raises(probe.ProbeFailure):
        probe.denied(
            missing_device, "test-token", "shell.exec", {}, probe.SCOPE_DENIED
        )
