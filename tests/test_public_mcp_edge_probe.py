"""Regression tests for the credential-free MCP edge diagnostic."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/public_mcp_edge_probe.py"
spec = importlib.util.spec_from_file_location("public_mcp_edge_probe", SCRIPT)
assert spec is not None and spec.loader is not None
probe_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe_module)


@pytest.mark.parametrize(
    ("status", "challenge", "body", "expected"),
    [
        (403, False, b'{"type":"error-1010"}', "cloudflare_error_1010"),
        (401, True, b"", "oauth_challenge_present"),
        (401, False, b"", "unauthenticated_denied_no_challenge"),
        (200, False, b"{}", "unexpected_anonymous_success"),
        (403, False, b"denied", "other_response"),
        (404, False, b"", "other_response"),
    ],
)
def test_classify_mcp_responses(status, challenge, body, expected):
    assert probe_module.classify(status, challenge, body) == expected


def test_diagnostic_request_never_sends_credentials(monkeypatch):
    class FakeResponse:
        status = 401
        headers = {"WWW-Authenticate": 'Bearer realm="test"'}

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def read(self, _limit):
            return b""

    def fake_urlopen(request, timeout):
        assert timeout == 2
        assert request.get_method() == "POST"
        assert request.get_header("Authorization") is None
        assert request.get_header("Cookie") is None
        assert b'"method": "tools/list"' in request.data
        return FakeResponse()

    monkeypatch.setattr(probe_module.urllib.request, "urlopen", fake_urlopen)
    assert probe_module.probe("https://example.com/mcp/core", "curl/8.0.1", 2) == {
        "status": 401,
        "classification": "oauth_challenge_present",
    }


def test_diagnostic_handles_network_failure_without_credentials(monkeypatch):
    def fail_network(_request, timeout):
        assert timeout == 2
        raise probe_module.urllib.error.URLError("offline")

    monkeypatch.setattr(probe_module.urllib.request, "urlopen", fail_network)
    assert probe_module.probe("https://example.com/mcp/core", "Python-urllib/3", 2) == {
        "status": None,
        "classification": "network_failure",
    }
