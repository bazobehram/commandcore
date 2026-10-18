from __future__ import annotations
import importlib.util
from pathlib import Path
from unittest.mock import patch
import io


def verifier():
    path = Path(__file__).resolve().parents[1] / "scripts/verify_mcp_release.py"
    spec = importlib.util.spec_from_file_location("verify_mcp_release", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_version_match():
    with patch(
        "urllib.request.urlopen",
        return_value=io.BytesIO(b'{"status":"ok","version":"1.2"}'),
    ):
        assert verifier().verify("http://localhost/healthz", "1.2")["status"] == "pass"


def test_version_mismatch_fails_closed():
    with patch(
        "urllib.request.urlopen",
        return_value=io.BytesIO(b'{"status":"ok","version":"1.2"}'),
    ):
        try:
            verifier().verify("http://localhost/healthz", "2.0")
        except ValueError as exc:
            assert "Version mismatch" in str(exc)
        else:
            raise AssertionError("Expected version mismatch")


def test_unhealthy_fails_closed():
    with patch(
        "urllib.request.urlopen",
        return_value=io.BytesIO(b'{"status":"fail","version":"1.2"}'),
    ):
        try:
            verifier().verify("http://localhost/healthz", "1.2")
        except ValueError as exc:
            assert "Unhealthy" in str(exc)
        else:
            raise AssertionError("Expected unhealthy failure")
