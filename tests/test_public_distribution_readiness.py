"""Offline coverage for the read-only public distribution HTTP readiness gate."""

from __future__ import annotations

import base64
import importlib.util
import json
from pathlib import Path

import pytest

MODULE_PATH = (
    Path(__file__).resolve().parents[1] / "scripts" / "public_distribution_readiness.py"
)
spec = importlib.util.spec_from_file_location("public_distribution_readiness", MODULE_PATH)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
import sys

sys.modules[spec.name] = module
spec.loader.exec_module(module)

Response = module.Response


def release_manifest() -> bytes:
    return json.dumps(
        {
            "schema_version": 1,
            "product": "commandcore-agent",
            "version": "0.9.0-rc7",
            "signature": base64.b64encode(b"x" * 64).decode("ascii"),
            "artifacts": [
                {
                    "platform": "linux",
                    "architecture": "x86_64",
                    "sha256": "0" * 64,
                }
            ],
        }
    ).encode()


def responses() -> dict[str, Response]:
    return {
        "linux": Response(200, "text/plain", b"#!/bin/sh\necho test\n"),
        "manifest": Response(200, "application/json", release_manifest()),
        "helper": Response(503, "application/json", b""),
        "windows": Response(404, "application/json", b""),
    }


def test_public_linux_http_ready_is_not_release_approval() -> None:
    statuses, ready = module.assess(responses())
    assert ready
    assert statuses == {
        "linux_installer": "http_content_present",
        "signed_manifest": "http_content_present_unverified_signature",
        "linux_helper": "unpublished",
        "windows_preview": "preview_unpublished",
    }


def test_require_helper_fails_closed() -> None:
    statuses, ready = module.assess(responses(), require_helper=True)
    assert not ready
    assert statuses["linux_helper"] == "unpublished"


def test_missing_both_public_feed_files_fails() -> None:
    r = responses()
    r["linux"] = Response(404, "application/json", b"")
    r["manifest"] = Response(404, "application/json", b"")
    statuses, ready = module.assess(r)
    assert not ready
    assert statuses["linux_installer"] == "unpublished"
    assert statuses["signed_manifest"] == "unpublished"


@pytest.mark.parametrize(
    ("response", "expected"),
    [
        (Response(301, "text/plain", b"#!test"), "http_failure"),
        (Response(200, "text/html", b"#!/bin/sh"), "unexpected_payload"),
        (Response(200, "text/plain", b"<html/>"), "unexpected_payload"),
        (Response(200, "text/plain", b"#!/bin/sh", too_large=True), "unexpected_payload"),
    ],
)
def test_unexpected_linux_endpoint_is_rejected(
    response: Response, expected: str
) -> None:
    r = responses()
    r["linux"] = response
    statuses, ready = module.assess(r)
    assert not ready
    assert statuses["linux_installer"] == expected


@pytest.mark.parametrize(
    "response",
    [
        Response(302, "application/json", release_manifest()),
        Response(200, "text/html", release_manifest()),
        Response(200, "application/json", b"not JSON"),
        Response(200, "application/json", b"{}"),
        Response(200, "application/json", release_manifest(), too_large=True),
    ],
)
def test_manifest_must_be_structurally_plausible(response: Response) -> None:
    r = responses()
    r["manifest"] = response
    statuses, ready = module.assess(r)
    assert not ready
    assert statuses["signed_manifest"] != "http_content_present_unverified_signature"


def test_manifest_signature_is_not_verified_by_http_gate() -> None:
    # 64 arbitrary bytes satisfy structural presence, NOT the Ed25519 trust check.
    statuses, ready = module.assess(responses())
    assert ready
    assert statuses["signed_manifest"] == "http_content_present_unverified_signature"


def test_windows_200_does_not_claim_windows_support() -> None:
    r = responses()
    r["windows"] = Response(200, "text/plain", b"#!/bin/sh")
    statuses, ready = module.assess(r)
    assert ready
    assert statuses["windows_preview"] == "preview_http_present_not_approved"


@pytest.mark.parametrize(
    "origin",
    [
        "http://commandcore.example.org",
        "https://operator:password@commandcore.example.org",
        "https://commandcore.example.org/private",
        "https://commandcore.example.org?token=test",
        "https://commandcore.example.org#fragment",
        "https://commandcore.example.org:invalid",
    ],
)
def test_origin_must_be_bare_authenticated_https(origin: str) -> None:
    with pytest.raises(ValueError):
        module.validate_origin(origin)


def test_valid_https_origin() -> None:
    assert module.validate_origin("https://commandcore.example.org") == (
        "commandcore.example.org",
        443,
    )
    assert module.validate_origin("https://commandcore.example.org:8443/") == (
        "commandcore.example.org",
        8443,
    )
