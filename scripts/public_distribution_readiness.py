#!/usr/bin/env python3
"""Read-only public distribution HTTP gate; never installs or trusts a release.

HTTP delivery readiness is *not* cryptographic release approval. The signing
key, manifest signature, artifact integrity, and real platform lifecycle must
be verified independently before publishing an installer to end users.
"""

from __future__ import annotations

import argparse
import base64
import http.client
import json
import ssl
from dataclasses import dataclass
from urllib.parse import urlsplit

PATHS = {
    "linux": "/install/linux",
    "manifest": "/releases/agent/manifest.json",
    "helper": "/install/linux-ready",
    "windows": "/install/windows",
}
MAX_BODY = 128 * 1024
TIMEOUT_SECONDS = 12


@dataclass(frozen=True)
class Response:
    status: int
    media_type: str
    body: bytes
    too_large: bool = False


def validate_origin(origin: str) -> tuple[str, int]:
    parsed = urlsplit(origin)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("A bare HTTPS origin with no credentials is required")
    try:
        port = parsed.port or 443
    except ValueError as error:
        raise ValueError("Invalid HTTPS port") from error
    return parsed.hostname, port


def request(origin: str, path: str) -> Response:
    """Fetch only fixed same-origin paths, without redirect following."""
    host, port = validate_origin(origin)
    connection = http.client.HTTPSConnection(
        host, port=port, timeout=TIMEOUT_SECONDS, context=ssl.create_default_context()
    )
    try:
        connection.request(
            "GET",
            path,
            headers={
                "User-Agent": "CommandCore-Distribution-Readiness/1",
                "Accept": "application/json, text/plain, text/x-shellscript, */*",
            },
        )
        result = connection.getresponse()
        media_type = result.getheader("Content-Type", "").split(";", 1)[0].lower()
        data = result.read(MAX_BODY + 1)
        return Response(
            status=result.status,
            media_type=media_type,
            body=data[:MAX_BODY],
            too_large=len(data) > MAX_BODY,
        )
    finally:
        connection.close()


def _script_status(response: Response) -> str:
    if response.status != 200:
        if response.status in (404, 503):
            return "unpublished"
        return "http_failure"
    if response.too_large:
        return "unexpected_payload"
    if response.media_type not in (
        "text/plain",
        "text/x-sh",
        "text/x-shellscript",
        "application/x-sh",
        "application/octet-stream",
    ):
        return "unexpected_payload"
    if not response.body.startswith(b"#!"):
        return "unexpected_payload"
    return "http_content_present"


def _manifest_status(response: Response) -> str:
    if response.status != 200:
        return "unpublished" if response.status == 404 else "http_failure"
    if response.too_large or response.media_type != "application/json":
        return "unexpected_payload"
    try:
        manifest = json.loads(response.body)
        signature = base64.b64decode(manifest["signature"], validate=True)
        if (
            manifest.get("schema_version") != 1
            or manifest.get("product") != "commandcore-agent"
            or not isinstance(manifest.get("artifacts"), list)
            or not manifest["artifacts"]
            or len(signature) != 64
        ):
            return "unexpected_payload"
        if not any(
            isinstance(item, dict)
            and item.get("platform") == "linux"
            and item.get("architecture") == "x86_64"
            for item in manifest["artifacts"]
        ):
            return "unexpected_payload"
    except (ValueError, KeyError, TypeError, AttributeError, UnicodeDecodeError):
        return "unexpected_payload"
    return "http_content_present_unverified_signature"


def assess(responses: dict[str, Response], require_helper: bool = False) -> tuple[dict[str, str], bool]:
    linux = _script_status(responses["linux"])
    manifest = _manifest_status(responses["manifest"])
    helper = _script_status(responses["helper"])
    windows = responses["windows"]
    if windows.status == 404:
        windows_state = "preview_unpublished"
    elif windows.status == 200:
        windows_state = "preview_http_present_not_approved"
    else:
        windows_state = "unexpected_http_status"

    statuses = {
        "linux_installer": linux,
        "signed_manifest": manifest,
        "linux_helper": helper,
        "windows_preview": windows_state,
    }
    good = linux == "http_content_present" and manifest == "http_content_present_unverified_signature"
    if require_helper:
        good = good and helper == "http_content_present"
    return statuses, good


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--origin", default="https://commandcore.app")
    parser.add_argument(
        "--require-helper",
        action="store_true",
        help="Require optional one-command Linux helper onboarding HTTP endpoint",
    )
    args = parser.parse_args()
    try:
        validate_origin(args.origin)
        responses = {key: request(args.origin, path) for key, path in PATHS.items()}
    except (ValueError, OSError, ssl.SSLError, http.client.HTTPException) as error:
        # Do not print URLs, response content, tokens, or raw network exceptions.
        print("PUBLIC_DISTRIBUTION_TRANSPORT=failed")
        print("TRANSPORT_ERROR_TYPE=" + type(error).__name__)
        return 2
    statuses, ready = assess(responses, require_helper=args.require_helper)
    for key, value in statuses.items():
        print(key.upper() + "=" + value)
    print("HTTP_DELIVERY_READY=" + ("true" if ready else "false"))
    print("CRYPTOGRAPHIC_RELEASE_APPROVAL=NOT_VERIFIED")
    print("AGENT_INSTALLER_LIFECYCLE=NOT_VERIFIED")
    print("WINDOWS_SUPPORT=PREVIEW")
    return 0 if ready else 1


if __name__ == "__main__":
    raise SystemExit(main())
