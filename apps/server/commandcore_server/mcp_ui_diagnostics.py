"""Opt-in, credential-free MCP UI asset ingestion diagnostics.

This observes existing authenticated resource handling; it never changes
resource visibility, authorization or transport validation.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from pathlib import Path

LOGGER = logging.getLogger("commandcore.mcp.ui_resources")


def record_ui_resource_request(
    *,
    method: str,
    uri: object,
    assets: dict[str, tuple],
    resolve_asset,
    modern: bool,
    method_header_matches: bool,
) -> None:
    if os.environ.get("COMMANDCORE_MCP_UI_DIAGNOSTICS") != "true":
        return
    if not isinstance(method, str) or method not in {
        "resources/list",
        "resources/read",
    }:
        return
    # Never echo unknown URIs, request bodies, identities, headers or paths.
    spec = assets.get(uri) if isinstance(uri, str) else None
    record = {
        "event": "mcp_ui_resource_request",
        "method": method,
        "resource": uri if spec else None,
        "registered": spec is not None,
        "modern": bool(modern),
        "method_header_matches": bool(method_header_matches),
    }
    if spec:
        try:
            content = Path(resolve_asset(spec[2])).read_bytes()
            record["html_sha256"] = hashlib.sha256(content).hexdigest()
            record["asset_readable"] = True
        except OSError:
            record["asset_readable"] = False
    LOGGER.warning("%s", json.dumps(record, sort_keys=True))
