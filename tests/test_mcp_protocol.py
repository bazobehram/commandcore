from __future__ import annotations

import json

import pytest
from commandcore_server.mcp_protocol import (
    LEGACY_PROTOCOLS,
    MODERN_PROTOCOL,
    _modernize,
    _rpc_error,
    _rpc_result,
    _tool_error,
    _tool_result,
    _validate_modern,
    _with_server_info,
)
from starlette.requests import Request


def _request(headers: dict[str, str]) -> Request:
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/mcp",
            "headers": [
                (key.lower().encode(), value.encode()) for key, value in headers.items()
            ],
        }
    )


def _modern_headers(method: str, *, name: str | None = None) -> dict[str, str]:
    headers = {
        "mcp-protocol-version": MODERN_PROTOCOL,
        "mcp-method": method,
    }
    if name is not None:
        headers["mcp-name"] = name
    return headers


def _modern_body(
    method: str, *, name: str | None = None, meta: dict | None = None
) -> dict:
    params = {
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": MODERN_PROTOCOL,
            "io.modelcontextprotocol/clientCapabilities": {},
        }
    }
    if meta is not None:
        params["_meta"] = meta
    if name is not None:
        params["name"] = name
    return {"jsonrpc": "2.0", "id": "request-1", "method": method, "params": params}


def _error_body(response):
    return json.loads(response.body)["error"]


def test_rpc_result_and_error_preserve_jsonrpc_envelopes_and_http_status():
    result = _rpc_result("request-1", {"ready": True})
    assert result.status_code == 200
    assert json.loads(result.body) == {
        "jsonrpc": "2.0",
        "id": "request-1",
        "result": {"ready": True},
    }

    error = _rpc_error("request-2", -32602, "Invalid params", {"field": "name"}, 422)
    assert error.status_code == 422
    assert json.loads(error.body) == {
        "jsonrpc": "2.0",
        "id": "request-2",
        "error": {
            "code": -32602,
            "message": "Invalid params",
            "data": {"field": "name"},
        },
    }


@pytest.mark.parametrize(
    ("headers", "body", "message"),
    [
        ({}, _modern_body("tools/list"), "UnsupportedProtocolVersion"),
        (
            {**_modern_headers("tools/list"), "mcp-method": "resources/list"},
            _modern_body("tools/list"),
            "HeaderMismatch: Mcp-Method",
        ),
        (
            _modern_headers("tools/call", name="system.info"),
            _modern_body("tools/call", name="system.exec"),
            "HeaderMismatch: Mcp-Name does not match",
        ),
        (
            _modern_headers("tools/list", name="system.info"),
            _modern_body("tools/list"),
            "HeaderMismatch: Mcp-Name not valid",
        ),
        (
            _modern_headers("tools/list"),
            _modern_body(
                "tools/list",
                meta={"io.modelcontextprotocol/protocolVersion": MODERN_PROTOCOL},
            ),
            "require clientCapabilities",
        ),
        (
            _modern_headers("tools/list"),
            _modern_body(
                "tools/list", meta={"io.modelcontextprotocol/clientCapabilities": {}}
            ),
            "require protocolVersion",
        ),
    ],
)
def test_modern_request_validation_rejects_header_and_metadata_mismatches(
    headers, body, message
):
    valid, error = _validate_modern(_request(headers), body)
    assert valid is False
    assert error is not None
    assert message in _error_body(error)["message"]


def test_modern_request_validation_accepts_matching_call_contract():
    body = _modern_body("tools/call", name="system.info")
    valid, error = _validate_modern(
        _request(_modern_headers("tools/call", name="system.info")), body
    )
    assert valid is True
    assert error is None


def test_protocol_versions_and_modern_result_defaults_remain_stable():
    assert LEGACY_PROTOCOLS == {
        "2025-11-25",
        "2025-06-18",
        "2025-03-26",
        "2024-11-05",
    }
    original = {"tools": []}
    modern = _modernize("tools/list", original)
    assert original == {"tools": []}
    assert modern == {
        "tools": [],
        "resultType": "complete",
        "ttlMs": 0,
        "cacheScope": "private",
    }
    assert (
        _modernize("tools/call", {"resultType": "partial"})["resultType"] == "partial"
    )
    assert _modernize("tools/list", {"ttlMs": 50, "cacheScope": "public"}) == {
        "ttlMs": 50,
        "cacheScope": "public",
        "resultType": "complete",
    }


def test_server_info_is_added_without_overwriting_existing_metadata():
    icons = [{"src": "https://example.test/icon.png", "mimeType": "image/png"}]
    result = _with_server_info({"resultType": "complete"}, "1.2.3", icons=icons)
    assert result["_meta"]["io.modelcontextprotocol/serverInfo"] == {
        "name": "commandcore",
        "version": "1.2.3",
        "icons": icons,
    }
    original = {
        "_meta": {
            "existing": True,
            "io.modelcontextprotocol/serverInfo": {"name": "custom"},
        }
    }
    preserved = _with_server_info(original, "2.0.0")
    assert preserved["_meta"] == {
        "existing": True,
        "io.modelcontextprotocol/serverInfo": {"name": "custom"},
    }
    assert original["_meta"]["existing"] is True


def test_tool_result_preserves_text_structured_and_operation_metadata():
    payload = {
        "summary": "system.info on fixture: ok",
        "result": {"status": "ok"},
        "screenshot_base64": "aGVsbG8=",
        "_ui_operation": {"tool": "system.info", "operation_id": "op-1"},
        "_ui_viewer": {"url": "https://commandcore.example/view"},
    }
    result = _tool_result(payload, modern=True)
    assert result["resultType"] == "complete"
    assert result["_meta"]["commandcore/operation"]["operation_id"] == "op-1"
    assert result["_meta"]["commandcore/viewer"]["url"].startswith("https://")
    assert result["structuredContent"]["summary"] == "system.info on fixture: ok"
    assert "screenshot_base64" not in result["structuredContent"]
    assert result["content"][0]["type"] == "text"
    assert result["content"][1] == {
        "type": "image",
        "mimeType": "image/png",
        "data": "aGVsbG8=",
    }
    assert payload["_ui_operation"]["operation_id"] == "op-1"
    assert payload["screenshot_base64"] == "aGVsbG8="


def test_screenshot_result_is_emitted_as_image_and_not_duplicated_in_structured_data():
    payload = {
        "summary": "screen.capture on fixture: ok",
        "result": {
            "mime_type": "image/png",
            "data_base64": "c25hcHNob3Q=",
            "bytes": 8,
            "window_id": "window-1",
        },
        "_ui_operation": {"tool": "screen.capture"},
    }
    result = _tool_result(payload, modern=False)
    assert result["content"] == [
        {"type": "image", "mimeType": "image/png", "data": "c25hcHNob3Q="}
    ]
    assert result["structuredContent"]["result"] == {
        "mime_type": "image/png",
        "bytes": 8,
        "window_id": "window-1",
    }
    assert result["_meta"]["commandcore/operation"]["tool"] == "screen.capture"


def test_tool_error_keeps_legacy_and_modern_error_shapes():
    legacy = _tool_error("permission_denied", "Not allowed", modern=False)
    assert legacy["isError"] is True
    assert legacy["structuredContent"] == {
        "error": "permission_denied",
        "message": "Not allowed",
    }
    assert json.loads(legacy["content"][0]["text"]) == legacy["structuredContent"]

    modern = _tool_error("permission_denied", "Not allowed", modern=True)
    assert modern["resultType"] == "complete"
    assert modern["isError"] is True
    assert modern["structuredContent"] == legacy["structuredContent"]
