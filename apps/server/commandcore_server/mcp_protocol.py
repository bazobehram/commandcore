"""Pure MCP JSON-RPC and protocol response helpers.

This module owns wire-format validation and response shaping only. It does
not authenticate principals, authorize tools, or dispatch operations.
"""

from __future__ import annotations

import json
from typing import Any

from fastapi import Request
from fastapi.responses import JSONResponse


MODERN_PROTOCOL = "2026-07-28"
LEGACY_PROTOCOLS = {"2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"}


def _rpc_result(request_id: Any, result: dict[str, Any]) -> JSONResponse:
    return JSONResponse({"jsonrpc": "2.0", "id": request_id, "result": result})


def _rpc_error(
    request_id: Any, code: int, message: str, data: Any = None, status_code: int = 400
) -> JSONResponse:
    err: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return JSONResponse(
        {"jsonrpc": "2.0", "id": request_id, "error": err}, status_code=status_code
    )


def _validate_modern(
    request: Request, body: dict[str, Any]
) -> tuple[bool, JSONResponse | None]:
    req_id = body.get("id")
    method = body.get("method")
    if request.headers.get("mcp-protocol-version") != MODERN_PROTOCOL:
        return False, _rpc_error(
            req_id,
            -32022,
            "UnsupportedProtocolVersion",
            {"supportedVersions": [MODERN_PROTOCOL]},
        )
    if request.headers.get("mcp-method") != method:
        return False, _rpc_error(
            req_id, -32020, "HeaderMismatch: Mcp-Method does not match JSON-RPC method"
        )
    params = body.get("params") if isinstance(body.get("params"), dict) else {}
    expected_name = None
    if method == "tools/call":
        expected_name = params.get("name")
    header_name = request.headers.get("mcp-name")
    if expected_name is not None and header_name != str(expected_name):
        return False, _rpc_error(
            req_id, -32020, "HeaderMismatch: Mcp-Name does not match params.name"
        )
    if expected_name is None and header_name:
        return False, _rpc_error(
            req_id, -32020, "HeaderMismatch: Mcp-Name not valid for this method"
        )
    meta = params.get("_meta") if isinstance(params.get("_meta"), dict) else None
    if (
        not meta
        or meta.get("io.modelcontextprotocol/protocolVersion") != MODERN_PROTOCOL
    ):
        return False, _rpc_error(
            req_id,
            -32602,
            "Modern MCP requests require protocolVersion in params._meta",
        )
    if "io.modelcontextprotocol/clientCapabilities" not in meta:
        return False, _rpc_error(
            req_id,
            -32602,
            "Modern MCP requests require clientCapabilities in params._meta",
        )
    return True, None


def _modernize(method: str, result: dict[str, Any]) -> dict[str, Any]:
    result = dict(result)
    result.setdefault("resultType", "complete")
    if method in {"server/discover", "tools/list"}:
        result.setdefault("ttlMs", 0)
        result.setdefault("cacheScope", "private")
    return result


def _with_server_info(
    result: dict[str, Any],
    server_version: str,
    name: str = "commandcore",
    icons: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    out = dict(result)
    meta = dict(out.get("_meta") or {})
    info: dict[str, Any] = {"name": name, "version": server_version}
    if icons:
        info["icons"] = icons
    meta.setdefault("io.modelcontextprotocol/serverInfo", info)
    out["_meta"] = meta
    return out


def _tool_result(payload: dict[str, Any], modern: bool) -> dict[str, Any]:
    payload = dict(payload)
    operation = payload.pop("_ui_operation", None)
    viewer = payload.pop("_ui_viewer", None)
    # Screenshots must be returned as MCP images, not twice as huge
    # text/structured JSON or in an activity log.
    captured = payload.get("result") or {}
    if (
        isinstance(captured, dict)
        and any(
            payload.get("summary", "").startswith(p)
            for p in ("screen.capture on ", "agents.observe on ")
        )
        and captured.get("mime_type") == "image/png"
        and isinstance(captured.get("data_base64"), str)
    ):
        image = captured["data_base64"]
        safe_payload = dict(payload)
        safe_payload["result"] = {
            key: captured.get(key)
            for key in (
                "mime_type",
                "bytes",
                "window_id",
                "title",
                "pid",
                "input_coordinate_space",
                "window_geometry",
                "conversation_id_verified",
                "agent_state",
            )
            if key in captured
        }
        answer = {
            "content": [{"type": "image", "mimeType": "image/png", "data": image}],
            "structuredContent": safe_payload,
            "isError": False,
        }
        if operation:
            answer["_meta"] = {
                "commandcore/operation": operation,
                "commandcore/viewer": viewer or {},
            }
        return _modernize("tools/call", answer) if modern else answer
    meta = dict(payload)
    screenshot = meta.pop("screenshot_base64", None)
    content: list[dict[str, Any]] = [
        {"type": "text", "text": json.dumps(meta, ensure_ascii=False, indent=2)}
    ]
    if screenshot:
        content.append({"type": "image", "mimeType": "image/png", "data": screenshot})
    result: dict[str, Any] = {
        "content": content,
        "structuredContent": meta,
        "isError": False,
    }
    if operation:
        result["_meta"] = {
            "commandcore/operation": operation,
            "commandcore/viewer": viewer or {},
        }
    return _modernize("tools/call", result) if modern else result


def _tool_error(code: str, message: str, modern: bool) -> dict[str, Any]:
    payload = {"error": code, "message": message}
    result: dict[str, Any] = {
        "content": [{"type": "text", "text": json.dumps(payload, ensure_ascii=False)}],
        "structuredContent": payload,
        "isError": True,
    }
    return _modernize("tools/call", result) if modern else result
