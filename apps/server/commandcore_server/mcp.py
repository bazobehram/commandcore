from __future__ import annotations

import json
import asyncio
from typing import Any, Callable

from fastapi import Request
from fastapi.responses import JSONResponse, StreamingResponse

from .metrics import Metrics
from .models import Principal
from .tools import TOOL_DEFINITIONS, ToolError, ToolService
from .web_assets import web_asset

BROWSER_WIDGET_URI = "ui://commandcore/browser-view-v1.html"
BROWSER_WIDGET_MIME = "text/html;profile=mcp-app"
ACTIVITY_UI_URI = "ui://commandcore/activity-view-v1.html"
ACTIVITY_UI_MIME = "text/html;profile=mcp-app"
COMMANDCORE_UI_URI = "ui://commandcore/live-views-v1.html"
COMMANDCORE_UI_MIME = "text/html;profile=mcp-app"

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


def _client_id(params: dict[str, Any]) -> str:
    meta = params.get("_meta") if isinstance(params.get("_meta"), dict) else {}
    info = (
        meta.get("io.modelcontextprotocol/clientInfo")
        if isinstance(meta, dict)
        else None
    )
    if isinstance(info, dict):
        name = str(info.get("name", "unknown"))
        version = str(info.get("version", "unknown"))
        return f"{name}/{version}"
    return "unknown"


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
    return _modernize("tools/call", result) if modern else result


def _tool_error(code: str, message: str, modern: bool) -> dict[str, Any]:
    payload = {"error": code, "message": message}
    result: dict[str, Any] = {
        "content": [{"type": "text", "text": json.dumps(payload, ensure_ascii=False)}],
        "structuredContent": payload,
        "isError": True,
    }
    return _modernize("tools/call", result) if modern else result


class MCPHandler:
    def __init__(
        self,
        tools: ToolService,
        metrics: Metrics,
        server_version: str,
        scope_challenge: Callable[[str], str] | None = None,
        definitions: list[dict[str, Any]] | None = None,
        name: str = "commandcore",
        icons: list[dict[str, Any]] | None = None,
    ):
        self.tools = tools
        self.metrics = metrics
        self.server_version = server_version
        self.scope_challenge = scope_challenge
        raw_definitions = TOOL_DEFINITIONS if definitions is None else definitions
        self.ui_specs = {
            "browser.watch": (
                BROWSER_WIDGET_URI,
                BROWSER_WIDGET_MIME,
                "browser-widget.html",
                "CommandCore Live Browser",
            ),
            "activity.watch": (
                ACTIVITY_UI_URI,
                ACTIVITY_UI_MIME,
                "activity-widget.html",
                "CommandCore Live Activity",
            ),
            "commandcore.watch": (
                COMMANDCORE_UI_URI,
                COMMANDCORE_UI_MIME,
                "commandcore-widget.html",
                "CommandCore Live Views",
            ),
        }
        self.definitions = []
        self.ui_resources = {}
        for source in raw_definitions:
            entry = dict(source)
            spec = self.ui_specs.get(entry["name"])
            if spec:
                uri, mime, asset, title = spec
                meta = dict(entry.get("_meta") or {})
                meta["ui"] = {"resourceUri": uri}
                meta["openai/outputTemplate"] = uri
                meta["openai/widgetAccessible"] = True
                entry["_meta"] = meta
                self.ui_resources[uri] = spec
            self.definitions.append(entry)
        self.browser_widget_available = BROWSER_WIDGET_URI in self.ui_resources
        self.activity_widget_available = ACTIVITY_UI_URI in self.ui_resources
        self.name = name
        self.icons = icons

    async def handle(self, request: Request, principal: Principal) -> JSONResponse:
        self.metrics.inc("commandcore_mcp_requests_total")
        try:
            body = await request.json()
        except Exception:
            self.metrics.inc("commandcore_mcp_errors_total")
            return _rpc_error(None, -32700, "Parse error")
        if (
            not isinstance(body, dict)
            or body.get("jsonrpc") != "2.0"
            or not isinstance(body.get("method"), str)
        ):
            self.metrics.inc("commandcore_mcp_errors_total")
            return _rpc_error(
                body.get("id") if isinstance(body, dict) else None,
                -32600,
                "Invalid Request",
            )

        method = body["method"]
        params = body.get("params") if isinstance(body.get("params"), dict) else {}
        req_id = body.get("id")
        version_header = request.headers.get("mcp-protocol-version")
        modern = version_header == MODERN_PROTOCOL or method == "server/discover"
        if modern:
            ok, error = _validate_modern(request, body)
            if not ok:
                self.metrics.inc("commandcore_mcp_errors_total")
                assert error is not None
                return error

        if method == "server/discover":
            result = {
                "supportedVersions": [MODERN_PROTOCOL],
                "capabilities": {
                    "tools": {},
                    **({"resources": {}} if self.ui_resources else {}),
                },
                "_meta": {
                    "io.modelcontextprotocol/serverInfo": {
                        "name": self.name,
                        "version": self.server_version,
                        **({"icons": self.icons} if self.icons else {}),
                    }
                },
                "instructions": (
                    "CommandCore controls enrolled computers. Call devices.list, then devices.select. "
                    "Reuse the returned selection_id in subsequent device tools. Explicit device_id overrides selection_id."
                ),
            }
            return _rpc_result(
                req_id,
                _with_server_info(
                    _modernize(method, result),
                    self.server_version,
                    self.name,
                    self.icons,
                ),
            )

        if method == "initialize":
            requested = str(params.get("protocolVersion", "2025-11-25"))
            selected = requested if requested in LEGACY_PROTOCOLS else "2025-11-25"
            return _rpc_result(
                req_id,
                {
                    "protocolVersion": selected,
                    "capabilities": {
                        "tools": {},
                        **({"resources": {}} if self.ui_resources else {}),
                    },
                    "serverInfo": {
                        "name": self.name,
                        "version": self.server_version,
                        **(
                            {"icons": self.icons}
                            if self.icons and selected == "2025-11-25"
                            else {}
                        ),
                    },
                    "instructions": "Use devices.select and pass selection_id to subsequent tools.",
                },
            )

        if method == "notifications/initialized":
            return JSONResponse({}, status_code=202)

        if method == "resources/list":
            if not self.ui_resources:
                return _rpc_error(req_id, -32601, "Resources unavailable")
            result = {
                "resources": [
                    {"uri": uri, "name": spec[3], "mimeType": spec[1]}
                    for uri, spec in self.ui_resources.items()
                ]
            }
            return _rpc_result(req_id, _modernize(method, result) if modern else result)

        if method == "resources/read":
            if not self.ui_resources:
                return _rpc_error(req_id, -32601, "Resources unavailable")
            spec = self.ui_resources.get(params.get("uri"))
            if spec is None:
                return _rpc_error(req_id, -32002, "Unknown UI resource")
            uri, mime, asset, _title = spec
            result = {
                "contents": [
                    {
                        "uri": uri,
                        "mimeType": mime,
                        "text": web_asset(asset).read_text(encoding="utf-8"),
                        "_meta": {
                            "ui": {
                                "prefersBorder": True,
                                "csp": {"connectDomains": [], "resourceDomains": []},
                            },
                            "openai/ui": {
                                "availableDisplayModes": ["inline", "fullscreen"]
                            },
                        },
                    }
                ]
            }
            return _rpc_result(req_id, _modernize(method, result) if modern else result)

        if method == "tools/list":
            result = {"tools": self.definitions}
            return _rpc_result(
                req_id,
                _with_server_info(
                    _modernize(method, result),
                    self.server_version,
                    self.name,
                    self.icons,
                )
                if modern
                else result,
            )

        if method == "tools/call":
            name = params.get("name")
            args = (
                params.get("arguments")
                if isinstance(params.get("arguments"), dict)
                else {}
            )
            if not isinstance(name, str):
                self.metrics.inc("commandcore_mcp_errors_total")
                return _rpc_error(req_id, -32602, "tools/call requires params.name")
            if name not in {tool["name"] for tool in self.definitions}:
                return _rpc_result(
                    req_id,
                    _tool_error(
                        "unknown_tool", "Tool unavailable on this MCP surface", modern
                    ),
                )
            progress_token = (
                (params.get("_meta") or {}).get("progressToken")
                if isinstance(params.get("_meta"), dict)
                else None
            )
            if "text/event-stream" in request.headers.get("accept", "") and isinstance(
                progress_token, (str, int)
            ):
                return self._stream_call(
                    principal, name, args, req_id, modern, progress_token
                )
            try:
                payload = await self.tools.call(principal, name, args)
                result = _tool_result(payload, modern)
                spec = self.ui_specs.get(name)
                if spec and spec[0] in self.ui_resources:
                    meta = dict(result.get("_meta") or {})
                    meta["ui"] = {"resourceUri": spec[0]}
                    meta["openai/outputTemplate"] = spec[0]
                    result["_meta"] = meta
                return _rpc_result(
                    req_id,
                    _with_server_info(
                        result, self.server_version, self.name, self.icons
                    )
                    if modern
                    else result,
                )
            except ToolError as exc:
                self.metrics.inc("commandcore_mcp_errors_total")
                result = _tool_error(exc.code, exc.message, modern)
                if (
                    exc.code == "insufficient_scope"
                    and principal.auth_kind == "oauth2"
                    and self.scope_challenge is not None
                    and any(tool["name"] == name for tool in TOOL_DEFINITIONS)
                ):
                    required = self.tools._required_scope(name)
                    result["_meta"] = {
                        "mcp/www_authenticate": [self.scope_challenge(required)]
                    }
                return _rpc_result(
                    req_id,
                    _with_server_info(
                        result, self.server_version, self.name, self.icons
                    )
                    if modern
                    else result,
                )

        self.metrics.inc("commandcore_mcp_errors_total")
        return _rpc_error(req_id, -32601, f"Method not found: {method}")

    def _stream_call(self, principal, name, args, req_id, modern, progress_token):
        from .activity import observer

        async def stream():
            queue = asyncio.Queue()

            async def event(event):
                await queue.put(
                    {
                        "jsonrpc": "2.0",
                        "method": "notifications/progress",
                        "params": {
                            "progressToken": progress_token,
                            "progress": 0 if event["status"] == "running" else 1,
                            "total": 1,
                            "message": f"{event['tool']} [{event['execution_id']}] {event['status']}",
                        },
                    }
                )

            async def run():
                token = observer.set(event)
                try:
                    try:
                        payload = await self.tools.call(principal, name, args)
                        result = _tool_result(payload, modern)
                    except ToolError as exc:
                        result = _tool_error(exc.code, exc.message, modern)
                        if (
                            exc.code == "insufficient_scope"
                            and principal.auth_kind == "oauth2"
                            and self.scope_challenge
                        ):
                            result["_meta"] = {
                                "mcp/www_authenticate": [
                                    self.scope_challenge(
                                        self.tools._required_scope(name)
                                    )
                                ]
                            }
                    await queue.put({"jsonrpc": "2.0", "id": req_id, "result": result})
                finally:
                    observer.reset(token)
                    await queue.put(None)

            task = asyncio.create_task(run())
            try:
                while True:
                    message = await queue.get()
                    if message is None:
                        break
                    yield (
                        "event: message\ndata: "
                        + json.dumps(message, ensure_ascii=False)
                        + "\n\n"
                    )
                await task
            finally:
                if not task.done():
                    task.cancel()
                await asyncio.gather(task, return_exceptions=True)

        return StreamingResponse(
            stream(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-store"},
        )
