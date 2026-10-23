from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from typing import Any

from fastapi import Request
from fastapi.responses import JSONResponse, StreamingResponse

from .mcp_ui_diagnostics import record_ui_resource_request
from .metrics import Metrics
from .models import Principal
from .tools import (
    DEVICE_TOOLS,
    TOOL_DEFINITIONS,
    ToolError,
    ToolService,
    operation_ui_context,
)
from .web_assets import web_asset

# v2 resource identities are deployed successfully in the canonical OAuth
# CommandCore plugin. Always retain the original v1 URI for old conversations,
# but advertise versioned resources to avoid UI-template cache collisions.
WORKSPACE_UI_URI = "ui://commandcore/workspace-0.12.0-b1.html"
BROWSER_WIDGET_URI = WORKSPACE_UI_URI
BROWSER_WIDGET_MIME = "text/html;profile=mcp-app"
ACTIVITY_UI_URI = WORKSPACE_UI_URI
ACTIVITY_UI_MIME = "text/html;profile=mcp-app"
COMMANDCORE_UI_URI = WORKSPACE_UI_URI
COMMANDCORE_UI_MIME = "text/html;profile=mcp-app"
OPERATION_UI_URI = "ui://commandcore/operation-0.12.0-b1.html"
TASK_UI_URI = "ui://commandcore/task-0.12.0-b16.html"
TASK_UI_URIS = {
    "ui://commandcore/task-0.12.0-b15.html",
    "ui://commandcore/task-0.12.0-b14.html",
    "ui://commandcore/task-0.12.0-b13.html",
    "ui://commandcore/task-0.12.0-b12.html",
    "ui://commandcore/task-0.12.0-b11.html",
    "ui://commandcore/task-0.12.0-b10.html",
    TASK_UI_URI,
    "ui://commandcore/task-0.12.0-b9.html",
    "ui://commandcore/task-0.12.0-b8.html",
    "ui://commandcore/task-0.12.0-b7.html",
    "ui://commandcore/task-0.12.0-b6.html",
    "ui://commandcore/task-0.12.0-b4.html",
    "ui://commandcore/task-0.12.0-b1.html",
}
OPERATION_UI_URIS = {
    OPERATION_UI_URI,
    "ui://commandcore/operation-0.11.0-b3.html",
    "ui://commandcore/operation-0.11.0-b2.html",
    "ui://commandcore/operation-0.11.0-b1.html",
}
OPERATION_TOOLS = (
    {
        "browser.search",
        "browser.links",
        "browser.follow",
        "browser.back",
        "browser.forward",
    }
    | set(DEVICE_TOOLS)
    | {
        "browser." + x
        for x in (
            "open",
            "click",
            "move",
            "scroll",
            "type",
            "keypress",
            "observe",
            "handoff",
            "close",
        )
    }
)
TASK_ACTION_TOOLS = OPERATION_TOOLS - {
    "process.output",
    "process.status",
    "process.list",
    "devices.list",
    "devices.select",
}
LEGACY_UI_RESOURCES = {
    **{
        uri: (COMMANDCORE_UI_MIME, "commandcore-widget.html", "Saved task")
        for uri in TASK_UI_URIS
        if uri != TASK_UI_URI
    },
    "ui://commandcore/task-0.12.0-b1.html": (
        COMMANDCORE_UI_MIME,
        "commandcore-widget.html",
        "Saved task",
    ),
    "ui://commandcore/operation-0.11.0-b3.html": (
        COMMANDCORE_UI_MIME,
        "commandcore-widget.html",
        "Saved operation",
    ),
    "ui://commandcore/workspace-0.11.0-b3.html": (
        COMMANDCORE_UI_MIME,
        "commandcore-widget.html",
        "Saved workspace",
    ),
    **{
        uri: (COMMANDCORE_UI_MIME, "commandcore-widget.html", "Saved operation")
        for uri in OPERATION_UI_URIS
        if uri != OPERATION_UI_URI
    },
    **{
        uri: (COMMANDCORE_UI_MIME, "commandcore-widget.html", "Previous workspace")
        for uri in (
            "ui://commandcore/workspace-0.11.0-b1.html",
            "ui://commandcore/workspace-0.11.0-b2.html",
        )
    },
    "ui://commandcore/workspace-0.10.3-b2.html": (
        COMMANDCORE_UI_MIME,
        "commandcore-widget.html",
        "Previous workspace",
    ),
    "ui://commandcore/workspace-0.10.3-b1.html": (
        COMMANDCORE_UI_MIME,
        "commandcore-widget.html",
        "Previous workspace",
    ),
    "ui://commandcore/workspace-0.10.2-b3.html": (
        COMMANDCORE_UI_MIME,
        "commandcore-widget.html",
        "Previous workspace",
    ),
    "ui://commandcore/workspace-v8-state-20261017.html": (
        COMMANDCORE_UI_MIME,
        "commandcore-widget.html",
        "Previous workspace",
    ),
    "ui://commandcore/workspace-v8-approval-preview-20261018.html": (
        COMMANDCORE_UI_MIME,
        "commandcore-widget.html",
        "Previous approval inbox workspace",
    ),
    "ui://commandcore/workspace-premium-v7-static-20261017.html": (
        COMMANDCORE_UI_MIME,
        "commandcore-widget.html",
        "Prior UI workspace",
    ),
    "ui://commandcore/workspace-premium-v6-20261017.html": (
        COMMANDCORE_UI_MIME,
        "commandcore-widget.html",
        "Previous workspace",
    ),
    "ui://commandcore/workspace-premium-v5-20261017.html": (
        COMMANDCORE_UI_MIME,
        "commandcore-widget.html",
        "Previous UI version",
    ),
    "ui://commandcore/workspace-premium-v4-20261017.html": (
        COMMANDCORE_UI_MIME,
        "commandcore-widget.html",
        "Prior UI workspace",
    ),
    "ui://commandcore/workspace-premium-v3-20261017.html": (
        COMMANDCORE_UI_MIME,
        "commandcore-widget.html",
        "Prior workspace resource",
    ),
    "ui://commandcore/workspace-premium-v2-20261017.html": (
        COMMANDCORE_UI_MIME,
        "commandcore-widget.html",
        "Previous CommandCore workspace",
    ),
    "ui://commandcore/workspace-premium-v1-20261017.html": (
        COMMANDCORE_UI_MIME,
        "commandcore-widget.html",
        "CommandCore previous premium workspace",
    ),
    "ui://commandcore/workspace-v8-7-4.html": (
        COMMANDCORE_UI_MIME,
        "commandcore-widget.html",
        "CommandCore previous workspace",
    ),
    "ui://commandcore/workspace-v8-7-3.html": (
        COMMANDCORE_UI_MIME,
        "commandcore-widget.html",
        "CommandCore workspace (v8.7.3 compatibility)",
    ),
    "ui://commandcore/workspace-v8-7-2.html": (
        COMMANDCORE_UI_MIME,
        "commandcore-widget.html",
        "CommandCore workspace (v8.7.2 compatibility)",
    ),
    "ui://commandcore/workspace-v8-7-1.html": (
        COMMANDCORE_UI_MIME,
        "commandcore-widget.html",
        "CommandCore workspace (v8.7.1 compatibility)",
    ),
    "ui://commandcore/workspace-v8-7.html": (
        COMMANDCORE_UI_MIME,
        "commandcore-widget.html",
        "CommandCore workspace (v8.7 compatibility)",
    ),
    "ui://commandcore/workspace-v8-6.html": (
        COMMANDCORE_UI_MIME,
        "commandcore-widget.html",
        "CommandCore workspace (v8.6 compatibility)",
    ),
    "ui://commandcore/workspace-v8-5.html": (
        COMMANDCORE_UI_MIME,
        "commandcore-widget.html",
        "CommandCore workspace (v8.5 compatibility)",
    ),
    "ui://commandcore/workspace-v8-3.html": (
        COMMANDCORE_UI_MIME,
        "commandcore-widget.html",
        "CommandCore workspace (v8.3 compatibility)",
    ),
    "ui://commandcore/workspace-v6-r4.html": (
        ACTIVITY_UI_MIME,
        "commandcore-widget.html",
        "CommandCore workspace (v6.4 compatibility)",
    ),
    "ui://commandcore/workspace-v6.html": (
        ACTIVITY_UI_MIME,
        "activity-widget.html",
        "CommandCore workspace (v6 compatibility)",
    ),
    "ui://commandcore/activity-view-v2.html": (
        ACTIVITY_UI_MIME,
        "activity-widget.html",
        "CommandCore Activity (v2 compatibility)",
    ),
    "ui://commandcore/activity-view-v4.html": (
        ACTIVITY_UI_MIME,
        "activity-widget.html",
        "CommandCore Activity (V5.2 compatibility)",
    ),
    "ui://commandcore/browser-view-v4.html": (
        BROWSER_WIDGET_MIME,
        "browser-widget.html",
        "CommandCore Browser (v4 compatibility)",
    ),
    "ui://commandcore/live-views-v3.html": (
        COMMANDCORE_UI_MIME,
        "commandcore-widget.html",
        "CommandCore workspace (v3 compatibility)",
    ),
    "ui://commandcore/browser-view-v1.html": (
        BROWSER_WIDGET_MIME,
        "browser-widget.html",
        "CommandCore Browser (legacy)",
    ),
    "ui://commandcore/browser-view-v2.html": (
        BROWSER_WIDGET_MIME,
        "browser-widget.html",
        "CommandCore Browser (v2 compatibility)",
    ),
    "ui://commandcore/browser-view-v3.html": (
        BROWSER_WIDGET_MIME,
        "browser-widget.html",
        "CommandCore Browser (v3 compatibility)",
    ),
    "ui://commandcore/activity-view-v1.html": (
        ACTIVITY_UI_MIME,
        "activity-widget.html",
        "CommandCore Activity (legacy)",
    ),
    "ui://commandcore/activity-view-v3.html": (
        ACTIVITY_UI_MIME,
        "activity-widget.html",
        "CommandCore Activity (v3 compatibility)",
    ),
    "ui://commandcore/live-views-v1.html": (
        COMMANDCORE_UI_MIME,
        "commandcore-widget.html",
        "CommandCore Live Views (legacy)",
    ),
    "ui://commandcore/live-views-v2.html": (
        COMMANDCORE_UI_MIME,
        "commandcore-widget.html",
        "CommandCore Live Views (v2 compatibility)",
    ),
}

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


CARD_STYLE = '<style id="cc-operation-card-style">\nbody[data-cc-operation-compact=true]{border-radius:12px!important;min-height:0!important;max-width:940px!important;background:var(--cc-card)!important}\nbody[data-cc-operation-compact=true]>:not(#cc-step):not(script):not(style){display:none!important}\n#cc-step{display:none;border:1px solid var(--cc-line);border-radius:12px;overflow:hidden;font:12px/1.45 system-ui,sans-serif;color:var(--cc-text);background:var(--cc-card)}\nbody[data-cc-operation-compact=true] #cc-step{display:block}\n#cc-step-head{display:flex;align-items:center;gap:8px;padding:4px 8px;min-width:0}\n#cc-step-mark{width:7px;height:7px;background:#929298;border-radius:50%;flex:none}\n#cc-step[data-status=ok] #cc-step-mark{background:var(--cc-ok)}\n#cc-step[data-status=error] #cc-step-mark{background:var(--cc-fail)}\n#cc-step-tool{font-weight:650;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1}\n#cc-step-device{color:var(--cc-muted);font:10px/1.4 ui-monospace,monospace;max-width:30%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}\n#cc-step-expand{flex:none;min-width:40px;min-height:40px;font-size:17px;padding:3px 8px}\n#cc-step-summary{padding:0 8px 5px;color:var(--cc-muted);overflow-wrap:anywhere;font-size:11px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}\n#cc-step-details{padding:0 8px 5px}#cc-step-details summary{color:var(--cc-muted);font-size:11px}\n#cc-step-context{white-space:pre-wrap;overflow-wrap:anywhere;font:11px/1.6 ui-monospace,monospace;padding-top:6px}\n#cc-step-preview{display:block;width:100%;max-height:180px;object-fit:contain;background:#17181b;border-top:1px solid var(--cc-line)}\n#cc-step-caption{display:block;padding:7px 12px;color:var(--cc-muted);font-size:10px;border-top:1px solid var(--cc-line)}\n#cc-step-back{min-width:30px;min-height:34px;padding:3px 7px}\n@media(prefers-color-scheme:light){#cc-step{background:var(--color-background-secondary,#f7f7f8);color:var(--color-text-primary,#202124)}#cc-step-summary,#cc-step-device,#cc-step-details summary,#cc-step-caption{color:var(--color-text-secondary,#62646b)}}\n</style>\n'
CARD_BODY = '\n<section id="cc-step" aria-label="CommandCore operation" data-status="pending">\n <div id="cc-step-head"><span id="cc-step-mark" aria-hidden="true"></span><strong id="cc-step-tool">CommandCore</strong><span id="cc-step-device">—</span><button id="cc-step-expand" type="button" aria-label="Expand operation in CommandCore" title="Open full workspace">⤢</button></div>\n <div id="cc-step-summary" role="status">Loading operation details…</div>\n <details id="cc-step-details" hidden><summary>Command &amp; target</summary><div id="cc-step-context"></div></details>\n <img id="cc-step-preview" alt="Browser screenshot returned by this operation" hidden>\n <small id="cc-step-caption" hidden>Snapshot of this step · expand for live Browser</small>\n</section>\n'
CARD_RUNTIME = "\n<script id=\"cc-operation-card-runtime\">\n(()=>{\n \"use strict\";\n const by=id=>document.getElementById(id),root=by('cc-step');\n let kind='activity',boundOperation=null,displaySequence=0;\n const clean=(s,n=180)=>typeof s==='string'?s.slice(0,n):'';\n function envelope(raw){\n  let value=raw||{};\n  for(let i=0;i<4;i++){\n   const next=value.call_tool_result||value.mcp_tool_result||(value.result?.structuredContent?value.result:null);\n   if(!next)break;value=next;\n  }\n  return value;\n }\n function recordedResult(r){\n  const data=r.structuredContent||r;\n  if(!data||typeof data!=='object')return null;\n  // Rehydrate only this saved result. Never use latest account feed rows,\n  // raw commands, file content, browser control tokens or another card.\n  const match=typeof data.summary==='string'?data.summary.match(/^([a-z][a-z0-9_.]+) on ([^\\n]{1,100}): [a-z_]+$/):null;\n  if(match&&typeof data.execution_id==='string')return {tool:match[1],kind:'activity',device:match[2],execution_id:data.execution_id,status:data.status||'returned',exit_code:data.exit_code};\n  if(r.isError||data.error)return {tool:'CommandCore result',status:'error'};\n  if(typeof data.state==='string'&&('url' in data||'session_id' in data))return {tool:'Browser result',kind:'browser',status:'returned'};\n  return null;\n }\n function render(raw){\n  const outer=envelope(raw),r=outer?.result?.structuredContent?outer.result:outer;\n  const meta=r?._meta||{};\n  const op=meta['commandcore/operation']||raw?.['commandcore/operation']||(!boundOperation?recordedResult(r):null);\n  if(!op||typeof op.tool!=='string')return;\n  if(boundOperation?.operation_id&&op.operation_id&&boundOperation.operation_id!==op.operation_id)return;\n  // This result is the sole source of the compact card. Never read latest feed\n  // rows, another widget's state, raw input arguments or shell stdout here.\n  boundOperation=op;kind=op.kind==='browser'?'browser':'activity';\n  by('cc-step-tool').textContent=op.tool;\n  by('cc-step-device').textContent=kind==='browser'?'Browser worker':clean(op.device,80)||'Device not reported';\n  const status=r.isError||['error','failed','timeout','agent_disconnected','disconnected','canceled','stopped','interrupted'].includes(op.status)||(Number.isInteger(op.exit_code)&&op.exit_code!==0)?'error':['running','started'].includes(op.status)?'running':['ok','completed'].includes(op.status)?'ok':'returned';\n  root.dataset.status=status;\n  let label=({ok:'Completed',error:'Failed',running:'Running',returned:'Returned'})[status];\n  if(Number.isFinite(op.duration_ms))label+=' · '+(op.duration_ms>=1000?(op.duration_ms/1000).toFixed(1)+'s':op.duration_ms+'ms');\n  if(Number.isInteger(op.exit_code))label+=' · exit '+op.exit_code;\n  by('cc-step-summary').textContent=label;\n  const d=op.detail&&typeof op.detail==='object'?op.detail:{};\n  let target=clean(d.path||d.cwd||d.command_name,500);\n  if(kind==='browser'&&typeof (r.structuredContent||r)?.url==='string'){try{const u=new URL((r.structuredContent||r).url);if(!u.username&&!u.password)target=u.origin+u.pathname;}catch(_){}}\n  if(target){by('cc-step-summary').textContent=label+' · '+target;by('cc-step-summary').title=target;}\n  const lines=[];\n  for(const [key,name] of [['command_name','Command'],['cwd','Folder'],['path','File'],['destination','Target'],['verified_effect','Effect']]){\n   if(typeof d[key]==='string'&&d[key])lines.push(name+' · '+clean(d[key],500));\n  }\n  if(lines.length&&op.execution_id)lines.push('Execution · '+clean(op.execution_id,80));\n  by('cc-step-context').textContent=lines.join('\\n');by('cc-step-details').hidden=!lines.length;\n  const image=(r.content||[]).find(x=>x.type==='image'&&x.mimeType==='image/png'&&/^[A-Za-z0-9+/=]+$/.test(x.data||''));\n  const privateControl=r.structuredContent?.state==='awaiting_human';\n  by('cc-step-preview').hidden=true;by('cc-step-preview').removeAttribute('src');by('cc-step-caption').hidden=true;\n  if(kind==='browser'&&image&&!privateControl){\n   by('cc-step-preview').src='data:image/png;base64,'+image.data;by('cc-step-preview').hidden=false;by('cc-step-caption').hidden=false;\n  }else if(kind==='browser'&&privateControl){by('cc-step-summary').textContent='Private human control · screen hidden';}\n }\n function hostMode(mode){\n  if(typeof window.openai?.requestDisplayMode==='function')return Promise.resolve(window.openai.requestDisplayMode({mode})).catch(()=>{});\n  // Shared MCP Apps bridge; absence or rejection keeps a usable local view.\n  window.parent.postMessage({jsonrpc:'2.0',id:'cc-step-mode-'+(++displaySequence),method:'ui/request-display-mode',params:{mode}},'*');\n  return Promise.resolve();\n }\n function expand(){\n  document.body.dataset.ccOperationCompact='false';document.body.dataset.ccMinimized='false';\n  document.getElementById(kind==='browser'?'browser-tab':'activity-tab').click();\n  hostMode('fullscreen');\n }\n by('cc-step-expand').addEventListener('click',expand);\n const back=document.createElement('button');back.id='cc-step-back';back.type='button';back.textContent='↙';\n back.title='Back to this operation';back.setAttribute('aria-label','Back to operation card');document.querySelector('header').append(back);\n back.addEventListener('click',()=>{document.body.dataset.ccOperationCompact='true';hostMode('inline');});\n window.addEventListener('message',e=>{\n  if(e.source!==window.parent)return;\n  if(e.data?.method==='ui/notifications/tool-result')render(e.data.params);\n  if(e.data?.method==='ui/notifications/tool-input'&&!boundOperation){\n   root.dataset.status='running';by('cc-step-summary').textContent='Running this operation…';\n  }\n });\n window.addEventListener('openai:set_globals',e=>{\n  const g=e.detail?.globals||{};render(g.toolResponseMetadata||{});if(!boundOperation)render(g.toolOutput||{});\n });\n render(window.openai?.toolResponseMetadata||{});\n if(!boundOperation)render(window.openai?.toolOutput||{});\n setTimeout(()=>{if(!boundOperation)by('cc-step-summary').textContent='Operation details unavailable in this view. No command was rerun.';},5000);\n})();\n</script>\n"


def _operation_html(html: str) -> str:
    html = html.replace(
        "bounds.left-area.left+(bounds.width-width)/2+cursor.x*scale",
        "bounds.left-area.left+stage.scrollLeft+(bounds.width-width)/2+cursor.x*scale",
    ).replace(
        "bounds.top-area.top+(bounds.height-height)/2+cursor.y*scale",
        "bounds.top-area.top+stage.scrollTop+(bounds.height-height)/2+cursor.y*scale",
    )
    return (
        html.replace("</head>", CARD_STYLE + "</head>", 1)
        .replace("<body>", '<body data-cc-operation-compact="true">' + CARD_BODY, 1)
        .replace("</body>", CARD_RUNTIME + "</body>", 1)
    )


# Durable UI task boundaries. No command arguments, output, paths, browser
# screenshots or credentials are stored here. Authorization stays in MCPHandler.
import contextlib
from datetime import UTC


class UITaskLedger:
    def __init__(self, path=None):
        import os
        import sqlite3
        import threading

        # Native Windows server hosting is not a Browser persistence target.
        # Keep auxiliary summaries only in memory, never in an unprotected file.
        self._memory_db = None
        self._memory_lock = threading.RLock()
        if os.name != "posix" or path == ":memory:":
            self.path = None
            self._memory_db = sqlite3.connect(":memory:", check_same_thread=False)
        else:
            self._initialize_file(path)
        self._initialize_schema()

    def _initialize_file(self, path):
        import os
        from pathlib import Path

        self.path = Path(
            path
            or os.environ.get("COMMANDCORE_UI_TASK_DB")
            or str(
                Path(
                    os.environ.get("COMMANDCORE_DB", "/data/commandcore.sqlite3")
                ).with_name("ui-tasks.sqlite3")
            )
        )
        if not self.path.is_absolute() or self.path.is_symlink():
            raise RuntimeError("UI task database requires a private absolute file")
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
            os.close(fd)
        except FileExistsError:
            if self.path.stat().st_mode & 0o077:
                raise RuntimeError("UI task database must be private")

    def _initialize_schema(self):
        with self.connect() as db:
            db.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS ui_tasks (
                    id TEXT PRIMARY KEY, owner TEXT NOT NULL, conversation TEXT NOT NULL,
                    started REAL NOT NULL, ended REAL,
                    last_tool TEXT NOT NULL DEFAULT '', device TEXT NOT NULL DEFAULT ''
                );
                CREATE INDEX IF NOT EXISTS ui_tasks_owner ON ui_tasks(owner,conversation,started);
                CREATE TABLE IF NOT EXISTS ui_calls (
                    id TEXT PRIMARY KEY, task_id TEXT NOT NULL, started REAL NOT NULL,
                    ended REAL, status TEXT NOT NULL, tool TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS ui_calls_task ON ui_calls(task_id,started);
            """)
            # A process restart cannot certify an outstanding remote call.
            db.execute(
                "UPDATE ui_calls SET ended=?,status='interrupted' WHERE ended IS NULL",
                (self.now(),),
            )

    def bind_activity(self, live):
        """Bind conversation tags to this private durable ledger at startup.

        Viewer references and activity traces remain ephemeral. Only the random
        HMAC secret survives, so persisted task identities survive a restart.
        Never replace the key of a broker already serving viewers or activity.
        """
        import os
        import secrets
        import stat

        if self._memory_db is not None or not hasattr(live, "_session_key"):
            return
        path = self.path.with_name(self.path.name + ".session-key")
        try:
            fd = os.open(
                path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
            )
        except FileExistsError:
            pass
        else:
            with os.fdopen(fd, "wb") as handle:
                handle.write(secrets.token_bytes(32))
                handle.flush()
                os.fsync(handle.fileno())
        # A malicious FIFO must fail immediately instead of blocking startup.
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as handle:
            info = os.fstat(handle.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_mode & 0o077
                or info.st_uid != os.geteuid()
                or info.st_nlink != 1
            ):
                raise RuntimeError(
                    "Conversation key requires a private owner-only regular file"
                )
            key = handle.read(33)
        if len(key) != 32:
            raise RuntimeError("Conversation key must contain exactly 32 bytes")
        if live._session_key != key:
            if any(
                getattr(live, name, None)
                for name in ("_viewers", "active", "completed")
            ):
                raise RuntimeError(
                    "Conversation key must be bound before serving activity"
                )
            live._session_key = key

    @staticmethod
    def now():
        import time

        return time.time()

    @contextlib.contextmanager
    def connect(self):
        import sqlite3
        from urllib.parse import quote

        with (
            self._memory_lock
            if self._memory_db is not None
            else contextlib.nullcontext()
        ):
            yield from self._connection_scope(sqlite3, quote)

    def _connection_scope(self, sqlite3, quote):
        db = (
            self._memory_db
            if self._memory_db is not None
            else sqlite3.connect(
                "file:" + quote(str(self.path), safe="/") + "?mode=rw",
                uri=True,
                timeout=2,
            )
        )
        db.row_factory = sqlite3.Row
        try:
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            if self._memory_db is None:
                db.close()

    @staticmethod
    def owner(principal):
        import hashlib
        import json

        return hashlib.sha256(
            json.dumps(
                [principal.issuer, principal.subject, principal.client_id],
                separators=(",", ":"),
            ).encode()
        ).hexdigest()

    def start(self, owner, conversation):
        import uuid

        now = self.now()
        task = str(uuid.uuid4())
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            # Prior cards stop following later work in this same conversation.
            db.execute(
                "UPDATE ui_calls SET ended=?,status='interrupted' WHERE ended IS NULL AND task_id IN (SELECT id FROM ui_tasks WHERE owner=? AND conversation=? AND ended IS NULL)",
                (now, owner, conversation),
            )
            db.execute(
                "UPDATE ui_tasks SET ended=? WHERE owner=? AND conversation=? AND ended IS NULL",
                (now, owner, conversation),
            )
            db.execute(
                "INSERT INTO ui_tasks(id,owner,conversation,started) VALUES(?,?,?,?)",
                (task, owner, conversation, now),
            )
            cutoff = now - 7 * 86400
            db.execute(
                "DELETE FROM ui_calls WHERE task_id IN (SELECT id FROM ui_tasks WHERE started<?)",
                (cutoff,),
            )
            db.execute("DELETE FROM ui_tasks WHERE started<?", (cutoff,))
        return task

    def get(self, owner, conversation, task):
        if not isinstance(task, str) or len(task) != 36:
            raise ToolError(
                "invalid_task_view", "Task unavailable in this conversation"
            )
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM ui_tasks WHERE id=? AND owner=? AND conversation=?",
                (task, owner, conversation),
            ).fetchone()
            if row is None:
                raise ToolError(
                    "invalid_task_view", "Task unavailable in this conversation"
                )
            stats = db.execute(
                """SELECT count(*) total,
                sum(CASE WHEN ended IS NULL THEN 1 ELSE 0 END) running,
                sum(CASE WHEN ended IS NOT NULL AND status NOT IN ('ok','completed','started','returned') THEN 1 ELSE 0 END) failed
                FROM ui_calls WHERE task_id=?""",
                (task,),
            ).fetchone()
            last = db.execute(
                "SELECT status,tool FROM ui_calls WHERE task_id=? ORDER BY started DESC LIMIT 1",
                (task,),
            ).fetchone()
        return dict(row) | {
            "total": stats["total"],
            "running": stats["running"] or 0,
            "failed": stats["failed"] or 0,
            "last_status": last["status"] if last else "ready",
            "last_tool": last["tool"] if last else "",
        }

    @staticmethod
    def public(row):
        return {
            key: row[key]
            for key in [
                "id",
                "started",
                "ended",
                "total",
                "running",
                "failed",
                "last_status",
                "last_tool",
                "device",
            ]
        }

    def begin_call(self, owner, conversation, tool):
        import uuid

        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            task = db.execute(
                "SELECT id FROM ui_tasks WHERE owner=? AND conversation=? AND ended IS NULL ORDER BY started DESC LIMIT 1",
                (owner, conversation),
            ).fetchone()
            if not task:
                return None
            call = str(uuid.uuid4())
            db.execute(
                "INSERT INTO ui_calls(id,task_id,started,status,tool) VALUES(?,?,?,?,?)",
                (call, task["id"], self.now(), "running", tool),
            )
            db.execute("UPDATE ui_tasks SET last_tool=? WHERE id=?", (tool, task["id"]))
        return call

    def end_call(self, call, status, device=""):
        if not call:
            return
        with self.connect() as db:
            db.execute(
                "UPDATE ui_calls SET ended=?,status=? WHERE id=? AND ended IS NULL",
                (self.now(), str(status)[:40], call),
            )
            if isinstance(device, str) and device:
                db.execute(
                    "UPDATE ui_tasks SET device=? WHERE id=(SELECT task_id FROM ui_calls WHERE id=?)",
                    (device[:100], call),
                )

    def history(self, owner, conversation, task):
        # Recheck ownership in the query; never expose another task's calls.
        from datetime import datetime

        with self.connect() as db:
            rows = db.execute(
                """SELECT c.id,c.started,c.ended,c.status,c.tool
                FROM ui_calls c JOIN ui_tasks t ON t.id=c.task_id
                WHERE t.id=? AND t.owner=? AND t.conversation=?
                ORDER BY c.started DESC LIMIT 50""",
                (task, owner, conversation),
            ).fetchall()

        def iso(value):
            return (
                datetime.fromtimestamp(value, UTC).isoformat()
                if value is not None
                else None
            )

        return [
            {
                "id": "saved-call-" + r["id"],
                "tool": r["tool"],
                "status": r["status"],
                "device": "Not retained",
                "started_at": iso(r["started"]),
                "finished_at": iso(r["ended"]),
                "duration_ms": round(max(0, (r["ended"] - r["started"]) * 1000))
                if r["ended"] is not None
                else None,
                "history_summary": True,
                "detail": {
                    "category": "Saved summary",
                    "note": "Saved call summary. Device, command and file details are no longer available. Duration includes call tracking overhead.",
                },
            }
            for r in rows
        ]

    def finish(self, owner, conversation, task):
        row = self.get(owner, conversation, task)
        if row["running"]:
            raise ToolError(
                "task_still_running",
                "Wait for outstanding calls before finishing the task",
            )
        with self.connect() as db:
            db.execute(
                "UPDATE ui_tasks SET ended=COALESCE(ended,?) WHERE id=?",
                (self.now(), task),
            )
        return self.public(self.get(owner, conversation, task))


TASK_STYLE = '<style id="cc-task-style">\nbody[data-cc-task-compact=true]{display:block!important;border:0!important;padding:0!important;height:auto!important;min-height:0!important;max-width:940px!important;background:var(--cc-card)!important;border-radius:12px!important}\nbody[data-cc-task-compact=true]>:not(#cc-task):not(script):not(style){display:none!important}\n#cc-task{display:none;border:1px solid var(--cc-line);border-radius:12px;background:var(--cc-card);color:var(--cc-text);font:12px/1.45 system-ui,sans-serif;overflow:hidden}\nbody[data-cc-task-compact=true] #cc-task{display:block}\n#cc-task-head{display:flex;align-items:center;gap:8px;padding:8px 12px 4px;min-width:0}\n#cc-task-dot{width:7px;height:7px;flex:none;border-radius:50%;background:var(--cc-muted)}\n#cc-task[data-state=running] #cc-task-dot{background:var(--cc-warn,#b58023)}\n#cc-task[data-state=ok] #cc-task-dot{background:var(--cc-ok)}\n#cc-task[data-state=error] #cc-task-dot{background:var(--cc-fail)}\n#cc-task-title{font-size:13px;flex:1;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-weight:650}\n#cc-task-device{padding:3px 6px;border:1px solid var(--cc-line);border-radius:6px;max-width:30%;color:var(--cc-muted);font:10px/1.4 ui-monospace,monospace;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}\n#cc-task-device:empty{display:none}\n#cc-task-expand{min-height:40px;min-width:40px;padding:3px 8px;font-size:17px;flex:none}\n#cc-task-summary{padding:0 12px 8px;color:var(--cc-muted);font-size:12px;overflow-wrap:anywhere}\n#cc-task-steps{padding:0 12px 8px;font-size:12px}#cc-task-steps summary{color:var(--cc-muted);cursor:pointer;min-height:32px;align-content:center}#cc-task-steps[open] summary{color:var(--cc-text)}\n#cc-task-list{list-style:none;padding:0;margin:5px 0 0}#cc-task-list li{border-top:1px solid var(--cc-line);padding:5px 0;overflow-wrap:anywhere}\n#cc-task-list small{display:block;color:var(--cc-muted);font-size:10px}\n#cc-task-preview{width:100%;max-height:260px;object-fit:contain;background:#17181b;border-top:1px solid var(--cc-line)}\n#cc-task-caption{display:block;padding:5px 8px;color:var(--cc-muted);font-size:10px}\n#cc-task-retry{margin:0 8px 7px;min-height:40px;font-size:11px}\n#cc-task-back{min-height:40px;min-width:36px;padding:3px 7px}\n#cc-task :is(button,summary):focus-visible{outline:2px solid var(--cc-cyan);outline-offset:-2px}\n#cc-task [hidden]{display:none!important}\n</style>'
TASK_BODY = '<section id="cc-task" aria-label="CommandCore live task" data-state="waiting">\n <div id="cc-task-head"><span id="cc-task-dot" aria-hidden="true"></span><strong id="cc-task-title">CommandCore</strong><span id="cc-task-device"></span><button id="cc-task-expand" type="button" aria-label="Expand task in CommandCore" title="Show task details">⤢</button></div>\n <div id="cc-task-summary" role="status">Loading this task…</div>\n <details id="cc-task-steps" hidden><summary>Details</summary><ol id="cc-task-list"></ol><button id="cc-task-retry" type="button" hidden>Retry live updates</button></details>\n <img id="cc-task-preview" alt="Browser preview for this conversation" hidden><small id="cc-task-caption" hidden></small>\n</section>'
TASK_RUNTIME = "<script id=\"cc-task-runtime\">\n(()=>{\n 'use strict';\n const by=id=>document.getElementById(id),root=by('cc-task');\n let widgetId='',id='',viewer='',task=null,kind='activity',generation=0,busy=false,timer=null,failures=0,renewed=false,sequence=-1,frameMissing=false,browserActive=false,previewSession='';\n const clean=(x,n=160)=>typeof x==='string'?x.slice(0,n):'';\n const label=tool=>({'shell.exec':'Command','system.metrics':'Device resources','system.info':'Device information','fs.read':'Reading a file','fs.write':'File update','fs.list':'Files','process.start':'Starting a process','process.stop':'Stopping a process','git.status':'Git status','git.diff':'Reviewing changes','browser.search':'Web search','browser.open':'Browsing','browser.links':'Inspecting page links','browser.follow':'Opening a page link','browser.back':'Previous page','browser.forward':'Next page','browser.observe':'Page inspection','browser.close':'Browser closed'})[tool]||tool||'CommandCore';\n const normalized=raw=>{let v=raw||{};for(let i=0;i<4;i++){const next=v.call_tool_result||v.mcp_tool_result||(v.result?.structuredContent?v.result:null);if(!next)break;v=next;}return v;};\n const data=raw=>{const r=normalized(raw);return r.structuredContent||r;};\n const active=()=>!document.hidden&&!window.__ccWorkspaceSuspended&&document.body.dataset.ccTaskCompact==='true';\n function imageOff(){by('cc-task-preview').hidden=true;by('cc-task-preview').removeAttribute('src');by('cc-task-caption').hidden=true;}\n function schedule(delay=1500){clearTimeout(timer);if(active()&&id&&task?.ended==null&&failures<3)timer=setTimeout(poll,delay);}\n let lastSaved='';\n function summarySnapshot(events){\n  const total=Number.isSafeInteger(task?.total)&&task.total>=0?task.total:0;\n  return {version:1,task:{id,total,running:Number.isSafeInteger(task?.running)?Math.max(0,task.running):0,failed:Number.isSafeInteger(task?.failed)?Math.max(0,task.failed):0,ended:typeof task?.ended==='number'&&Number.isFinite(task.ended)?task.ended:null,last_tool:clean(task?.last_tool,80),device:clean(task?.device,80)},events:(Array.isArray(events)?events:[]).slice(0,3).map(row=>({tool:clean(row?.tool,80),status:clean(row?.status,32),device:clean(row?.device,80)}))};\n }\n function saveSummary(events){\n  if(typeof window.openai?.setWidgetState!=='function')return;\n  const saved=summarySnapshot(events),signature=JSON.stringify(saved);if(signature===lastSaved)return;\n  lastSaved=signature;\n  try{const existing=window.openai.widgetState;Promise.resolve(window.openai.setWidgetState({...((existing&&typeof existing==='object'&&!Array.isArray(existing))?existing:{}),ccTaskSummary:saved})).catch(()=>{});}catch(_){}\n }\n function restoredSummary(next){\n  const saved=window.openai?.widgetState?.ccTaskSummary,t=saved?.task;\n  if(saved?.version!==1||t?.id!==next||!Number.isSafeInteger(t.total)||t.total<0||!Number.isSafeInteger(t.running)||t.running<0||!Number.isSafeInteger(t.failed)||t.failed<0||t.failed>t.total)return null;\n  if(t.ended!==null&&!(typeof t.ended==='number'&&Number.isFinite(t.ended)&&t.ended>0&&t.running===0))return null;\n  return {task:{id:next,total:t.total,running:t.running,failed:t.failed,ended:t.ended,last_tool:clean(t.last_tool,80),device:clean(t.device,80)},events:(Array.isArray(saved.events)?saved.events:[]).slice(0,3).map(row=>({tool:clean(row?.tool,80),status:clean(row?.status,32),device:clean(row?.device,80)}))};\n }\n function archived(){\n  failures=3;clearTimeout(timer);imageOff();root.dataset.state=task?.failed?'error':'waiting';\n  const count=Number.isSafeInteger(task?.total)?task.total:0;\n  by('cc-task-summary').textContent='Saved task · '+count+' call'+(count===1?'':'s')+(task?.failed?' · '+task.failed+' need review':'');\n  by('cc-task-retry').hidden=true;by('cc-task-expand').hidden=true;\n }\n\n function accept(raw){\n  const r=normalized(raw),p=data(r),next=p.task_id||p.task?.id;\n  const incoming=clean(r._meta?.['openai/widgetSessionId']||raw?.['openai/widgetSessionId'],160);\n  if(typeof next!=='string'||!/^[a-f0-9-]{36}$/i.test(next))return;\n  if(widgetId&&incoming&&widgetId!==incoming)return;\n  if(id&&id!==next){\n   // A host may explicitly reuse this mounted widget. Rebind only when its\n   // per-instance host ID matches; unrelated result replays stay isolated.\n   if(!widgetId||incoming!==widgetId)return;\n   generation++;clearTimeout(timer);imageOff();viewer='';task=null;id='';sequence=-1;frameMissing=false;browserActive=false;previewSession='';\n  }\n  if(!widgetId&&incoming)widgetId=incoming;\n  const changed=!id;id=next;window.__ccTaskId=id;\n  if(p.session_available===true&&typeof p.session_ref==='string')viewer=p.session_ref;\n  if(changed){generation++;failures=0;renewed=false;}\n  if(p.task&&p.task.id===id&&!(task?.ended!=null&&p.task.ended==null)&&!(failures>=3&&p.task.ended==null)){\n   const saved=changed&&p.task.ended==null?restoredSummary(id):null;\n   if(p.task.ended!=null&&task?.ended==null){generation++;clearTimeout(timer);}\n   task=saved?.task||p.task;render(saved?.events||p.events||[]);\n  }\n  if(viewer&&window.__ccAcceptViewer)window.__ccAcceptViewer({session_available:true,session_ref:viewer});\n  if(changed)poll();\n }\n function render(events){\n  if(!task)return;\n  const total=Number.isInteger(task.total)?task.total:0,running=Number.isInteger(task.running)?task.running:0,failed=Number.isInteger(task.failed)?task.failed:0;\n  const last=clean(task.last_tool,80);\n  const browserStep=last.startsWith('browser.')?last:(Array.isArray(events)?events:[]).find(x=>typeof x?.tool==='string'&&x.tool.startsWith('browser.')&&x.tool!=='browser.frame')?.tool;\n  if(browserStep)browserActive=browserStep!=='browser.close';\n  kind=browserActive?'browser':'activity';\n  by('cc-task-expand').hidden=false;by('cc-task-expand').title=browserActive?'Open Browser controls':'Show task details';\n  root.dataset.state=running?'running':failed?'error':(task.ended!=null||total)?'ok':'waiting';\n  by('cc-task-title').textContent=label(last);by('cc-task-title').title=last;by('cc-task-device').textContent=clean(task.device,80);\n  let summary=running?'Running · '+running+' active':task.ended!=null?(failed?'Task ended':'Completed'):'Ready';\n  summary+=' · '+total+' call'+(total===1?'':'s');if(failed)summary+=' · '+failed+' need review';\n  by('cc-task-summary').textContent=summary;\n  const rows=Array.isArray(events)?events.filter(x=>x&&typeof x.tool==='string'&&!['devices.list','devices.select','process.output','process.status','process.list'].includes(x.tool)).slice(0,3):[];\n  const list=by('cc-task-list');list.replaceChildren();\n  const status=s=>({ok:'Completed',completed:'Completed',started:'Running',running:'Running',timeout:'Timed out',agent_disconnected:'Disconnected',error:'Failed',canceled:'Canceled',stopped:'Stopped',interrupted:'Interrupted'})[s]||'Returned';\n  for(const row of rows){const li=document.createElement('li');li.textContent=label(clean(row.tool,80))+' · '+status(row.status);li.title=clean(row.tool,80);const hint=document.createElement('small');hint.textContent=clean(row.device,80)+(row.detail?.path?' · '+clean(row.detail.path,180):'');li.append(hint);list.append(li);}\n  by('cc-task-steps').hidden=rows.length===0;\n  if(kind!=='browser'||task.ended!=null){imageOff();sequence=-1;previewSession='';}\n  by('cc-task-retry').hidden=true;saveSummary(events);\n }\n function failure(message){failures++;root.dataset.state=task?.failed?'error':'waiting';by('cc-task-summary').textContent='Live updates paused';by('cc-task-retry').hidden=false;by('cc-task-steps').hidden=false;imageOff();}\n async function call(name,args){\n  await window.__ccBridgeReady;\n  let deadline;let result;try{result=await Promise.race([window.__ccCallTool(name,args),new Promise((_,reject)=>{deadline=setTimeout(()=>reject(Error('viewer_timeout')),12000);})]);}finally{clearTimeout(deadline);}\n  const payload=data(result);\n  if(result?.isError||payload?.error){\n   let code=clean(payload?.error,80);\n   if(!code){try{code=clean(JSON.parse((normalized(result).content||[]).find(x=>x.type==='text')?.text||'{}').error,80);}catch(_){}}\n   throw Error(code||'viewer_unavailable');\n  }\n  return result;\n }\n async function browserFrame(current){\n  if(kind!=='browser'||task?.ended!=null||(frameMissing&&Date.now()<frameMissing))return;\n  try{\n   const result=await call('browser.frame',{session_ref:viewer,after_sequence:sequence});if(current!==generation||!active())return;\n   const p=data(result);\n   if(['awaiting_human','awaiting_human_control'].includes(p.state)){\n    imageOff();sequence=-1;by('cc-task-caption').textContent='Private human control · screen hidden';by('cc-task-caption').hidden=false;return;\n   }\n   if(typeof p.session_id==='string'&&p.session_id!==previewSession){imageOff();sequence=-1;previewSession=p.session_id;}\n   const image=(normalized(result).content||[]).find(x=>x.type==='image'&&x.mimeType==='image/png'&&typeof x.data==='string'&&/^[A-Za-z0-9+/=]+$/.test(x.data));\n   if(image){if(Number.isSafeInteger(p.sequence))sequence=p.sequence;by('cc-task-preview').src='data:image/png;base64,'+image.data;by('cc-task-preview').hidden=false;by('cc-task-caption').textContent='Live preview · expand for Browser controls';by('cc-task-caption').hidden=false;}\n   else if(by('cc-task-preview').hidden){by('cc-task-caption').textContent='Connecting to Browser preview…';by('cc-task-caption').hidden=false;}\n  }catch(_){if(current===generation){imageOff();sequence=-1;frameMissing=Date.now()+12000;by('cc-task-caption').textContent='Browser preview unavailable · expand to check the session';by('cc-task-caption').hidden=false;}}\n }\n async function poll(){\n  clearTimeout(timer);if(busy||!active()||!id||task?.ended!=null||failures>=3)return;\n  busy=true;const current=generation;\n  try{\n   let result;\n   try{result=await call('activity.feed',{view:'conversation',session_ref:viewer,task_id:id,include_details:true,limit:35});}\n   catch(err){\n    if(/insufficient_scope|invalid_include_details/.test(err.message))result=await call('activity.feed',{view:'conversation',session_ref:viewer,task_id:id,include_details:false,limit:35});\n    else if(!renewed&&/invalid_session_view/.test(err.message)){\n     renewed=true;const fresh=data(await call('commandcore.viewer',{}));if(fresh.session_available!==true||typeof fresh.session_ref!=='string')throw err;\n     viewer=fresh.session_ref;if(window.__ccAcceptViewer)window.__ccAcceptViewer(fresh);\n     result=await call('activity.feed',{view:'conversation',session_ref:viewer,task_id:id,include_details:false,limit:35});\n    }else throw err;\n   }\n   if(current!==generation||!active())return;\n   const p=data(result);if(!p.task||p.task.id!==id)throw Error('invalid_task_view');\n   task=p.task;failures=0;renewed=false;render(p.events||[]);await browserFrame(current);\n  }catch(err){if(current===generation&&active()){\n   if(err.message==='invalid_task_view'){archived();}\n   else failure(err.message==='invalid_session_view'?'Task connection expired. Reconnect to verify this chat.':'Task connection unavailable. Reconnect to try again.');\n  }}\n  finally{busy=false;schedule(failures?Math.min(15000,2500*2**failures):1500);}\n }\n function mode(mode){if(typeof window.openai?.requestDisplayMode==='function')Promise.resolve(window.openai.requestDisplayMode({mode})).catch(()=>{});else window.parent.postMessage({jsonrpc:'2.0',id:'task-mode-'+Date.now(),method:'ui/request-display-mode',params:{mode}},'*');}\n by('cc-task-expand').addEventListener('click',()=>{generation++;clearTimeout(timer);document.body.dataset.ccTaskCompact='false';document.body.dataset.ccOperationCompact='false';document.body.dataset.ccMinimized='false';by(kind==='browser'?'browser-tab':'activity-tab').click();queueSize();});\n const back=document.createElement('button');back.id='cc-task-back';back.type='button';back.textContent='↙';back.setAttribute('aria-label','Back to live task');document.querySelector('header').append(back);\n function collapse(){\n  if(document.body.dataset.ccTaskCompact!=='true'){generation++;clearTimeout(timer);}\n  document.body.dataset.ccTaskCompact='true';document.body.dataset.ccOperationCompact='true';document.body.dataset.ccMinimized='false';\n  by('cc-task-steps').open=false;imageOff();sequence=-1;\n  const minimize=by('cc-minimize');if(minimize){minimize.textContent='Minimize';minimize.setAttribute('aria-expanded','true');minimize.setAttribute('aria-label','Minimize CommandCore workspace');}\n  mode('inline');poll();queueSize();\n }\n back.addEventListener('click',collapse);\n // Task details stay inside the conversation. Full workspace is separate.\n by('cc-browser-enlarge')?.remove();\n by('cc-minimize')?.addEventListener('click',collapse);\n by('cc-task-retry').addEventListener('click',()=>{failures=0;renewed=false;frameMissing=false;poll();});\n window.addEventListener('message',e=>{if(e.source===window.parent&&e.data?.method==='ui/notifications/tool-result')accept(e.data.params);});\n window.addEventListener('openai:set_globals',e=>{const g=e.detail?.globals||{};if(g.displayMode&&g.displayMode!=='inline')collapse();if(g.toolResponseMetadata)accept(g.toolResponseMetadata);if(g.toolOutput)accept(g.toolOutput);});\n window.addEventListener('pagehide',()=>{generation++;clearTimeout(timer);imageOff();});\n window.addEventListener('pageshow',e=>{if(e.persisted)collapse();else if(active())poll();});\n document.addEventListener('visibilitychange',()=>{generation++;clearTimeout(timer);if(!document.hidden)collapse();else imageOff();});\n // Report the actual body height, not the iframe viewport height. This\n // prevents a compact mobile card from retaining an empty full-screen block.\n let sizeReady=false,lastHeight=-1,sizeFrame=0;\n function reportSize(){\n  sizeFrame=0;if(!sizeReady||document.hidden||window.__ccWorkspaceSuspended)return;\n  const height=Math.max(1,Math.ceil(document.body.getBoundingClientRect().height));\n  if(height===lastHeight)return;lastHeight=height;\n  let reported=false;\n  try{if(typeof window.openai?.notifyIntrinsicHeight==='function'){window.openai.notifyIntrinsicHeight(height);reported=true;}}catch(_){/* Hosts without the OpenAI height channel use MCP below. */}\n  if(!reported)window.parent.postMessage({jsonrpc:'2.0',method:'ui/notifications/size-changed',params:{height}},'*');\n }\n function queueSize(){if(!sizeFrame)sizeFrame=requestAnimationFrame(reportSize);}\n new ResizeObserver(queueSize).observe(document.body);\n Promise.resolve(window.__ccBridgeReady).then(()=>{sizeReady=true;collapse();}).catch(()=>{});\n window.addEventListener('pageshow',()=>{lastHeight=-1;queueSize();});\n window.addEventListener('resize',()=>{lastHeight=-1;queueSize();});\n document.addEventListener('visibilitychange',()=>{lastHeight=-1;queueSize();});\n window.addEventListener('message',e=>{if(e.source===window.parent&&e.data?.method==='ui/notifications/host-context-changed'){lastHeight=-1;queueSize();}});\n accept(window.openai?.toolResponseMetadata||{});accept(window.openai?.toolOutput||{});\n setTimeout(()=>{if(!id){root.dataset.state='error';by('cc-task-summary').textContent='Task details unavailable in this view. No command was rerun.';}},5000);\n})();\n</script>"

BROWSER_UX_STYLE = '<style id="cc-browser-usability">\n#browser-help,#browser-freshness{margin:0 10px 7px;color:var(--cc-muted);font:11px/1.45 system-ui,sans-serif;overflow-wrap:anywhere}\n#browser-pane .browser-toolbar{flex-wrap:wrap!important;align-items:stretch!important;padding-top:0!important}\n#browser-pane .browser-toolbar button{min-height:42px!important;flex:1 1 110px;white-space:normal}\n#browser-pane .browser-toolbar #browser-take{flex:1 1 110px!important}\n#browser-stage{min-width:0;box-sizing:border-box;overscroll-behavior:contain}\nbody[data-cc-browser-zoom=true] #browser-stage{display:block!important;overflow:auto!important;max-height:300px!important}\nbody[data-cc-browser-zoom=true] #browser-stage img{display:block;width:200%!important;height:auto!important;max-width:none!important;max-height:none!important}\n#browser-zoom[aria-pressed=true]{border-color:var(--cc-cyan);background:var(--cc-card)}\n@media(max-width:540px){body[data-cc-browser-zoom=true] #browser-stage{max-height:280px!important}}\n</style>'
BROWSER_UX_RUNTIME = "<script id=\"cc-browser-usability-runtime\">\n(()=>{\n 'use strict';\n const by=id=>document.getElementById(id),screen=by('browser-screen'),stage=by('browser-stage'),toolbar=by('browser-refresh').parentElement,take=by('browser-take'),auto=by('browser-auto');\n const help=document.createElement('p');help.id='browser-help';help.textContent='Live preview. Ask ChatGPT to search or browse. Use privately for website controls, sign-in and approvals.';\n const fresh=document.createElement('p');fresh.id='browser-freshness';fresh.setAttribute('role','status');fresh.textContent='Waiting for a preview';\n const zoom=document.createElement('button');zoom.id='browser-zoom';zoom.type='button';zoom.textContent='Zoom in';zoom.setAttribute('aria-label','Zoom browser preview');zoom.setAttribute('aria-pressed','false');zoom.title='Magnify the preview, then scroll inside it to see the page';zoom.disabled=true;\n toolbar.insertBefore(zoom,take);\n stage.before(help,toolbar,fresh);\n let source='',updated='',zoomed=false;\n function resetZoom(){zoomed=false;document.body.dataset.ccBrowserZoom='false';zoom.setAttribute('aria-pressed','false');zoom.textContent='Zoom in';zoom.setAttribute('aria-label','Zoom browser preview');}\n zoom.addEventListener('click',()=>{if(zoom.disabled)return;zoomed=!zoomed;document.body.dataset.ccBrowserZoom=String(zoomed);zoom.setAttribute('aria-pressed',String(zoomed));zoom.textContent=zoomed?'Fit preview':'Zoom in';zoom.setAttribute('aria-label',zoomed?'Fit browser preview':'Zoom browser preview');if(!zoomed){stage.scrollLeft=0;stage.scrollTop=0;}window.dispatchEvent(new Event('resize'));});\n function sync(){\n  const visible=!screen.hidden&&!!screen.getAttribute('src');zoom.disabled=!visible;\n  if(!visible){source='';updated='';resetZoom();fresh.textContent=document.body.dataset.ccBrowserState==='awaiting_human'?'Private control · preview hidden':'No preview available';}\n  else{\n   const next=screen.getAttribute('src');if(next!==source){source=next;updated=new Date().toLocaleTimeString();}\n   const paused=auto.getAttribute('aria-pressed')==='false';fresh.textContent=(paused?'Preview paused':'Live preview')+' · updated '+updated;\n  }\n  if(take.textContent==='Take control'){take.textContent='Use privately';take.title='Open private browser control. The AI cannot see your private screen.';}\n }\n new MutationObserver(sync).observe(screen,{attributes:true,attributeFilter:['src','hidden']});\n new MutationObserver(sync).observe(auto,{attributes:true,attributeFilter:['aria-pressed']});\n new MutationObserver(sync).observe(take,{childList:true});\n document.addEventListener('visibilitychange',()=>{if(document.hidden)resetZoom();});\n sync();\n})();\n</script>"

BROWSER_JOURNEY_STYLE = '<style id="cc-browser-journey-style">\n#cc-browser-navigation{display:flex;flex-wrap:wrap;gap:6px;margin:0 10px 8px}\n#cc-browser-navigation button{min-height:42px;min-width:76px;flex:1 1 76px}\n#cc-browser-navigation-note,#cc-browser-navigation-message,#cc-browser-pages{margin:0 10px 8px;color:var(--cc-muted);font:11px/1.45 system-ui,sans-serif;overflow-wrap:anywhere}\n#cc-browser-pages ol{padding-left:20px;max-height:160px;overflow:auto}\n#cc-browser-pages li{padding:4px 0}#cc-browser-pages small{display:block}\n</style>'
BROWSER_JOURNEY_RUNTIME = "<script id=\"cc-browser-journey-runtime\">\n(()=>{\n 'use strict';\n const by=id=>document.getElementById(id),screen=by('browser-screen'),help=by('browser-help');\n const nav=document.createElement('div');nav.id='cc-browser-navigation';nav.setAttribute('role','group');nav.setAttribute('aria-label','Browser page navigation');\n const back=document.createElement('button'),forward=document.createElement('button');\n back.id='cc-browser-back';back.type=forward.type='button';back.textContent='Back';back.setAttribute('aria-label','Go to previous page');\n forward.id='cc-browser-forward';forward.textContent='Forward';forward.setAttribute('aria-label','Go to next page');nav.append(back,forward);\n const note=document.createElement('p');note.id='cc-browser-navigation-note';note.textContent='Refresh preview checks the screen only. Back and Forward revisit pages; they do not undo or repeat website actions.';\n const message=document.createElement('p');message.id='cc-browser-navigation-message';message.setAttribute('role','status');message.hidden=true;\n const pages=document.createElement('details');pages.id='cc-browser-pages';pages.hidden=true;\n const summary=document.createElement('summary');summary.textContent='Recent pages';const list=document.createElement('ol');pages.append(summary,list);\n help.after(nav,note,message,pages);\n let frame={},pending=false,generation=0,waitingForPreview=null;\n function sync(){\n  const unavailable=screen.hidden||!screen.getAttribute('src')||frame.state==='awaiting_human'||document.body.dataset.ccBrowserState==='unavailable';\n  back.disabled=unavailable||pending||frame.busy===true||frame.can_go_back!==true;\n  forward.disabled=unavailable||pending||frame.busy===true||frame.can_go_forward!==true;\n  if(unavailable){list.replaceChildren();pages.hidden=true;}\n }\n window.addEventListener('commandcore:browser-frame',event=>{\n  frame=event.detail||{};list.replaceChildren();if(frame.state==='awaiting_human'){message.hidden=true;waitingForPreview=null;}\n  if(waitingForPreview&&frame.busy!==true&&Number.isSafeInteger(frame.sequence)&&frame.sequence>waitingForPreview.after&&frame.action===waitingForPreview.action){message.hidden=false;message.textContent=waitingForPreview.action+'.';waitingForPreview=null;}\n  if(frame.state!=='awaiting_human'&&Array.isArray(frame.recent_pages)){\n   for(const page of frame.recent_pages.slice(-20)){\n    if(!page||typeof page.title!=='string'||typeof page.url!=='string')continue;\n    const li=document.createElement('li');li.textContent=page.title.slice(0,140)||'Page';\n    if(page.current===true){li.setAttribute('aria-current','page');li.append(' · current');}\n    try{const u=new URL(page.url);if(u.protocol!=='https:'||u.username||u.password)continue;const address=document.createElement('small');address.textContent=u.hostname+u.pathname.slice(0,180);li.append(address);}catch(_){continue;}\n    list.append(li);\n   }\n  }\n  pages.hidden=list.children.length===0;sync();\n });\n window.addEventListener('commandcore:viewer-changed',()=>{generation++;frame={};pending=false;waitingForPreview=null;message.hidden=true;list.replaceChildren();sync();});\n new MutationObserver(sync).observe(screen,{attributes:true,attributeFilter:['src','hidden']});\n async function navigate(name){\n  const button=name==='browser.back'?back:forward;if(button.disabled)return;\n  const current=generation,viewer=window.__ccBrowserViewerRef,completed=name==='browser.back'?'Previous page opened':'Next page opened';waitingForPreview={after:Number.isSafeInteger(frame.sequence)?frame.sequence:-1,action:completed};pending=true;sync();message.hidden=false;message.textContent='Opening recorded page…';let timeout;\n  try{\n   const response=await Promise.race([window.__ccCallTool(name,{session_ref:viewer||''}),new Promise((_,reject)=>{timeout=setTimeout(()=>reject(Error('response_delayed')),15000);})]);\n   if(current!==generation)return;\n   if(response?.isError||response?.result?.isError)throw Error('navigation_failed');\n   message.textContent=waitingForPreview?'Page opened. Updating preview…':completed+'.';\n  }catch(error){\n   if(current!==generation)return;\n   message.textContent=error.message==='response_delayed'?'Navigation response delayed. Refresh preview to check the current page before trying again.':'Navigation could not be confirmed. Refresh preview or ask ChatGPT to inspect the current page.';\n  }finally{\n   clearTimeout(timeout);\n   if(current===generation){pending=false;sync();by('browser-refresh').click();}\n  }\n }\n back.addEventListener('click',()=>navigate('browser.back'));forward.addEventListener('click',()=>navigate('browser.forward'));sync();\n})();\n</script>"


def _task_html(html: str) -> str:
    html = (
        html.replace(
            "const actionFailed=",
            "const manualNeeded=/^Manual step required/.test(browserAction); const actionFailed=",
            1,
        )
        .replace(
            'actionFailed?"Interaction failed":page.busy?',
            'manualNeeded?"Your action needed":actionFailed?"Interaction failed":page.busy?',
            1,
        )
        .replace(
            '(actionFailed?"Browser interaction failed: ":page.busy?"AI working: ":"AI control: ")',
            '(manualNeeded?"Your action needed: ":actionFailed?"Browser interaction failed: ":page.busy?"AI working: ":"Ready: ")',
            1,
        )
    )
    html = html.replace(
        "function show(data) {",
        'function show(data) { window.dispatchEvent(new CustomEvent("commandcore:browser-frame",{detail:data.structuredContent||{}}));',
        1,
    )
    html = html.replace(
        'appCapabilities:{availableDisplayModes:["inline","fullscreen"]}',
        'appCapabilities:{availableDisplayModes:["inline"]}',
    ).replace("UI 0.12.0 · build 1", "UI 0.12.0 · build 16")
    html = html.replace(
        "bounds.left-area.left+(bounds.width-width)/2+cursor.x*scale",
        "bounds.left-area.left+stage.scrollLeft+(bounds.width-width)/2+cursor.x*scale",
    ).replace(
        "bounds.top-area.top+(bounds.height-height)/2+cursor.y*scale",
        "bounds.top-area.top+stage.scrollTop+(bounds.height-height)/2+cursor.y*scale",
    )
    return (
        html.replace(
            "</head>",
            TASK_STYLE + BROWSER_UX_STYLE + BROWSER_JOURNEY_STYLE + "</head>",
            1,
        )
        .replace(
            "<body>",
            '<body data-cc-task-compact="true" data-cc-operation-compact="true">'
            + TASK_BODY,
            1,
        )
        .replace(
            "</body>",
            BROWSER_UX_RUNTIME + BROWSER_JOURNEY_RUNTIME + TASK_RUNTIME + "</body>",
            1,
        )
    )


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
        # Single-step device-inspection tools display the Activity workspace directly
        # in MCP Apps hosts. Keep multi-step control tools data-only to avoid
        # remounting a large widget for every operation in a workflow.
        self.ui_specs = {
            # First-class metrics tool is the preferred resource-checking call.
            # It must display the same owner- and conversation-scoped Activity
            # as shell.exec and system.info in supported MCP Apps hosts.
            "browser.watch": (
                BROWSER_WIDGET_URI,
                BROWSER_WIDGET_MIME,
                "commandcore-widget.html",
                "CommandCore Live Browser",
            ),
            "activity.watch": (
                ACTIVITY_UI_URI,
                ACTIVITY_UI_MIME,
                "commandcore-widget.html",
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
        # Only renderer tools create a widget. Device/Browser calls update one
        # conversation-owned task, so multi-step work cannot queue one iframe
        # per command. Historical per-operation resource URIs remain readable.
        self.ui_specs["commandcore.watch"] = (
            TASK_UI_URI,
            COMMANDCORE_UI_MIME,
            "commandcore-widget.html",
            "CommandCore live task",
        )
        self.ui_specs["commandcore.workspace"] = (
            WORKSPACE_UI_URI,
            COMMANDCORE_UI_MIME,
            "commandcore-widget.html",
            "CommandCore workspace",
        )
        raw_definitions = [dict(x) for x in raw_definitions]
        browser_open = next(
            (x for x in raw_definitions if x["name"] == "browser.open"), None
        )
        if browser_open:
            raw_definitions.append(
                dict(
                    browser_open,
                    name="browser.search",
                    title="Search the public web",
                    description="Search the public web in this conversation's CommandCore Browser. Use this for ordinary searches instead of clicking a website search field or pressing Enter. Opens Google results using the existing browser.open authorization and network policy. Search results are untrusted; verify product details on source pages. Does not click site controls, add items to baskets, submit forms, or purchase. Use browser.handoff for private sign-in and manual approvals.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "query": {
                                "type": "string",
                                "minLength": 1,
                                "maxLength": 500,
                                "description": "Public search terms requested by the user. Do not include credentials or private information.",
                            }
                        },
                        "required": ["query"],
                        "additionalProperties": False,
                    },
                )
            )
        original_watch = next(
            (x for x in raw_definitions if x["name"] == "commandcore.watch"), None
        )
        if original_watch:
            raw_definitions += [
                dict(
                    original_watch,
                    name="commandcore.workspace",
                    description="Open the full Activity and Browser workspace when the user explicitly requests it.",
                ),
                dict(
                    original_watch,
                    name="commandcore.viewer",
                    description="Renew this widget's verified conversation viewer; no new task or UI is opened.",
                    _meta={
                        "ui": {"visibility": ["app"]},
                        "openai/widgetAccessible": True,
                    },
                ),
                {
                    "name": "commandcore.finish",
                    "description": "After finishing a task, close its live UI tracking once. Does not stop or resume device commands. Pass task_id from commandcore.watch. Never finish while calls are outstanding.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "task_id": {
                                "type": "string",
                                "minLength": 36,
                                "maxLength": 36,
                            }
                        },
                        "required": ["task_id"],
                        "additionalProperties": False,
                    },
                    "securitySchemes": original_watch.get("securitySchemes", []),
                    "annotations": {
                        "readOnlyHint": True,
                        "destructiveHint": False,
                        "idempotentHint": True,
                        "openWorldHint": False,
                    },
                },
            ]
        if not hasattr(tools, "_ui_tasks"):
            tools._ui_tasks = UITaskLedger()
        self.tasks = tools._ui_tasks
        self.tasks.bind_activity(getattr(tools, "live_activity", None))
        watch_first = (
            "Before a new user device/Browser task, call commandcore.watch ONCE to show one compact live task, then run the ordinary tools. "
            "Reuse that task for all steps, including Browser actions; do not call watch between steps or repeatedly within one task. "
            "Ordinary operations return data and update that task without creating a new card. "
            "After the last call returns, call commandcore.finish once with its task_id. Never retry a timed-out write automatically."
        )
        for source in raw_definitions:
            entry = json.loads(json.dumps(source))
            tool_name = entry["name"]
            if tool_name == "commandcore.watch":
                entry["description"] = (
                    "Start one compact live task before a new user device or Browser task. Returns task_id; reuse it through all steps and finish once at the end. The card expands to Activity or Browser. "
                    + watch_first
                )
            elif tool_name in OPERATION_TOOLS:
                entry["description"] = entry["description"] + " " + watch_first
            if name == "commandcore" and tool_name in {
                "devices.list",
                "devices.select",
                "system.metrics",
                "shell.exec",
                "commandcore.watch",
            }:
                entry["description"] += (
                    " Legacy endpoint /mcp. For new ChatGPT conversations prefer "
                    "the canonical CommandCore /mcp/core connection."
                )
            entry.setdefault("_meta", {}).setdefault("ui", {}).setdefault(
                "visibility", ["model", "app"]
            )
            entry["_meta"]["openai/widgetAccessible"] = True
            if tool_name == "activity.feed":
                entry["inputSchema"]["properties"]["task_id"] = {
                    "type": "string",
                    "minLength": 36,
                    "maxLength": 36,
                    "description": "Verified task boundary issued by commandcore.watch; never an account-wide lookup.",
                }
            spec = self.ui_specs.get(entry["name"])
            if spec:
                uri, mime, asset, title = spec
                meta = dict(entry.get("_meta") or {})
                meta["ui"] = {"resourceUri": uri, "visibility": ["model", "app"]}
                # Backward compatibility for existing MCP Apps hosts that
                # still index the deprecated flat resource pointer.
                meta["ui/resourceUri"] = uri
                meta["openai/outputTemplate"] = uri
                meta["openai/widgetAccessible"] = True
                entry["_meta"] = meta
                self.ui_resources[uri] = spec
            self.definitions.append(entry)
        if self.ui_resources:
            for uri, (mime, asset, title) in LEGACY_UI_RESOURCES.items():
                # Only register resource types present in this instance's
                # advertised tool set: do not leak Browser UI in disabled mode.
                current_tool = {
                    "browser-widget.html": "browser.watch",
                    "activity-widget.html": "activity.watch",
                    "commandcore-widget.html": "commandcore.watch",
                }[asset]
                if any(tool["name"] == current_tool for tool in self.definitions):
                    self.ui_resources.setdefault(uri, (uri, mime, asset, title))
        self.browser_widget_available = any(
            tool["name"] == "browser.watch" for tool in self.definitions
        )
        self.activity_widget_available = any(
            tool["name"] == "activity.watch" for tool in self.definitions
        )
        self.name = name
        self.icons = icons

    async def handle(self, request: Request, principal: Principal) -> JSONResponse:
        self.metrics.inc("commandcore_mcp_requests_total")
        try:
            body = await request.json()
        except Exception:  # noqa: BLE001 - fail-closed boundary or best-effort cleanup
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
        record_ui_resource_request(
            method=method,
            uri=params.get("uri"),
            assets=self.ui_resources,
            resolve_asset=web_asset,
            modern=modern,
            method_header_matches=request.headers.get("mcp-method") in (None, method),
        )
        if modern:
            if method in {"resources/list", "resources/read"}:
                # Backported from verified canonical production UI fix.
                # UI resources are read-only and require a valid Principal
                # from the authenticated MCP entry point. Some clients omit
                # the modern Mcp-Method/_meta headers for resource fetches.
                # Reject supplied headers if they disagree with the request.
                method_header = request.headers.get("mcp-method")
                supplied_meta = params.get("_meta")
                if (
                    version_header != MODERN_PROTOCOL
                    or (method_header and method_header != method)
                    or (
                        isinstance(supplied_meta, dict)
                        and supplied_meta.get(
                            "io.modelcontextprotocol/protocolVersion",
                            MODERN_PROTOCOL,
                        )
                        != MODERN_PROTOCOL
                    )
                ):
                    self.metrics.inc("commandcore_mcp_errors_total")
                    return _rpc_error(req_id, -32020, "Invalid UI resource request")
            else:
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
                    "Reuse the returned selection_id in subsequent device tools. Explicit device_id overrides selection_id. "
                    "Call commandcore.watch once at the start of a user device/Browser task. "
                    "Reuse its single live task card for every step; ordinary tools return data. "
                    "Call commandcore.finish once after the last action returns. "
                    "Open commandcore.workspace only for an explicitly requested full workspace. "
                    "Use browser.search for public searches, browser.links then browser.follow to open visible results without coordinates, and browser.back/browser.forward to revisit public pages. Never guess a result URL or replay an uncertain submission. Use browser.handoff for private "
                    "sign-in and approvals. Tool success is not visual UI acceptance."
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
                    "instructions": (
                        "Use devices.select and pass selection_id to device tools. "
                        "Call commandcore.watch once before a new user device/Browser task. "
                        "Reuse its live card for all steps and call commandcore.finish once at the end. "
                        "Ordinary tools return data. Use commandcore.workspace for an explicitly requested full workspace. "
                        "Request browser.handoff for private approval."
                    ),
                },
            )

        if method == "notifications/initialized":
            return JSONResponse({}, status_code=202)

        if method == "resources/list":
            if not self.ui_resources:
                return _rpc_error(req_id, -32601, "Resources unavailable")
            result = {
                "resources": [
                    {
                        "uri": uri,
                        "name": spec[3],
                        "mimeType": spec[1],
                        "_meta": {
                            **(
                                {
                                    "openai/widgetMinFrameHeight": 1,
                                    "openai/widgetHeightHint": 112,
                                }
                                if uri in TASK_UI_URIS
                                else {}
                            ),
                            "ui": {
                                "prefersBorder": True,
                                "csp": {"connectDomains": [], "resourceDomains": []},
                            },
                        },
                    }
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
                        "text": _task_html(web_asset(asset).read_text(encoding="utf-8"))
                        if uri in TASK_UI_URIS
                        else _operation_html(
                            web_asset(asset).read_text(encoding="utf-8")
                        )
                        if uri in OPERATION_UI_URIS
                        else web_asset(asset).read_text(encoding="utf-8"),
                        "_meta": {
                            **(
                                {
                                    "openai/widgetMinFrameHeight": 1,
                                    "openai/widgetHeightHint": 112,
                                }
                                if uri in TASK_UI_URIS
                                else {}
                            ),
                            "ui": {
                                "prefersBorder": True,
                                "csp": {"connectDomains": [], "resourceDomains": []},
                            },
                            "openai/ui": {
                                "availableDisplayModes": ["inline"]
                                if uri in TASK_UI_URIS
                                else ["inline", "fullscreen"]
                            },
                        },
                    }
                ]
            }
            if modern:
                result["ttlMs"] = 0
                result["cacheScope"] = "private"
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
            call_meta = (
                params.get("_meta") if isinstance(params.get("_meta"), dict) else {}
            )
            host_session = call_meta.get("openai/session")
            progress_token = (
                (params.get("_meta") or {}).get("progressToken")
                if isinstance(params.get("_meta"), dict)
                else None
            )
            if "text/event-stream" in request.headers.get("accept", "") and isinstance(
                progress_token, (str, int)
            ):
                return self._stream_call(
                    principal,
                    name,
                    args,
                    req_id,
                    modern,
                    progress_token,
                    host_session=host_session,
                )
            try:
                payload = await self._call_tools(principal, name, args, host_session)
                # Emit a live release fingerprint in model-readable viewer results.
                # Unlike tool descriptor UI metadata, this information comes from the
                # current server execution and does not depend on host schema refresh.
                if name in {
                    "commandcore.watch",
                    "commandcore.workspace",
                    "activity.watch",
                    "browser.watch",
                } and isinstance(payload, dict):
                    spec = self.ui_specs.get(name)
                    payload = dict(payload)
                    payload["ui_build"] = "0.12.0+b16"
                    payload["ui_resource_uri"] = spec[0] if spec else None
                result = _tool_result(payload, modern)
                spec = self.ui_specs.get(name)
                if spec and spec[0] in self.ui_resources:
                    meta = dict(result.get("_meta") or {})
                    meta["ui"] = {"resourceUri": spec[0]}
                    meta["ui/resourceUri"] = spec[0]
                    meta["openai/outputTemplate"] = spec[0]
                    # On direct execution-tool rendering, bind the embedded Activity
                    # panel to the verified ChatGPT conversation, not account-wide
                    # activity. This metadata is widget-only, never command output.
                    if name in OPERATION_TOOLS:
                        meta["commandcore/viewer"] = (
                            self.tools.live_activity.issue_viewer(
                                principal, host_session
                            )
                        )
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
                if name in OPERATION_TOOLS:
                    result["_meta"] = {
                        "commandcore/operation": {
                            "tool": name,
                            "kind": "browser"
                            if name.startswith("browser.")
                            else "activity",
                            "status": "error",
                        }
                    }
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

    def _task_context(self, principal, args, host_session):
        from .auth import READ_SCOPE, scope_allows

        if not (
            principal.auth_kind == "oauth2"
            and principal.issuer
            and principal.client_id not in {"", "unknown", "oauth-client"}
            and scope_allows(principal.scopes, READ_SCOPE)
        ):
            raise ToolError(
                "invalid_task_view", "Verified conversation context required"
            )
        host_tag = self.tools.live_activity.session_tag(host_session)
        if "session_ref" in args:
            tag = (
                self.tools.live_activity.resolve_viewer(principal, args["session_ref"])
                if isinstance(args["session_ref"], str)
                else None
            )
        else:
            tag = self.tools.live_activity.session_tag(host_session)
        if host_tag and tag and host_tag != tag:
            raise ToolError(
                "invalid_task_view", "Task unavailable in this conversation"
            )
        if not tag:
            raise ToolError(
                "invalid_session_view", "Verified conversation context required"
            )
        return self.tasks.owner(principal), tag

    @staticmethod
    def _task_store(method, *args):
        import sqlite3

        try:
            return method(*args)
        except (OSError, sqlite3.Error):
            raise ToolError(
                "task_tracking_unavailable",
                "Task tracking is unavailable; no new device command was started",
            )

    def _record_task_call(self, call, status, device=""):
        import sqlite3

        try:
            self.tasks.end_call(call, status, device)
            return True
        except (OSError, sqlite3.Error):
            # Never erase an actual device result or encourage duplicate writes
            # because the auxiliary UI summary could not be updated.
            return False

    async def _call_tools(self, principal, name, args, host_session):
        if name == "commandcore.finish":
            owner, tag = self._task_context(principal, args, host_session)
            return {
                "task": self._task_store(
                    self.tasks.finish, owner, tag, args.get("task_id")
                ),
                "state": "task_closed",
                "mode": "read_only",
            }
        task_row = None
        if name == "activity.feed" and "task_id" in args:
            owner, tag = self._task_context(principal, args, host_session)
            task_row = self._task_store(self.tasks.get, owner, tag, args["task_id"])
            args = {key: value for key, value in args.items() if key != "task_id"}
            if args.get("view", "conversation") != "conversation":
                raise ToolError(
                    "invalid_task_view", "Task activity requires conversation scope"
                )
            args = dict(args, view="conversation", limit=50)
        mapped = (
            "commandcore.watch"
            if name == "commandcore.workspace"
            else "activity.watch"
            if name == "commandcore.viewer"
            else name
        )
        call = None
        if name in TASK_ACTION_TOOLS:
            try:
                owner, tag = self._task_context(
                    principal,
                    args if name in {"browser.back", "browser.forward"} else {},
                    host_session,
                )
            except ToolError:
                pass  # UI tracking never broadens or replaces device authorization.
            else:
                call = self._task_store(self.tasks.begin_call, owner, tag, name)
        try:
            payload = await self._call_tools_impl(principal, mapped, args, host_session)
        except BaseException as exc:
            self._record_task_call(
                call,
                "interrupted"
                if isinstance(exc, BaseException) and not isinstance(exc, Exception)
                else "error",
            )
            raise
        if call:
            operation = payload.get("_ui_operation") or {}
            status = payload.get("status") or (
                "error" if payload.get("error") else "returned"
            )
            if not self._record_task_call(call, status, operation.get("device", "")):
                payload = dict(
                    payload,
                    ui_tracking_warning="Task summary unavailable; operation result retained. Do not repeat a write based on this warning.",
                )
        if name == "commandcore.watch":
            payload = dict(payload)
            try:
                owner, tag = self._task_context(principal, {}, host_session)
                task = self._task_store(self.tasks.start, owner, tag)
                payload.update(
                    task_available=True,
                    task_id=task,
                    task=self.tasks.public(
                        self._task_store(self.tasks.get, owner, tag, task)
                    ),
                )
            except ToolError:
                payload.update(task_available=False)
        if task_row is not None:
            task_row = self._task_store(self.tasks.get, owner, tag, task_row["id"])
            from datetime import datetime

            def in_task(event):
                try:
                    started = event.get("started_at")
                    timestamp = (
                        datetime.fromisoformat(
                            started.replace("Z", "+00:00")
                        ).timestamp()
                        if isinstance(started, str)
                        else float(started)
                    )
                    return task_row["started"] <= timestamp and (
                        task_row["ended"] is None or timestamp <= task_row["ended"]
                    )
                except (ValueError, TypeError, OverflowError):
                    return False

            payload = dict(payload)
            payload["events"] = [
                event for event in payload.get("events", []) if in_task(event)
            ]

            # The live feed is bounded and transient. Preserve the existing
            # detailed records where present; fill evicted calls from the
            # private durable ledger, without retaining command arguments.
            saved = self._task_store(self.tasks.history, owner, tag, task_row["id"])

            def seconds(value):
                try:
                    return (
                        datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
                        if isinstance(value, str)
                        else float(value)
                    )
                except (ValueError, TypeError, OverflowError):
                    return None

            def matches(event, call):
                stamp = seconds(event.get("started_at"))
                start, end = seconds(call["started_at"]), seconds(call["finished_at"])
                return (
                    event.get("tool")
                    == (
                        "browser.open"
                        if call["tool"] == "browser.search"
                        else call["tool"]
                    )
                    and stamp is not None
                    and start <= stamp
                    and (end is None or stamp <= end)
                )

            payload["events"] += [
                call
                for call in saved
                if not any(matches(event, call) for event in payload["events"])
            ]
            payload["events"] = sorted(
                payload["events"],
                key=lambda e: seconds(e.get("started_at")) or 0,
                reverse=True,
            )[:50]
            payload["task"] = self.tasks.public(task_row)
        return payload

    async def _call_tools_impl(self, principal, name, args, host_session):
        if name == "browser.search":
            from urllib.parse import urlencode

            query = args.get("query") if isinstance(args, dict) else None
            if (
                not isinstance(args, dict)
                or set(args) != {"query"}
                or not isinstance(query, str)
                or not 1 <= len(query) <= 500
                or not query.strip()
                or any(ord(char) < 32 or ord(char) == 127 for char in query)
            ):
                raise ToolError(
                    "invalid_arguments",
                    "query must be 1-500 characters of public search terms, without control characters or extra fields",
                )
            # Delegate to the existing ToolService entry point. This retains
            # scope checks, egress restrictions, conversation ownership,
            # pause/private-handoff rules, audit and durable session handling.
            name, args = (
                "browser.open",
                {
                    "url": "https://www.google.com/search?"
                    + urlencode({"q": query.strip()})
                },
            )
        sink = {}
        token = operation_ui_context.set(sink)
        try:
            if host_session is None:
                payload = await self.tools.call(principal, name, args)
            else:
                payload = await self.tools.call(
                    principal, name, args, host_session=host_session
                )
            if name in OPERATION_TOOLS and isinstance(payload, dict):
                payload = dict(payload)
                viewer = self.tools.live_activity.issue_viewer(principal, host_session)
                operation = {
                    "tool": name,
                    "kind": "browser" if name.startswith("browser.") else "activity",
                    "status": "returned",
                }
                tag = self.tools.live_activity.session_tag(host_session)
                # Match the request-local immutable operation ID, never the latest
                # account event, tool name or timestamp. Reuse feed authorization.
                if tag and sink.get("operation_id"):
                    snapshot = self.tools.live_activity.snapshot(
                        principal,
                        [],
                        self.tools.db.list_accessible_devices(principal.subject),
                        50,
                        include_details=False,
                        session_tag=tag,
                    )
                    row = next(
                        (
                            x
                            for x in snapshot["events"]
                            if x.get("operation_id") == sink["operation_id"]
                        ),
                        None,
                    )
                    if row:
                        operation.update(row)
                        # Detailed traces follow the existing STANDARD OAuth rule.
                        from .auth import STANDARD_SCOPE, scope_allows

                        if (
                            principal.auth_kind == "oauth2"
                            and principal.issuer
                            and principal.client_id
                            and scope_allows(principal.scopes, STANDARD_SCOPE)
                        ):
                            detailed = self.tools.live_activity.snapshot(
                                principal,
                                [],
                                self.tools.db.list_accessible_devices(
                                    principal.subject
                                ),
                                50,
                                include_details=True,
                                session_tag=tag,
                            )
                            exact = next(
                                (
                                    x
                                    for x in detailed["events"]
                                    if x.get("operation_id") == sink["operation_id"]
                                ),
                                None,
                            )
                            if exact:
                                operation.update(exact)
                payload["_ui_operation"] = operation
                payload["_ui_viewer"] = viewer
            return payload
        finally:
            operation_ui_context.reset(token)

    def _stream_call(
        self,
        principal,
        name,
        args,
        req_id,
        modern,
        progress_token,
        *,
        host_session=None,
    ):
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
                        payload = await self._call_tools(
                            principal, name, args, host_session
                        )
                        # Emit a live release fingerprint in model-readable viewer results.
                        # Unlike tool descriptor UI metadata, this information comes from the
                        # current server execution and does not depend on host schema refresh.
                        if name in {
                            "commandcore.watch",
                            "commandcore.workspace",
                            "activity.watch",
                            "browser.watch",
                        } and isinstance(payload, dict):
                            spec = self.ui_specs.get(name)
                            payload = dict(payload)
                            payload["ui_build"] = "0.12.0+b16"
                            payload["ui_resource_uri"] = spec[0] if spec else None
                        result = _tool_result(payload, modern)
                        spec = self.ui_specs.get(name)
                        if spec and spec[0] in self.ui_resources:
                            meta = dict(result.get("_meta") or {})
                            meta["ui"] = {"resourceUri": spec[0]}
                            meta["ui/resourceUri"] = spec[0]
                            meta["openai/outputTemplate"] = spec[0]
                            if name in OPERATION_TOOLS:
                                meta["commandcore/viewer"] = (
                                    self.tools.live_activity.issue_viewer(
                                        principal, host_session
                                    )
                                )
                            result["_meta"] = meta
                        if modern:
                            result = _with_server_info(
                                result, self.server_version, self.name, self.icons
                            )
                    except ToolError as exc:
                        result = _tool_error(exc.code, exc.message, modern)
                        if name in OPERATION_TOOLS:
                            result["_meta"] = {
                                "commandcore/operation": {
                                    "tool": name,
                                    "kind": "browser"
                                    if name.startswith("browser.")
                                    else "activity",
                                    "status": "error",
                                }
                            }
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
