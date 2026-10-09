# Unified Live Views — staging acceptance and release gates

**Status:** optional developer preview, not a supported multi-user production browser.
This repository supplies self-hosted source code. It is not connected to any
particular author's private CommandCore deployment, credentials or device grants.
GitHub push, CI success and merges **must not deploy to private production**.

## Unified MCP Apps viewer

- `commandcore.watch`: a single MCP Apps resource
  `ui://commandcore/live-views-v1.html`, displaying Activity and (if the
  browser worker is configured) Browser tabs.
- `activity.watch`: independent activity viewer, available with
  `commandcore:read`.
- `browser.watch`: independent browser screenshot monitor, requiring
  `commandcore:standard` and an active browser session.
- `commandcore.watch` requires only `commandcore:read`. The Browser tab does
  **not** expand that scope; `browser.observe` and `browser.handoff` are
  separately checked by the server for `commandcore:standard`.
- The activity feed exposes operation type, authorized device, state, time and
  duration only. No command text, path, arguments, output or secrets.
- The browser page is untrusted. The viewport is a screenshot, not live remote
  video. Auto-refresh is off by default; user action is required to enable it.
- Human control uses a short-lived, same-account, authenticated handoff URL.
  The underlying AI session remains paused until the human explicitly resumes
  it in the CommandCore operator console.

The MCP Apps viewer does not modify ChatGPT's Thinking display. The client
must support MCP Apps and mount the resource. Background/hidden iframe polling
may stop.

## Tested in separate local staging, October 9, 2026

A disposable CommandCore instance and an independent Steel container were
started on an isolated Docker project network. The CommandCore HTTP port
was published only on `127.0.0.1:3898`; it had a separate ephemeral token,
temporary SQLite database and no enrolled devices or production Agent keys.

Actual HTTP/MCP acceptance verified:
1. Both browser and activity tools on the same `/mcp/core` surface.
2. Resource discovery and HTML resource reading for the two individual widgets.
3. `activity.watch` metadata and read-only tool output.
4. `browser.open` and `browser.observe` on `https://example.com/` with a real
   PNG response and the expected title.
5. `browser.watch` resource metadata, activity history for browser.open,
   sensitive argument redaction and acknowledged `browser.close`.
6. A Steel CDP host-header compatibility fix, verified with its **Docker DNS
   service name** rather than a manually substituted container IP.

The unified `commandcore.watch` widget is also subject to MCP resource,
tool-response and JavaScript host-bridge regression tests; a genuine ChatGPT
mobile client has **not** mounted this widget yet.

## Reproducible smoke tests

- `node scripts/activity_widget_smoke.mjs`
- `node scripts/browser_widget_smoke.mjs`
- `node scripts/live_views_widget_smoke.mjs`
- `pytest -q tests/test_live_activity.py tests/test_browser_widget.py
  tests/test_live_views_integration.py tests/test_visual_browser_poc.py`
- `make lint && make format-check && make test`

Do not run a browser smoke against personal logged-in websites. A disposable,
loopback-only staging environment is required for networked browser tests.

## Security blockers before a general release

- **High:** Steel's current shared CDP runtime was observed to leak browser
  state across different API session IDs. The gateway therefore permits one
  active owner only. This is not multi-tenant isolation.
- **High:** URL validation is not network egress control. Production use needs
  a tested outbound firewall, private/loopback/metadata address blocking,
  redirect and subresource policies, downloads and WebSocket restrictions.
- **High:** Do not browse banking, personal logins, stored profiles or secrets
  with this experimental browser configuration.
- **Medium:** Verify OAuth issuer/client identity consistency for widget tool
  calls, permission ceilings and token expiry in the actual ChatGPT connection.
- **Medium:** Verify authenticated human takeover on real HTTPS, mobile UX,
  refresh/reconnect, accessibility and rate limits.
- **Medium:** In-flight activity uses process-local memory; multi-process
  installations need shared state or event transport for consistent timelines.
- **Release gate:** GitHub CI and security checks must all pass at the unified
  branch head; stage tests do not prove ChatGPT mobile mounting.

Deployment to any private CommandCore instance requires separate explicit
approval, backup and rollback planning. The default browser feature remains
**disabled**. There is no GitHub-to-production auto-deploy mechanism in this code.
