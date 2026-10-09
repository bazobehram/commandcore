# Live Activity in ChatGPT (experimental)

CommandCore already records device Activity Events and owner-scoped audit
metadata. The optional `activity.watch` tool provides a read-only MCP Apps
timeline for those operations.

A typical flow is:

1. The user asks the AI to open **CommandCore Live Activity**.
2. The client calls `activity.watch`, which advertises
   `ui://commandcore/activity-view-v1.html`.
3. The ChatGPT-compatible widget calls `activity.feed` every three seconds
   while visible, or when the user presses Refresh.
4. The same owner can see **running** operations, followed by completed/failed
   historical audit entries with device, tool and elapsed time.

The feed never exposes shell command text, filesystem paths, file contents,
environment variables, stdout/stderr, agent identities, credentials, tokens or
free-form remote error messages. Arguments are deliberately redacted. A
separate explicitly opted-in path display could be designed later.

## Scope

- Both the ordinary and Core MCP surfaces expose `activity.feed` and
  `activity.watch`.
- Requires only `commandcore:read`; it never grants the ability to execute
  commands or modify devices.
- Historical audit events are filtered by the authenticated owner, and
  device-related events are shown only when the owner **currently** has access
  to that device.
- In-progress events are additionally filtered by issuer and subject.
- Polling `activity.feed` is not itself written to the audit trail.
- The process-local running-operation map is not durable across server
  restarts. Historical audit events survive restarts.
- Calls through other connectors (e.g., direct GitHub tools) and local
  assistant reasoning do not appear. Only CommandCore tools are tracked.

## Visibility limits

A widget is **not** the ChatGPT Thinking pane or native tool-call
progress renderer. A client must mount the MCP Apps resource and leave it
visible to receive polling updates. Some hosts pause hidden/background
iframes; the panel therefore does not guarantee uninterrupted telemetry.
No remote browser screen capture is included in this activity timeline.
The separate visual-browser preview implements screenshots.

## Read-only example

```text
activity.watch {}
activity.feed {"limit": 25}
```

A valid feed row contains only `id`, `tool`, `device`, `status`,
`started_at` and `duration_ms`. The UI displays current running operations
before their audit entries appear.

## Release gate

Before enabling on a real ChatGPT connection, test against actual OAuth,
the relevant account grants, simultaneous running operations, multi-account
isolation, UI mounting, auto-refresh behavior on mobile and full screen,
and the repository CI/security checks.
