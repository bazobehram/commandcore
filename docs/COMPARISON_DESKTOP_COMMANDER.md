# CommandCore and Desktop Commander

Last upstream review for this document: **2026-10-05**.

CommandCore is not a fork of Desktop Commander MCP. Both projects let AI clients
operate computers, but they emphasize different layers of the system.

This page is a factual selection guide, not a benchmark or a claim that one
project is universally better.

## Summary

| Area | CommandCore | Desktop Commander MCP |
|---|---|---|
| Primary focus | Self-hosted multi-device remote control plane | Mature local MCP computer tools plus a hosted Remote MCP path |
| Remote server | Shipped as part of the self-hostable project | Upstream docs direct remote users to mcp.desktopcommander.app |
| Device connection | Outbound authenticated Agent connection | Remote Device connects to the hosted Remote MCP service |
| Agent/runtime | Native Rust agent plus Python reference | Node.js package; Remote Device requires Node.js 18+ |
| Device identity | Local Ed25519 device identity | OAuth device authorization for Remote Device |
| Authorization | OAuth scopes + explicit device grants + server profile + local ceiling | Local guardrails and remote account/device authorization |
| Linux privilege separation | Optional separate privileged helper for FULL_CONTROL | Commands execute under the local user; upstream recommends OS isolation for stronger containment |
| Fleet lifecycle | Signed release, health validation, rollback, canary/ring primitives | Not CommandCore's comparison target; Desktop Commander focuses on its tool/runtime lifecycle |
| Rich document tools | Limited today | Strong Excel, PDF, DOCX, preview, and editing support |
| Windows/macOS maturity | Windows preview; macOS planned | More mature cross-platform local tool support |
| Repository license | AGPL-3.0-or-later | MIT |

## Where Desktop Commander is stronger today

Desktop Commander's public README documents a broad local tool surface including:

- interactive terminal/process workflows;
- file editing and recursive search;
- Excel read/write/edit/search;
- PDF read/create/modify workflows;
- DOCX read/create/edit/search;
- file preview UI;
- broad local-client installation guidance.

If the goal is rich local document/file manipulation on one workstation,
Desktop Commander may be the more complete tool today.

Its security documentation also clearly states that allowed directories and the
command blocklist are safety guardrails rather than a sandbox, and recommends
Docker/VM isolation when a connected AI client must not reach the wider machine.

## Where CommandCore is different

CommandCore was designed around remote control-plane concerns:

- one MCP endpoint for multiple authorized devices;
- a self-hosted server and device registry;
- per-account device grants;
- device-local permission ceilings;
- outbound device connectivity;
- locally generated cryptographic device identity;
- optional privilege separation for Linux FULL_CONTROL;
- signed Agent distribution and rollback;
- fleet/canary rollout primitives;
- explicit audit and execution identity.

CommandCore's Agent protocol is deliberately separate from MCP. AI clients speak
MCP to the control plane; devices speak the CommandCore Agent protocol to the
server.

## Remote architecture

Desktop Commander's documented remote path is:

~~~text
AI client
  -> Desktop Commander Remote MCP
  -> Remote Device
  -> local Desktop Commander MCP server
~~~

The public documentation points users to the hosted endpoint at
mcp.desktopcommander.app. This document does not infer licensing or deployment
properties of server-side components that are not explicitly documented in the
reviewed repository.

CommandCore's path is:

~~~text
AI / MCP client
  -> self-hosted CommandCore server
  -> outbound authenticated Agent connection
  -> device executor
  -> optional local privileged helper
~~~

## Can they be used together?

Potentially. CommandCore's executor boundary can support optional adapters in the
future. A Desktop Commander adapter could expose selected mature local document
capabilities behind CommandCore's identity, grant, and transport model without
making Desktop Commander a required dependency.

No Desktop Commander source is currently copied or vendored by CommandCore.

## Upstream material reviewed

Desktop Commander MCP repository:

- https://github.com/wonderwhy-er/DesktopCommanderMCP
- README.md
- SECURITY.md
- LICENSE
- src/remote-device/README.md
- package.json

At the time of review, the repository declared the MIT License and package
version 0.2.52. Re-check upstream before relying on time-sensitive details.
