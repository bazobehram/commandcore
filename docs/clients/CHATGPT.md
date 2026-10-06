# ChatGPT

Status: **LIVE VALIDATED** against a real remote CommandCore deployment.

CommandCore treats ChatGPT as one MCP client, not as an architectural dependency.

## Endpoint

Connect ChatGPT to the deployment's HTTPS MCP resource:

~~~text
https://commandcore.example.com/mcp
~~~

The deployment must expose valid OAuth protected-resource metadata and use an
OAuth/OIDC provider compatible with the client flow.

## Authorization

Start with the smallest useful scopes:

~~~text
commandcore:read
commandcore:standard
offline_access
~~~

Do not grant commandcore:full or administrative authority unless the deployment,
device-local policy, and intended client workflow all require it.

The effective device authority is still capped by the explicit account-to-device
grant and the device-local ceiling.

## Acceptance evidence

The project has validated the following through a real ChatGPT conversation using
OAuth and the remote MCP endpoint:

- authenticated identity inspection;
- devices.list;
- devices.select;
- system.info;
- filesystem read;
- STANDARD shell execution on an explicitly selected device.

That acceptance proves the CommandCore path, not every ChatGPT account, plan,
workspace policy, platform, or future product configuration. Client capabilities
can change independently of CommandCore.

## Validation checklist for a new deployment

1. Connect the remote MCP endpoint.
2. Complete OAuth login.
3. Verify auth.whoami shows only intended scopes and grants.
4. Run devices.list.
5. Select a non-critical test device.
6. Run system.info.
7. Read a harmless file such as /etc/hostname on Linux.
8. If STANDARD is intended, run a harmless command such as hostname.
9. Confirm audit records identify the account, device, and execution.
10. Revoke the device grant and verify access is denied.

Never use production FULL_CONTROL as the first integration test.
