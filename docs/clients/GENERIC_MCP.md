# Generic MCP clients

CommandCore exposes one remote MCP endpoint for all supported clients:

~~~text
https://commandcore.example.com/mcp
~~~

Replace the example host with the deployment's URL.

## Requirements

A client must support the MCP transport exposed by the CommandCore server and the
deployment's authorization method. Production internet-facing deployments should
use HTTPS and OAuth/OIDC.

## Minimum acceptance

For a new client, validate in this order:

1. protocol initialize;
2. tools/list;
3. auth.whoami when OAuth is enabled;
4. devices.list;
5. devices.select;
6. system.info on a non-critical test device;
7. harmless filesystem read;
8. harmless STANDARD action only if STANDARD access is intended;
9. device-grant revocation and denial.

Do not start validation with FULL_CONTROL, package management, service mutation,
reboot, shutdown, destructive filesystem operations, or unrelated workloads.

## Client independence

Client-specific registration and UI instructions belong under docs/clients/.
They must not alter the core authorization rules:

~~~text
OAuth scope
AND explicit device grant
AND server profile
AND device-local ceiling
~~~

A new AI provider should normally require documentation and acceptance evidence,
not a fork of the CommandCore server or Agent.
