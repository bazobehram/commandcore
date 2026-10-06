# Codex

Status: **REMOTE MCP TARGET; PROJECT LIVE ACCEPTANCE PENDING**.

Treat Codex as a generic MCP client. Configure the current Codex MCP mechanism
against the same deployment endpoint used by other clients:

~~~text
https://commandcore.example.com/mcp
~~~

CommandCore should not contain Codex-specific authorization or Agent behavior.

## Acceptance gate

Record Codex as project-validated only after a real client completes:

1. MCP initialize/tools discovery;
2. OAuth login when enabled;
3. auth.whoami;
4. devices.list;
5. devices.select on a non-critical device;
6. system.info;
7. harmless filesystem read;
8. harmless STANDARD shell command when intended;
9. device-grant revocation denial.

Client-specific configuration details belong in this file because Codex product
behavior can change independently of CommandCore.
