# Claude

Status: **REMOTE MCP TARGET; PROJECT LIVE ACCEPTANCE PENDING**.

CommandCore contains no Claude-specific server or Agent assumptions. Use Claude's
current remote MCP/custom connector mechanism and point it at the same CommandCore
MCP endpoint used by other clients:

~~~text
https://commandcore.example.com/mcp
~~~

## Expected flow

~~~text
Claude
  -> OAuth/OIDC
  -> CommandCore MCP
  -> explicit device grant
  -> selected Agent
~~~

The client must support the deployment's OAuth discovery/authorization flow and
the MCP transport used by CommandCore.

## Acceptance gate

Do not mark Claude as project-validated until a real Claude chat session completes:

1. OAuth login;
2. auth.whoami;
3. devices.list;
4. devices.select on a non-critical device;
5. system.info;
6. harmless filesystem read;
7. harmless STANDARD shell command when STANDARD access is intended;
8. grant revocation denial.

Record the Claude surface used and the date because client product behavior can
change independently of CommandCore.
