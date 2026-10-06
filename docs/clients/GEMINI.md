# Gemini

Status: **REMOTE MCP TARGET; PROJECT LIVE ACCEPTANCE PENDING**.

CommandCore contains no Gemini-specific server or Agent assumptions. Use a Gemini
surface that supports remote MCP and connect the deployment endpoint:

~~~text
https://commandcore.example.com/mcp
~~~

Gemini CLI or a Gemini chat surface may have different connector and OAuth
configuration. Follow the current client documentation rather than baking
client-specific assumptions into CommandCore.

## Acceptance gate

A Gemini integration is project-validated only after a real client completes:

1. OAuth login;
2. auth.whoami;
3. devices.list;
4. devices.select on a non-critical device;
5. system.info;
6. harmless filesystem read;
7. harmless STANDARD shell command when intended;
8. explicit revocation denial.

Keep Gemini-specific registration details in this client guide. Do not add
Gemini-specific shortcuts to the CommandCore authorization model.
