# Agent-assisted installation

CommandCore can be installed by a capable coding or operations agent, provided
the agent is given access to the target machine and is instructed to follow the
repository's deployment and security guidance.

The repository contains a root-level [AGENTS.md](../AGENTS.md) file specifically
for this workflow.

Read [installation readiness](INSTALLATION_READINESS.md) before promising a complete
installation. The default server has no published signed agent feed, Windows is
preview, and a working remote deployment requires real OAuth/provider setup. An
agent can automate mechanical work, but cannot manufacture release acceptance,
account consent, or DNS ownership.

## Why AGENTS.md?

`AGENTS.md` is a repository-scoped convention used by a growing number of
coding agents to discover project-specific instructions.

It is useful here because a user can hand the repository to an agent and say:

> Read AGENTS.md and make CommandCore usable on this server.

The agent can then discover the intended deployment flow, security boundaries,
validation steps, and completion report without the user having to repeat the
entire installation procedure.

AGENTS.md is not part of MCP itself, and not every AI agent automatically reads
it. For maximum portability, explicitly tell the agent to read it first.

## Recommended prompt: production-style deployment

Use this when CommandCore must be reachable by ChatGPT, Claude, Gemini, Codex,
another remote MCP client, or remote enrolled devices.

~~~text
Clone https://github.com/bazobehram/commandcore.git and read AGENTS.md before
making any changes.

Install a self-hosted CommandCore server on this machine and make it usable for
remote MCP clients.

Prefer the repository's documented Docker Compose deployment. Preserve the
security model: keep the internal application port private, use HTTPS/WSS for
remote access, configure OAuth/OIDC instead of leaving public bootstrap enabled,
do not enable recovery by default, and do not enable FULL_CONTROL unless I
explicitly ask for it and the device opts in locally.

Inspect the machine first and ask me only for account-bound information you
cannot safely infer, such as my public domain or OAuth provider credentials.

Do not claim success just because a container started. Verify /healthz, verify
the public endpoint, connect the intended MCP client when possible, perform a
read-only device acceptance test, and finish with a factual report containing
the public URL, MCP URL, Agent URL, OAuth status, enrolled devices, permission
ceiling, tests performed, rollback path, and any remaining manual steps.
~~~

## Recommended prompt: local evaluation

Use this when the goal is to try CommandCore without exposing it to the
internet.

~~~text
Clone https://github.com/bazobehram/commandcore.git and read AGENTS.md before
making any changes.

Set up CommandCore on this machine for a local-only evaluation. Keep the server
bound to loopback, do not create public DNS, tunnels, firewall exposure, or
internet-facing bootstrap/recovery access.

Use Docker Compose if available, generate unique local secrets, start the
service, verify /healthz, and tell me exactly how to open the local panel and
what would still be required later for a secure remote deployment.
~~~

## Recommended prompt: server plus one managed device

Use this when the machine running CommandCore should also become a device the
user can operate through MCP.

~~~text
Clone https://github.com/bazobehram/commandcore.git and read AGENTS.md first.

Install a self-hosted CommandCore server here, configure it using the repository
security guidance, and then enroll this Linux machine as a managed device only
after the server is healthy.

Use STANDARD as the maximum permission profile unless I explicitly request a
different ceiling. Do not enable FULL_CONTROL automatically.

After enrollment, verify the connection with read-only operations:
devices.list, select the intended device, system.info, and a harmless read such
as /etc/hostname. Report the actual results.
~~~

## What the agent should do automatically

A good installation agent should be able to handle most of the mechanical work:

- inspect the target OS and available tooling;
- detect an existing CommandCore installation before changing anything;
- clone or update the repository safely;
- create a protected local `.env`;
- generate unique deployment secrets;
- validate the Compose configuration;
- build and start CommandCore;
- verify the local health endpoint;
- configure a reverse proxy when the agent has access to it;
- install or enroll a device when requested;
- test the MCP path;
- produce a completion report.

## What usually still needs the operator

Some boundaries are deliberately account-controlled and should not be guessed or
bypassed by an agent.

Typical examples:

- choosing or confirming the public domain;
- changing DNS when the agent has no DNS-provider access;
- signing into an OAuth/OIDC provider;
- creating OAuth client credentials;
- approving a passkey, MFA, or account consent screen;
- deciding whether a device should receive STANDARD or FULL_CONTROL;
- granting an AI client access to a particular device.

A good agent should stop at these boundaries, explain exactly what it needs, and
resume after the operator completes the account-bound step.

## Expected architecture

For a normal remote deployment, the result should look like:

~~~text
AI / MCP client
      |
 HTTPS + OAuth
      |
 reverse proxy
      |
 CommandCore
      |
 outbound WSS
      |
 managed devices
~~~

The internal CommandCore application port should remain private.

## Definition of done

An agent-assisted installation is complete only when the relevant items below
have been verified rather than assumed:

- CommandCore health check passes;
- intended HTTPS endpoint is reachable;
- TLS hostname validation succeeds;
- OAuth/OIDC is configured for remote MCP use;
- MCP authentication succeeds;
- enrolled devices appear only for authorized accounts;
- device permission ceilings match operator intent;
- at least one read-only device operation succeeds when a device was enrolled;
- rollback or backup information is recorded;
- the operator receives the final MCP URL and any remaining manual steps.

## Troubleshooting philosophy

Do not solve installation problems by progressively weakening security.

If something fails, identify which boundary is failing:

~~~text
container
-> local health
-> reverse proxy
-> TLS / DNS
-> OAuth/OIDC
-> MCP authentication
-> device grant
-> Agent transport
-> device-local permission
~~~

Fix the failing boundary directly.

Do not respond to an OAuth problem by enabling permanent public bootstrap. Do
not respond to an Agent permission problem by running the Agent as root. Do not
respond to a TLS problem by disabling certificate validation.

## Related documentation

- [Self-hosting](SELF_HOSTING.md)
- [Deployment](DEPLOYMENT.md)
- [OAuth and MCP](OAUTH_MCP.md)
- [Installation](INSTALLATION.md)
- [Permissions](PERMISSIONS.md)
- [Security model](SECURITY_MODEL.md)
- [Verify Linux installer](VERIFY_LINUX_INSTALLER.md)
- [ChatGPT client guide](clients/CHATGPT.md)
- [Generic MCP client guide](clients/GENERIC_MCP.md)
