# AGENTS.md

This file is written for AI coding and operations agents working with the
CommandCore repository.

If a user asks you to "install CommandCore", "set up my CommandCore server",
"make this repository usable", "connect it to my AI client", or words to that
effect, treat that as a deployment task and follow this file before making
changes.

AGENTS.md is a repository-scoped convention used by many coding agents. It is
not part of the MCP protocol and support is not universal. If your agent does
not load it automatically, the user should explicitly tell the agent to read
AGENTS.md first.

## Mission

Produce a working, self-hosted CommandCore deployment without weakening the
security model for convenience.

A successful installation is not just "the container started". The agent should
leave the operator with:

- a healthy CommandCore server;
- a deliberate network exposure model;
- working HTTPS/WSS for remote use;
- OAuth/OIDC configured for internet-facing MCP access;
- an explicit device permission ceiling;
- at least one enrolled device when requested;
- the MCP URL for the user's client;
- a small acceptance report showing what was actually tested;
- a rollback path and a list of any remaining manual steps.

## Read before changing anything

For deployment work, read these files before acting:

1. `README.md`
2. `docs/SELF_HOSTING.md`
3. `docs/DEPLOYMENT.md`
4. `docs/OAUTH_MCP.md`
5. `docs/INSTALLATION.md`
6. `docs/PERMISSIONS.md`
7. `docs/SECURITY_MODEL.md`
8. the relevant client guide under `docs/clients/`

Also read `docs/INSTALLATION_READINESS.md` for current installation limits and
`docs/RELEASE_DOWNLOADS.md` before promising a signed agent installation.

For contributor work, also read `CONTRIBUTING.md`, `SECURITY.md`, and the
relevant architecture/protocol documents.

## Deployment modes

Determine which mode the user wants before exposing anything publicly.

### Local-only evaluation

Use this when the user only wants to try CommandCore on one machine or a private
network.

- Keep the application bound to loopback unless the user explicitly asks for a
  private-network binding.
- Do not create public DNS, public tunnels, or public firewall rules.
- Do not imply that a local evaluation is production-ready.

### Remote / production-style deployment

Use this when an MCP client or agent must reach CommandCore over the internet.

- Put CommandCore behind a reverse proxy or equivalent edge.
- Use valid HTTPS/WSS.
- Configure OAuth/OIDC.
- Keep the internal application port private.
- Keep public bootstrap and recovery disabled except for an explicit,
  time-bounded operator-approved procedure.

If the user's intent is ambiguous and the difference changes network exposure,
ask one focused question.

## Discover before asking

Inspect the machine and repository first. Do not ask the user for facts you can
safely determine yourself.

Useful checks include:

```bash
uname -a
docker --version
docker compose version
git status --short --branch
ss -ltn
```

Also check for:

- an existing CommandCore installation;
- an existing reverse proxy;
- an existing canonical hostname;
- occupied ports;
- existing data volumes;
- whether the current user can run Docker;
- whether the machine is already enrolled as a CommandCore device.

Ask only for inputs that cannot be safely inferred, such as:

- the canonical public hostname/domain;
- access to DNS or reverse-proxy configuration if the agent does not have it;
- OAuth/OIDC provider values or a user login that must be completed manually;
- whether the user wants this machine enrolled as a managed device;
- whether a permission ceiling above READ_ONLY is actually desired.

## Security invariants

Do not trade these away to make setup easier.

- Never commit `.env`, tokens, client secrets, private keys, signing keys, or
  device private identity material.
- Never print secrets back to the user unless the user explicitly asks to see a
  value that must be transferred.
- Generate unique deployment secrets. Do not reuse example values.
- Keep `COMMANDCORE_PUBLIC_BOOTSTRAP_ENABLED=false` by default.
- Keep `COMMANDCORE_RECOVERY_ENABLED=false` outside an explicit recovery
  procedure.
- Do not expose the internal CommandCore application port directly to the
  internet.
- Do not disable TLS certificate or hostname verification.
- Do not run the network-facing agent as root for convenience.
- Do not enable FULL_CONTROL merely because the remote account has a broad
  OAuth scope. FULL_CONTROL requires explicit local opt-in.
- Treat STANDARD shell access as powerful operating-system access.
- Do not reduce host firewall, reverse-proxy, OAuth, or branch/repository
  security settings unless the user explicitly requests the exact change and
  understands the consequence.
- Never claim a platform or capability works merely because it compiled.

If an existing deployment is found, preserve its data and configuration. Back
up before destructive migration and prefer an in-place, reversible change.

## Recommended server workflow

### 1. Obtain the repository

If the repository is not already present:

```bash
git clone https://github.com/bazobehram/commandcore.git
cd commandcore
```

Prefer a tagged/released version for a production deployment when one is
available. Do not silently switch an existing deployment to an unrelated
branch.

### 2. Prepare configuration

Start from the tracked template:

```bash
cp .env.example .env
chmod 600 .env
```

Generate two different secrets:

```bash
./scripts/generate-secret.sh
./scripts/generate-secret.sh
```

Store one as `COMMANDCORE_API_TOKEN` and the other as
`COMMANDCORE_PANEL_SESSION_SECRET`.

Do not put generated secrets in shell history, issue comments, pull requests, or
chat transcripts when avoidable.

Set the deployment URLs deliberately:

```text
COMMANDCORE_PUBLIC_BASE_URL=https://commandcore.example.com
COMMANDCORE_MCP_BASE_URL=https://commandcore.example.com/mcp
COMMANDCORE_AGENT_BASE_URL=wss://commandcore.example.com/agent
```

For a local-only evaluation, use values appropriate to that local deployment
instead of pretending the example hostname is real.

### 3. Validate before starting

At minimum:

```bash
docker compose config
```

Review the rendered configuration for accidental public port exposure and
missing required values.
The rendered configuration includes expanded secrets: inspect it locally and do
not paste it into a chat, issue, or public log. Use `docker compose config --quiet`
when only checking configuration validity.

### 4. Start the server

```bash
docker compose up -d --build
docker compose ps
```

The default Compose file binds the application to `127.0.0.1:8787`.

Verify health:

```bash
curl -fsS http://127.0.0.1:8787/healthz
```

Do not continue to public exposure if health is failing.

### 5. Add HTTPS/WSS for remote use

For an internet-facing deployment:

- use one canonical HTTPS origin;
- terminate TLS at a reverse proxy or equivalent trusted edge;
- proxy normal HTTPS requests and Agent WebSocket traffic;
- keep `127.0.0.1:8787` private;
- verify the public certificate and hostname normally.

Follow `docs/DEPLOYMENT.md` and `docs/SELF_HOSTING.md`.

Do not invent DNS credentials, OAuth credentials, or certificate ownership. If
the agent cannot perform one of those account-bound steps, stop at that boundary
and tell the operator exactly what remains.

### 6. Configure OAuth/OIDC

For remote MCP access, follow `docs/OAUTH_MCP.md`.

Verify issuer, audience/resource, JWKS, authorization-server metadata, and the
panel client configuration appropriate to the chosen provider.

Do not make public bootstrap a permanent substitute for OAuth.

### 7. Enroll devices only when requested

After the deployment endpoint is valid and the release/installer path is ready,
follow `docs/INSTALLATION.md`.

A deployment may expose its signed Linux installer at:

```bash
curl -fsSL https://commandcore.example.com/install/linux | sh -s -- --server https://commandcore.example.com
```

Before running a remote installer in a higher-trust environment, follow
`docs/VERIFY_LINUX_INSTALLER.md` and confirm that the deployment is publishing
the expected signed release material.

The default Compose deployment does not publish this route: it returns 404 until
`COMMANDCORE_DISTRIBUTION_DIR` points at a populated, readable release feed.
Check the installer and manifest endpoints before telling the user to install.
Pass `--server` explicitly; downloading a script from a host does not select that
host as the enrollment server. If no signed feed exists, report that boundary
and offer the documented source evaluation workflow instead of inventing a
release, trusting an arbitrary key, or weakening verification.

Enrollment is not authorization. Apply the minimum account-to-device grant and
permission ceiling that satisfies the user's request.

### 8. Connect the user's MCP client

The normal endpoint is:

```text
https://commandcore.example.com/mcp
```

Use the relevant guide under `docs/clients/`.

Do not claim the client is connected until authentication succeeds and an
actual MCP request reaches CommandCore.

## Acceptance test

Prefer a read-only acceptance first.

For an enrolled Linux device, a good minimum is:

1. list authorized devices;
2. select the intended device;
3. call `system.info`;
4. read a harmless file such as `/etc/hostname` when permitted.

Only run shell commands or write operations when the user has authorized that
level of testing.

Also verify:

- `/healthz` is healthy;
- the intended public HTTPS endpoint responds;
- the MCP endpoint requires/accepts the expected authentication;
- the device permission profile does not exceed the intended ceiling;
- no unexpected public application port was opened.

## Completion report

When finished, give the user a compact factual report:

```text
CommandCore server: healthy / not healthy
Deployment mode: local-only / remote
Public URL: ...
MCP URL: ...
Agent URL: ...
OAuth/OIDC: configured / remaining manual step
Devices enrolled: ...
Permission ceiling: ...
Acceptance performed: ...
Rollback/backups: ...
Remaining actions: ...
```

Report actual observations. Never convert an untested assumption into a success
claim.

## Failure and rollback behavior

If a step fails:

1. stop before broadening privileges or exposure;
2. preserve logs needed for diagnosis without leaking secrets;
3. identify the exact failing boundary;
4. restore the previous working configuration if the change was disruptive;
5. report what changed and what was rolled back.

Do not repeatedly restart services, rotate credentials, delete data, or loosen
security controls as a trial-and-error strategy.

## Repository changes

If the user asks you to modify CommandCore itself:

- work on a branch;
- keep public branding deployment-neutral;
- do not introduce private deployment names, domains, credentials, or histories;
- run the relevant tests and repository policy checks;
- use pull requests;
- keep commits DCO-signed as described in `CONTRIBUTING.md`;
- update documentation when behavior or operator expectations change.

Security-boundary changes deserve explicit review even when ordinary solo
maintainer PRs do not require a human approval.

## Experimental browser control

Do not enable the optional visual browser integration on production instances
or use private authenticated profiles. Review [visual browser security and
acceptance gates](docs/VISUAL_BROWSER_POC.md) before any evaluation. This
feature is still an isolated, single-operator PoC, not supported browser
automation.
