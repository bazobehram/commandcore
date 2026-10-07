<p align="center">
  <img src="apps/web/commandcore-logo.jpg" alt="CommandCore" width="560">
</p>

# CommandCore

[![CI](https://github.com/bazobehram/commandcore/actions/workflows/ci.yml/badge.svg)](https://github.com/bazobehram/commandcore/actions/workflows/ci.yml)
[![Repository policy](https://github.com/bazobehram/commandcore/actions/workflows/repository-policy.yml/badge.svg)](https://github.com/bazobehram/commandcore/actions/workflows/repository-policy.yml)
[![License: AGPL-3.0-or-later](https://img.shields.io/badge/license-AGPL--3.0--or--later-blue.svg)](LICENSE)

**Self-hosted remote computer control for AI and MCP clients.**

CommandCore connects AI clients to one or more computers through a vendor-neutral
MCP control plane. Devices make outbound connections to the server, retain their
own cryptographic identity, and enforce local permission ceilings.

CommandCore is free software licensed under **GNU AGPL-3.0-or-later**.

> **Project status:** 0.9 release-candidate family. Linux is the primary supported
> platform. Windows support is a preview. Interactive desktop control is
> experimental and is not yet part of the stable support promise.

## Why CommandCore?

Most computer-control MCP tools focus on one client talking to one machine.
CommandCore is designed as a control plane:

~~~text
ChatGPT -+
Claude --+
Gemini --+
Codex ---+-- MCP + OAuth --> CommandCore -- outbound WSS --> devices
IDE/CLI -+                       |
Other ---+                       +-- identity and grants
                                +-- policy and audit
                                +-- device selection
                                +-- signed agent lifecycle
~~~

A single MCP endpoint can expose every device the authenticated account is
allowed to use. Adding a device does not require adding another MCP server to
each AI client.

### Core properties

- **Self-hosted control plane** - server, protocol, agent, and deployment tooling
  are in this repository.
- **Vendor-neutral MCP** - the control plane does not depend on one AI provider.
- **Multi-device by design** - enumerate, select, and operate authorized devices.
- **Outbound-only device transport** - enrolled devices do not need inbound
  command ports.
- **Cryptographic device identity** - each agent keeps its Ed25519 private key
  locally.
- **Layered authorization** - OAuth scope, account-to-device grant, server
  profile, and device-local ceiling all restrict effective authority.
- **Privilege separation on Linux** - optional FULL_CONTROL uses a separate
  local privileged helper rather than making the network-facing agent root.
- **Auditable operations** - remote work is associated with identity, device,
  request, and execution metadata.
- **Managed long-running jobs** - process handles and bounded output survive
  transport/server reconnects in the native Linux agent.
- **Signed agent releases** - integrity verification, versioned installation,
  health validation, and rollback are first-class lifecycle concerns.

## Security model

CommandCore intentionally does not treat enrollment as authorization.

~~~text
effective authority =
    OAuth scope
    AND account -> device grant
    AND server permission profile
    AND device-local permission ceiling
~~~

Profiles:

| Profile | Meaning |
|---|---|
| READ_ONLY | Inspect permitted state and files |
| STANDARD | Normal operating-system authority of the agent user |
| FULL_CONTROL | Explicit local privileged-helper opt-in |

STANDARD shell access is powerful: it has the same authority as the operating
system account running the agent. Run the agent as a dedicated unprivileged user
when stronger host separation is required.

Read [SECURITY.md](SECURITY.md), [Security model](docs/SECURITY_MODEL.md), and
[Threat model](docs/THREAT_MODEL.md) before exposing a deployment to untrusted
clients.

## Capabilities

The current Linux implementation covers:

- filesystem list/stat/read/write/patch/search/copy/move/delete;
- shell execution;
- managed processes, status, output, and cancellation;
- system information and metrics;
- upload/download transfer primitives;
- Git operations;
- device enrollment, revocation, reconnect, and key rotation;
- OAuth-protected MCP access and explicit device grants;
- signed agent installation/update/rollback;
- fleet/canary rollout primitives;
- optional privilege-separated Linux FULL_CONTROL.

Interactive screen, mouse, keyboard, clipboard, browser automation, and some
platform-specific administration remain experimental or incomplete. The project
does not claim support from compilation alone; see the
[platform matrix](docs/PLATFORM_SUPPORT.md).

## Quick start

### 1. Run CommandCore

Requirements: Docker with Compose.

~~~bash
git clone https://github.com/bazobehram/commandcore.git
cd commandcore
cp .env.example .env

# Generate two different secrets and place them in .env:
./scripts/generate-secret.sh   # COMMANDCORE_API_TOKEN
./scripts/generate-secret.sh   # COMMANDCORE_PANEL_SESSION_SECRET

# Set the deployment URLs in .env, then:
docker compose up -d --build
docker compose ps
~~~

The public example binds the application port to `127.0.0.1`. Public bootstrap
and recovery are disabled by default. For a loopback-only first-time onboarding
window, an operator may deliberately enable bootstrap, configure OAuth/OIDC, test
it, and disable bootstrap again before normal remote operation.

For internet-facing deployments, use HTTPS/WSS behind a reverse proxy and
configure an external OAuth/OIDC provider. See
[Self-hosting](docs/SELF_HOSTING.md), [Deployment](docs/DEPLOYMENT.md), and
[OAuth/MCP](docs/OAUTH_MCP.md).

### 2. Install an agent

A deployment can publish its signed Linux installer at its own CommandCore URL:

~~~bash
curl -fsSL https://commandcore.example.com/install/linux | sh
~~~

The installer verifies the signed release manifest and artifact, creates a
versioned user installation, configures a systemd user service, and opens the
device-enrollment flow. Replace commandcore.example.com with your deployment.

See [Installation](docs/INSTALLATION.md) for upgrade, rollback, uninstall, and
advanced installation details.

### 3. Connect an MCP client

Use the deployment MCP endpoint:

~~~text
https://commandcore.example.com/mcp
~~~

Then authenticate with the configured OAuth/OIDC provider and grant only the
devices and scopes the client needs.

Client guides:

- [ChatGPT](docs/clients/CHATGPT.md)
- [Claude](docs/clients/CLAUDE.md)
- [Gemini](docs/clients/GEMINI.md)
- [Codex](docs/clients/CODEX.md)
- [Generic MCP clients](docs/clients/GENERIC_MCP.md)

Client product capabilities change independently of CommandCore. Each guide
distinguishes protocol support from live acceptance evidence.

## Platform status

| Platform | Status | Notes |
|---|---|---|
| Linux x86_64 | Supported candidate | Python reference + native Rust agent |
| Linux ARM64 | Supported candidate | Native Rust agent |
| Windows | Preview | Core enrollment/runtime work exists; release gates remain |
| macOS | Planned | No supported agent release yet |
| Interactive desktop | Experimental | Not part of stable support promise |

## CommandCore and Desktop Commander

CommandCore is not a fork of Desktop Commander. The projects solve overlapping
but different problems: Desktop Commander has a mature local computer-tool
surface, while CommandCore focuses on a self-hosted, multi-device remote control
plane with explicit identity, grants, policy, and agent lifecycle.

The comparison is intentionally factual rather than adversarial. See
[CommandCore and Desktop Commander](docs/COMPARISON_DESKTOP_COMMANDER.md).

## Documentation

Start with the [documentation index](docs/README.md). Important references:

- [Architecture](docs/ARCHITECTURE.md)
- [MCP contract](docs/MCP_CONTRACT.md)
- [Device protocol](docs/DEVICE_PROTOCOL.md)
- [Permissions](docs/PERMISSIONS.md)
- [Agent architecture](docs/AGENT_ARCHITECTURE.md)
- [Observability](docs/OBSERVABILITY.md)
- [Operator guide](docs/OPERATOR_GUIDE.md)
- [Development](docs/DEVELOPMENT.md)
- [Release process](docs/RELEASE.md)
- [Roadmap](docs/ROADMAP.md)

## Contributing

Contributions are welcome. Before opening a pull request, read
[CONTRIBUTING.md](CONTRIBUTING.md).

The project uses review-first development:

- changes arrive through pull requests;
- CI must pass;
- security-boundary changes require explicit security review;
- protocol changes require compatibility notes and tests;
- claims about platform support require real acceptance evidence;
- commits must carry a Signed-off-by line under the Developer Certificate of
  Origin policy described in CONTRIBUTING.md.

Sensitive vulnerabilities must **not** be reported in public issues. Follow
[SECURITY.md](SECURITY.md).

## License

CommandCore is licensed under the
[GNU Affero General Public License, version 3 or later](LICENSE).

If you modify CommandCore and make the modified program available to users over
a network, review the AGPL source-availability requirements that apply to that
use. Third-party dependencies retain their own licenses; see
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and
[dependency licensing](docs/DEPENDENCY_LICENSES.md).
