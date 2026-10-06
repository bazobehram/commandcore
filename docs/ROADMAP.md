# Roadmap

CommandCore is preparing its first public 0.9 release-candidate line. The roadmap
prioritizes reliability, secure self-hosting, client neutrality, and a clean
installation experience over feature count.

Roadmap items are intentions, not release promises.

## 0.9 public preview

### Public repository and onboarding

- publish the clean AGPL-3.0-or-later source tree;
- require pull-request review, DCO sign-off, CI, and security review for sensitive
  boundaries;
- ship a provider-neutral self-hosting guide;
- make a fresh Linux Agent install achievable with one signed installer command;
- make server setup reproducible with Docker Compose and documented generic OIDC;
- publish release hashes, SBOM, provenance, and known limitations.

### Linux reliability

- keep x86_64 and ARM64 native Agent parity gates green;
- expand reconnect/transport chaos tests;
- harden long-running process supervision and output retention;
- exercise server/proxy restart and failed-update rollback regularly;
- improve operator diagnostics for offline/stuck devices.

### Client interoperability

- keep the MCP contract provider-neutral;
- maintain real ChatGPT acceptance;
- complete and record real Claude acceptance;
- complete and record real Gemini acceptance;
- add generic MCP interoperability fixtures where practical.

## Toward 1.0

A 1.0 release should represent a compatibility and operations promise, not merely
a version number.

Required themes:

- stable documented Agent Protocol and MCP behavior;
- migration policy for database/config/protocol changes;
- repeatable signed release process;
- well-tested backup/restore and rollback;
- reliable Linux lifecycle across supported distributions;
- clear security response and supported-version policy;
- mature diagnostics/observability;
- clean install, upgrade, revoke, and uninstall experience.

## Platform expansion

### Windows

Windows remains a preview until real-machine gates cover:

- signed native installation;
- login/reboot lifecycle;
- reconnect;
- core operation matrix;
- privilege-separated helper;
- update/rollback;
- uninstall/recovery;
- interactive-session behavior where desktop control is claimed.

### macOS

Planned after the Linux and Windows lifecycle models are stable. A macOS release
will need a native Agent lifecycle and explicit privileged-helper/session model
rather than a thin compatibility claim.

## Capabilities

Potential post-preview work:

- optional browser automation with a dedicated security boundary;
- stable interactive desktop control after real-session acceptance;
- resumable large transfers;
- device-to-device transfer;
- richer policy and per-operation approval workflows;
- high-availability persistence profile for larger deployments;
- optional external observability integrations.

## Self-healing and incident response

The project intends to add bounded health monitoring and recovery for the
CommandCore infrastructure itself.

The first layer should be deterministic and independent of the Agent it monitors:
process/service checks, reconnect, bounded restart, rollback, incident capture,
and operator notification. AI-assisted diagnosis, if added, should be a later,
strictly scoped layer rather than the primary recovery mechanism.

## Non-goals

CommandCore does not aim to become:

- an AI model provider;
- a hosted-only device cloud;
- a substitute for operating-system security boundaries;
- a shell blacklist marketed as a sandbox;
- a vendor-specific MCP fork.

The control plane should remain self-hostable and client-neutral.
