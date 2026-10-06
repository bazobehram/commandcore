# Architecture

Status: **0.9 release-candidate architecture**. Platform-specific limits are tracked in [PLATFORM_SUPPORT.md](PLATFORM_SUPPORT.md).

## Product boundary

CommandCore is a vendor-neutral control plane. MCP is a northbound interface; Agent transport, identity, lifecycle, policy and job routing are CommandCore-owned.

```text
ChatGPT / Codex / Claude / Gemini / local agents
                     |
                     | MCP / future adapters
                     v
              CommandCore Server
 MCP / API / Web / Auth / Registry / Enrollment /
 Sessions / Jobs / Policy / Audit / Fleet Rollouts
                     |
                     | Agent Protocol v1 over outbound WSS
                     v
              commandcore-agent
                     |
          FULL_CONTROL authenticated IPC
                     v
              commandcore-helper
```

## Modular monolith server

The server is a FastAPI modular monolith backed by SQLite for the current self-hosted profile. Registry, enrollment, OAuth validation, selection handles, jobs, audit, panel APIs, Agent gateway and fleet rollout coordination share one deployable server while retaining module boundaries.

## MCP state model

MCP transport sessions are not authoritative security state. `devices.select` resolves a human-facing device into an opaque `selection_id`; every privileged call re-resolves the immutable device ID and re-checks current authorization. Explicit device ID can override the selection handle where supported.

## Authorization

Effective authority is the intersection of:

```text
OAuth execution scope
∩ per-subject device grant
∩ server device permission profile
∩ root-owned device-local maximum profile
```

Bootstrap/recovery authentication is an explicit deployment recovery path and is disabled by default in the public configuration template. External OAuth/JWKS is supported for northbound clients.

## Agent identity and transport

The Agent creates a durable Ed25519 keypair locally. The private key never leaves the device. WSS authentication combines a device token with a fresh server challenge signed by the device key. Two-phase key rotation proves both old and new keys and recovers interrupted/expired rotations without re-enrollment.

The Agent connection is outbound-only. No inbound shell or Agent port is required.

## Linux privilege separation

The network Agent stays unprivileged. FULL_CONTROL delegates to a separate root helper over authenticated Unix IPC. The helper verifies peer UID, HMAC, freshness/nonce and root-owned local policy. Validation runs the Agent as UID 65534 and helper as UID 0; remote `id -u` returns `0` and root-only filesystem access succeeds.

## Agent release lifecycle

Linux uses a versioned release layout plus a stable updater/helper runtime:

```text
/opt/commandcore-agent/
  current -> releases/<release>
  releases/
  helper/venv/
  rollout.json
```

Signed artifacts are verified before staging and independently re-verified at the privileged activation boundary. Activation atomically switches `current`, restarts the Agent and requires a fresh authenticated connected-health marker. Failure restores the previous release. Signed downgrade is rejected unless a local administrator explicitly overrides it for recovery.

## Fleet rollout coordinator

Fleet rollout is a persistent control-plane state machine, not a fire-and-forget broadcast.

```text
signed release already trusted locally on each device
        |
        v
canary ring
  stage -> activate -> authenticated reconnect -> commit
        |
        v
ring 1 -> ring 2 -> ...
        |
        +-- failure -> pause by default
        +-- offline -> wait, not failure
        +-- operator skip/resume/cancel
```

Each `advance` call performs at most one durable remote action. Rollout state and events are stored in SQLite. A stale `staging` state is recovered to a safe retry after timeout; transport loss while staging is retryable, and an activation dispatch race preserves the staged artifact.

The control plane cannot choose the release signing key or arbitrary update host. Each device must be locally configured with both a trusted Ed25519 release public key and allowed HTTPS manifest origin before it is eligible for fleet rollout.

## Persistence

SQLite tables include devices, grants, enrollment tokens, selection handles, jobs, audit events, `schema_migrations`, fleet rollouts, per-device rollout state and rollout events. Migrations are explicit and monotonic. State-changing actions are audited with secret-redacted argument summaries.

## Capability model

Implemented capability families include filesystem, shell, process, system, transfer, Git, Docker, Linux services/packages/power and Agent update lifecycle. Interactive desktop/screen/keyboard/mouse/clipboard capabilities are experimental and advertised only when a usable backend exists; browser automation is not implemented. Capability/version advertisement lets old and new Agents coexist.

## Native Agent

The native Rust Agent is the preferred release-candidate runtime for supported Linux x86_64 and ARM64 deployments. CI covers format, strict Clippy, locked tests/build and black-box parity. The Python Agent remains a reference implementation and controlled fallback.

## Platform direction

Linux is implemented first. Northbound contracts avoid assuming `/home`, bash, systemd or POSIX paths. Windows remains a preview and macOS is planned; see the platform matrix for evidence and limits.
