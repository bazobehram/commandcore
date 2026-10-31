# Architecture

Status: **1.0 release-readiness source architecture** (not a statement of production or multiuser security acceptance). Platform-specific limits are tracked in [PLATFORM_SUPPORT.md](PLATFORM_SUPPORT.md).

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

Implemented capability families include filesystem, shell, process, system, transfer, Git, Docker, Linux services/packages/power and Agent update lifecycle. Interactive desktop/screen/keyboard/mouse/clipboard capabilities are experimental and advertised only when a usable backend exists. The **optional managed Browser** has a separate owner-bound worker architecture; it is not an Agent-hosted browser and is not enabled by default. Capability/version advertisement lets old and new Agents coexist. See [BROWSER.md](BROWSER.md) for operator prerequisites and deployment limits.

## Native Agent

The native Rust Agent is the preferred release-candidate runtime for supported Linux x86_64 and ARM64 deployments. CI covers format, strict Clippy, locked tests/build and black-box parity. The Python Agent remains a reference implementation and controlled fallback.


## Contributor source map and trust boundaries

This is a **source responsibility map**, not a claim that all candidate deployments
have passed real-world acceptance. Keep authentication and permission enforcement
on the server/Agent boundary; the Angular UI is not a security authority.

| Boundary / responsibility | Primary source | Invariant when changing it |
|---|---|---|
| FastAPI routes, panel session lifecycle and OAuth resource metadata | `apps/server/commandcore_server/main.py` | Server revalidates identity and ownership; recovery is distinct from public OAuth |
| OAuth JWT validation and scope hierarchy | `apps/server/commandcore_server/auth.py` | Signature, issuer, audience and expiration checks; FULL is **not** ADMIN |
| MCP HTTP transport, handler dispatch and UI task ledger | `apps/server/commandcore_server/mcp.py` | Transport/session state is not an authorization source; policy remains server-side |
| MCP JSON-RPC framing, modern header validation and response shaping | `apps/server/commandcore_server/mcp_protocol.py` | Pure wire-contract helpers only; no principal authentication, tool authorization or dispatch |
| Tool schemas, device selection and dispatch checks | `apps/server/commandcore_server/tools.py` | Resolve current subject-to-device grants/profile before execution |
| SQLite registry, grants, selections, jobs and audit storage | `apps/server/commandcore_server/db.py`, `migrations.py` | Transactions, ownership filters and monotonic migrations |
| Agent WebSocket registration and dispatch | `apps/server/commandcore_server/agent_gateway.py` | Device identity and authenticated outbound transport |
| Linux Agent execution | `agent/rust/src/executor.rs`; Python fallback: `agent/commandcore_agent/executor.py` | Operations stay within effective device-local and server policy |
| Privileged Linux helper | `agent/` helper implementation and local policy | Root operations require authenticated IPC and explicit local opt-in |
| Angular workspace UI and session privacy | `apps/workspace-angular/src/app/app.ts`, `api-client.ts`, `session-epoch.ts` | No stale account data after logout/401; no client-side privilege escalation |
| Legacy operator/recovery UI | `apps/web/panel.js` and related legacy assets | Do not remove recovery workflows before an accepted replacement |
| Managed Browser orchestration | `browser_gateway.py`, `browser_worker_pool.py`, `browser_worker_binding.py` | OAuth owner binding, verified worker identity, no direct untrusted CDP |
| First-party Browser viewer and handoff | `browser_viewer.py` and Browser approval/policy modules | Issuer/subject/session checks; private control blocks AI access |

All short server paths in the last two rows are under
`apps/server/commandcore_server/`. Module size alone is not a refactoring
requirement; add behavior-preserving tests before splitting security-sensitive
responsibilities. Refer to [DEVELOPMENT.md](DEVELOPMENT.md) and
[SECURITY_MODEL.md](SECURITY_MODEL.md).

### Independent request flows

```text
External AI client -- OAuth JWT --> HTTPS MCP endpoint
                                     |
                                    mcp.py --> mcp_protocol.py (wire contract)
                                    mcp.py --> tools.py --> DB grant/scope/profile
                                                           |
                                                      Agent gateway
                                                           |
                                                 authenticated outbound WSS
                                                           |
                                                    device Agent
                                                           |
                                       optional locally approved root helper

Browser request --> server authorization --> owner-bound worker pool
                                               | worker proof + egress policy
                                               v
                                        isolated Browser worker / Steel
                                               |
                                        public HTTPS-only proxy
                                  (no private/LAN/metadata destinations)

Angular UI -- same-origin session cookie --> server panel/API
       |                                  |
       +-- session-epoch privacy guard    +-- authoritative OAuth/ownership checks
```

Browser workers are separately provisioned and operator-attested. They do not
control the user's existing desktop Chrome. A first-party preview or Browser
handoff must re-check the OAuth issuer and subject; a known `client_id` is
not proof of ownership. Physical isolation and proxy policy require deployment
acceptance beyond passing Python route tests. See
[BROWSER_SECURITY_REVIEW.md](BROWSER_SECURITY_REVIEW.md).

### Public and private deployments

A public instance and an operator-owned private instance may consume **the same
reviewed immutable release artifact**, but must retain independent databases,
OAuth audiences/clients, session keys, device identities, grants and audit
history. Merging a PR does **not** itself authorize an update of either system.
Test the public canary, verify rollback, then separately back up and verify the
private target with the vetted digest. See [PUBLIC_HOSTING.md](PUBLIC_HOSTING.md)
and [DEPLOYMENT.md](DEPLOYMENT.md).

### How to verify a change

- **API/session transport:** `npm run test:api` in `apps/workspace-angular`.
- **Angular lifecycle/DOM:** `npm run test:unit` (Vitest + simulated DOM) and
  `npm run build`. These tests cannot establish real mobile layout or live OAuth.
- **MCP/OAuth, grants, Browser and Agent:** `pytest -q` plus targeted negative
  suites for the changed boundary; release CI includes Python, Rust and Windows
  checks where applicable.
- **Browser visuals and cross-account acceptance:** use the documented isolated
  Browser UI suite and real separate user acceptance, not just a unit fixture.
- **Release:** verify required GitHub checks, provenance, canary, rollback and
  each deployment's authorization/health independently.


## Platform direction

Linux is implemented first. Northbound contracts avoid assuming `/home`, bash, systemd or POSIX paths. Windows remains a preview and macOS is planned; see the platform matrix for evidence and limits.
