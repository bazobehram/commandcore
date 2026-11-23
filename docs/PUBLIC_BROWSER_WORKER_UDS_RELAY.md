# Public Browser: per-worker Unix-socket Steel/CDP control relay

**Status (2026-11-23): source-only, disabled by default, NOT deployed as a production sidecar.** This PR implements the transport and proves its behavior with synthetic worker backends and real Linux peer UIDs. It does not establish signed relay identity or complete the real worker lifecycle; those remain strict stop-ship gates.

## Current topology and why it matters

A provisioned public Browser worker currently has three isolated Docker bridge networks: an isolated Chromium/Steel network, an isolated *control* network connected to the worker's boundary container, and a distinct outbound network for the boundary's deny-private HTTPS egress. The Steel container has no host-published control port. The `ccctl-<worker_id>` alias is available only on that one worker's control network. Joining the public API to every worker's control network would enlarge the cross-tenant failure domain, so this implementation **does not do that**.

The new `browser_worker_uds_relay.py` is an operator-only sidecar process designed to join **exactly one verified worker control network**. It accepts connections on two separate Unix sockets (no TCP listener) in a fixed, operator-owned host-mounted directory:

- `.../<worker_id>/steel.sock`: fixed control alias `ccctl-<worker_id>:3000`. Opaque HTTP and CDP WebSocket bytes are forwarded unchanged, with backpressure, timeout, per-connection maximum age and connection budget.
- `.../<worker_id>/policy.sock`: fixed control alias `ccctl-<worker_id>:8080`. Used only for the existing read-only egress policy endpoint; the API must continue checking the returned policy against its configured host allowlist.

The sidecar accepts only a pinned Linux `SO_PEERCRED` API UID + primary GID. It rejects invalid worker IDs, unsafe/writable/socket-collision paths, unknown ports and unauthorized peers. It cannot choose another worker's hostname from an HTTP request or CDP URI. It never sees OAuth bearer tokens, never uses Docker, and drops its sockets on clean shutdown only if inode/UID still match its own originals. A dedicated provision/read socket group and an operator-controlled, group-traversable but **not group-writable** directory are required. Do not reuse a broader signing/proof group for public API access.

The API side `browser_worker_uds_client.py` derives its path **only** from the physical worker ID selected by the verified owner-binding pool, not user arguments. It validates the operator-owned, non-symlinked root and worker directory, expects the exact operator UID/GID and 0660 socket permissions, and pins each socket inode on first use. Replacement of an in-use socket is a trust loss. The existing `BrowserGateway` now optionally sends all Steel HTTP, policy HTTP and CDP WebSocket connections over that transport, while private Browser uses the previous direct connection path by default.

`COMMANDCORE_BROWSER_UDS_RELAY_ENABLED=false` is the default. It requires Browser + OAuth + dynamic owner-bound pool, a configured absolute `COMMANDCORE_BROWSER_UDS_RELAY_ROOT`, expected operator UID/GID and verified Ed25519 **public** worker proof. The dynamic pool creates one `WorkerUnixClient` for each operator-verified worker ID; changes to a route invalidate cached sessions rather than transferring them. Never mount the Docker socket, operator HMAC binding secret or Ed25519 signing seed into an API container. The API must receive only the minimum read-only manifest/ledger and group-only socket path; socket directory should not be writable by the API.

## What is verified

- Real Linux Unix sockets: two mock worker backends return distinct HTTP responses through separate sockets, with no cross-route mixing; both Steel and policy paths tested.
- Transparent CDP-compatible WebSocket upgrade/text frames over UDS; `BrowserGateway`'s actual HTTP/CDP client uses those sockets in a separate test.
- Wrong UID is denied before an upstream connection; invalid worker IDs, symlink/world-writable directories, fake socket file and wrong group are rejected.
- A socket pathname replaced while the old relay process still runs is detected by API; the old process does not unlink the replacement.
- Netti host-identity acceptance, synthetic backends only: API UID 10001/GID999 and operator UID994/GID987, with a temporary restricted group-accessible directory. Script (operator staging only): `/opt/commandcore-public/staging/plugin-review-20261120/run_worker_relay_cross_uid_20261123.sh`. No Docker workers were created.

## Production STOP-SHIP: source code alone is not enough

1. Extend the operator **physical worker registry, labels, pinned image identity and Ed25519 proof** to verify one sidecar's immutable container ID, network endpoint membership, seccomp/capabilities, read-only rootfs and mounted socket directory. Reject any extra or changed network membership, published ports or unapproved host mounts. The current two-container physical proof does NOT cover the new sidecar. Do not start it in production without this verification.
2. Implement atomic sidecar create/start/stop/retire and state recovery alongside Steel/boundary; assure per-worker socket directories cannot be replaced and no stale credentials/sockets survive retirement. Mount only the exact worker's sockets read-only into the API; do not mount every worker's private state.
3. Publish operator-verified read-only owner binding/manifest to the API, and integrate live OAuth owner provisioning, operator quotas and durable ack/idempotency. Keep the API fail-closed on missing proof and never infer readiness from an IPC ACK.
4. Add the **relay's immutable identity / incarnation to signed physical proof** and enforce it before and after actions; verify start/stop/replacement/recovery and 15-minute idle. The socket UID/GID checks are not themselves proof that the relay is the correct Docker worker.
5. End-to-end test two REAL, independent Auth0/ChatGPT accounts, tenant routing/frames, cross-tenant and cross-chat denials, Steel CDP and host egress, handoff, restart and rollback. Re-verify parity against the private Browser without modifying its runtime state.
6. Publish owner-reviewed actual `/privacy` and `/terms` (currently 404), rerun authenticated OpenAI rc10 MCP Rescan, supply reviewer account/demo device and eight real test results, then submit only after all release gates pass.

This module deliberately accepts operator/API identity from deployment configuration and offers a dependency-injected upstream connector for synthetic tests. Production CLI always fixes upstream alias and ports from the immutable worker ID; there is no caller-selected destination. No public Browser flag is flipped by this PR.
