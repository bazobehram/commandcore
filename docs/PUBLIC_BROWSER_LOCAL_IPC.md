# Public Browser operator local IPC — source-only implementation

**Status:** implemented and tested in a disposable local environment; **not installed as a production daemon or connected to the live OAuth API**. Public Browser remains disabled. The private deployment does not share worker, OAuth, or signing credentials with the public operator.

## Trust boundary

- `browser_provision_ipc.send_provision_intent()` transmits a previously issued **60-second signed OAuth intent**, not an OAuth JWT/cookie, to an explicit Unix domain socket. The client first validates that the socket is inside a directory not writable by group/others and checks the server's kernel `SO_PEERCRED` UID (and optionally GID) equals the configured operator identity. It refuses oversize data and unknown responses.
- `browser_provision_ipc.serve_provision_intents()` is **Unix only**, never TCP/HTTP. The operator checks the client's kernel `SO_PEERCRED` UID and primary GID *before* reading the payload, caps request size, and handles requests one at a time. It creates the socket with a restrictive umask and `0660` permissions; a dedicated provision group (not the read-only attestation group) can permit the explicitly authorized API UID to connect. The operator is responsible for choosing the verified API host UID; no wildcard UID or public internet listener is supported.
- `scripts/browser_provision_listener.py` loads private credentials from explicitly configured file paths and invokes the one-shot intake adapter; the files must be 0600 and owned by the operator/root. It writes request payload only to a 0600 temporary file in the 0700 operator state directory and unlinks it on success or failure. The adapter authenticates and consumes the nonce in durable SQLite before invoking `scripts/browser_worker_lifecycle.py`. The operator chooses Steel/boundary images and egress allowlist; the HTTP client never chooses them.
- The signed envelope proves the user identity and purpose under the dedicated public provision key. It is **not encrypted**, so this socket and its containing directory must be accessible only to the trusted API and operator UIDs. No Docker socket, owner-binding secret, Ed25519 signing seed, or private network is supplied to the API. The operator does not return user identities or bearer tokens in its reply.
- The listener is serial and synchronous. The client waits for a result, and a transport timeout is **ambiguous**, not proof that provisioning failed. Never automatically retry an unknown outcome or report a worker ready without an actual worker attestation. A durable job/ack protocol and operator idempotency reporting are required before live rollout.

## Test evidence

- `tests/test_browser_provision_ipc.py` opens real Linux Unix sockets and verifies valid signed request, server/client UID rejection, replay denial, bad paths, symlink refusal, oversized requests and secure cleanup.
- `tests/test_browser_provision_listener.py` tests the actual listener wiring through an operator adapter with a fake lifecycle callback, enforcing owner identity, one-use nonce and ephemeral credential file cleanup; **no production Docker workers** are created.
- These tests exercise Linux `SO_PEERCRED` and should be skipped or platform-gated on unsupported operating systems. Keep Linux CI coverage mandatory.

## Remaining production integration — STOP-SHIP until completed

1. Use the observed public API host UID 10001 / primary GID 999 only after confirming them on the target deployment. Configure an **independent provisioning socket group** and verify the operator is permitted to `chgrp` the socket, plus the socket mount and read-only/execute directory ACLs; configure a dedicated public provision key via systemd `LoadCredential`, and keep it isolated from public worker binding/attestation keys. Nothing currently mounts this Unix socket in the public API or starts the listener.
2. Derive the intent only from the resource server's **already-verified** JWT `Principal` at an authenticated tool/panel entrypoint. Never accept a user-supplied issuer/subject/client ID or expose signed intents to the browser widget. Add per-owner quotas, bounded queue/admission, abuse throttling and rate controls.
3. Make worker allocation and outcomes recoverable and idempotent across API/operator restarts. Inspect the 16-worker registry and tombstone capacity/lifecycle policy; a cap on historical records is not the same as a cap on active workers.
4. Publish a separately verified, versioned per-owner worker manifest and stable immutable physical attestation. Implement an API-to-worker relay that cannot route to another tenant and supports live additions/removals without a global API restart. This must not break session/lease ownership or stale-card protections.
5. Verify the real authenticated two-user ChatGPT browser journey (positive, negative, expiry, replacement, handoff, egress, restart and cleanup). Perform a public canary with a documented rollback; reconcile the approved common source to private without sharing runtime state.
6. Operator-reviewed `/privacy` and `/terms`, an actual OpenAI authenticated rc10 rescan, reviewer device and eight completed test cases remain separate Plugin Directory release gates.

**Do not enable `COMMANDCORE_BROWSER_ENABLED=true` or deploy the listener to production solely because source tests pass.**
