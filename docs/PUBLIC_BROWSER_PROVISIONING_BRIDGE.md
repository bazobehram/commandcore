# Public Browser OAuth-to-operator provisioning: trust boundary

Status: **protocol plus an offline operator-only CLI adapter; not a deployed feature**. Public Browser remains off. This is not an operator listener, request queue, OAuth client, signed worker attestation, or dynamic routing implementation.

## Verified current topology

- The resource server verifies Auth0 OAuth JWT claims (issuer, audience, expiry, subject and scopes). A `Principal` is server-created, never accepted from arbitrary HTTP JSON.
- Netti has a separate dedicated Browser operator with Docker privileges and an Ed25519 worker signing seed. The public API has **only the public proof and read-only proof mount**. It must never obtain Docker access or the private signing seed.
- `OwnerBrowserWorkerPool` reads a preassigned owner manifest at startup. Public API currently has neither a mounted routing manifest/owner binding ledger nor a network route to the distinct per-worker control networks; automatic provisioning and live routing are NOT ready.
- Operator staging already demonstrated two physically isolated synthetic owners and exact resource cleanup. Real Auth0 two-account ChatGPT Browser acceptance is still missing.

## Protocol implemented in this change

`commandcore_server.browser_provision_intent` defines a **purpose-bound HMAC-SHA256 envelope**. Only the trusted resource-server code, after real JWT verification, may issue an intent for an `oauth2` principal with STANDARD or FULL scope. It binds `(issuer, subject, client_id)` and one random request ID to a fixed audience and a 60-second expiry. READ-only, anonymous, bootstrap, panel and placeholder identities are rejected.

The operator verifier enforces expected issuer, HMAC tag, audience, version, expiry, size and field allowlist. A dedicated, private SQLite `ProvisionNonceLedger` atomically marks each request ID used, including across restarts and racing consumers, without storing the OAuth identity. The operator should use only `verify_and_consume_provision_intent`; verification alone is not replay protection. Rejected or expired intents must never invoke Docker.

**Integrity is not confidentiality.** The envelope contains the OAuth owner triple in encoded cleartext. Transport it only over a narrowly authorized local Unix socket (or equivalently secured local channel), never browser JavaScript, logs, telemetry, GitHub, email or a user-facing URL. Do not forward OAuth bearer tokens. Provisioning HMAC secret must be dedicated to the *public API-to-operator* channel, distinct from public worker owner-binding and Ed25519 signing keys, and from all Private deployment secrets. Do not pass it as a command argument. Use root/operator credential files or restricted systemd credentials.

## Operator-only one-shot adapter

`scripts/browser_provision_from_intent.py` can consume one **operator-local** 0600 request file inside a private (0700) directory. It authenticates the signed request, atomically consumes the nonce, and calls the existing `scripts/browser_worker_lifecycle.py` provisioning function with a temporary 0600 owner JSON that is deleted even if provisioning fails. No raw OAuth bearer token, cookie, signing key, or owner identity is placed in command-line arguments or printed as output. The operator must run it with a dedicated `COMMANDCORE_BROWSER_PROVISION_REQUEST_KEY` and a **different** `COMMANDCORE_BROWSER_WORKER_BINDING_KEY`, from restricted systemd credentials, not passed on the CLI.

This is a narrow **local CLI**, not an HTTP endpoint and not an automatically invoked service. It requires a future authenticated local IPC receiver that stores a verified request in operator-owned storage and invokes it. Its unit tests replace the physical `provision` implementation with a stub, so they never start Docker or change production operator state. An operator deployment must provision quotas and networks separately, verify final physical worker attestation, then install a safe per-owner relay and routing manifest before enabling the public feature.

## Next integration work (NOT implemented)

1. Design peer-credential-checked local IPC. Require verified `Principal` at API entrypoint; authorize one bounded request per owner, require tenant cap, quota and rate limiting, and never accept a client-supplied owner triple.
2. Attach the local operator-only request adapter to the peer-verified IPC receiver, with durable queue/ack status and rate limits. Its envelope checks and owner lifecycle call are locally testable; production provisioning, quotas and failure recovery still require live integration. Limit workers and CPU/RAM on Netti; avoid broad public egress allowlists.
3. Publish only signed physical-worker manifests and API-readable immutable owner-binding evidence. API must not receive signing seed, Docker or mutable operator registry. Use atomic snapshot versions and fail closed on changes.
4. Implement a secure control/data relay so the API can reach only the selected worker's Steel/CDP/egress boundary without joining every tenant's isolated network. Validate authorization *before* routing and *after* each browser action; do not make per-worker control networks routable to all API tenants.
5. Implement manifest hot reload/reconciliation with no cross-owner session adoption, restart/stale-card handling and 15-minute idle expiry. Deny forged, replayed, unowned and unverified workers.
6. Perform disposable two-real-user Auth0 + ChatGPT acceptance and public canary/rollback. Enforce public/private release parity at the shared-source layer but do not share their runtime secrets or devices.

Do not set `COMMANDCORE_BROWSER_ENABLED=true` solely because the envelope tests pass. Legal/Privacy and OpenAI rc10 reviewer gates remain separate.
