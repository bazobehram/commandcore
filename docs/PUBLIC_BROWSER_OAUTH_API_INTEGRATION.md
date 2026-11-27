# Public Browser OAuth allocation entrypoint — source-only, disabled by default

**Status (2026-11-22):** code and synthetic tests only. This is NOT a deployed API-to-operator connection. Public Browser must stay disabled until per-tenant worker network relay and real Auth0/ChatGPT acceptance are complete.

This extends PRs #273-#275 without granting Docker privileges or Ed25519 private signing keys to the API. The new `COMMANDCORE_BROWSER_PROVISION_API_ENABLED=false` (default) setting may be enabled **only** together with OAuth, Browser, dynamic worker manifest and verified Ed25519 public proof. Independent settings must provide an API-readable dedicated 0600 provisioning secret file, restricted operator Unix socket, expected operator host UID/GID and a protected read-only worker manifest/owner-binding snapshot. No web request may submit an issuer, subject, client ID or OAuth bearer token as an operator identity; the caller uses only the server-verified OAuth `Principal`.

`ToolService` now offers a conditional flow on `browser.open` only. All existing scope and conversation checks run before allocation. A new owner without a worker may submit a 60-second, signed purpose-bound intent to the peer-authenticated operator. READ-only, bootstrap, absent issuer/client and other unauthenticated cases are denied. Only the operator chooses container images, egress policy, worker IDs and resource constraints. No other browser operations start allocation. A preexisting owner binding with stale/missing physical proof is not interpreted as permission to allocate a replacement.

The API has a bounded per-process 256-owner pending-intent cache and a 10-minute no-auto-retry period after unknown outcomes. This is **not** a production substitute for durable operator job state, global quotas/rate limits or multi-API-instance coordination. A transport ACK means only that the operator accepted the request; the Browser action still needs an owner-bound worker with a current operator-signed physical attestation and reachable, isolated Steel/CDP control relay. Do not claim Browser ready from the ACK.

Encrypted conversation leases now use a per-worker file and worker-ID-separated key for dynamic pools. Stable conversation tags derive from the existing owner-binding secret even when the process starts with zero workers. A newly created owner can open only in the authenticated host chat; after an API restart, the existing owner and exact session ID must still match the encrypted recovery entry. Sessions, handoff tokens and pending status do not become transferable to other OAuth owners or chats. The legacy single-worker private Browser lease path remains unchanged.

## Not yet implemented — production stop-ship

- Install operator provisioning socket with a **separate** restricted host group, dedicated credentials, exact API UID/GID verification and a durable job queue/ack/recovery. Do not reuse the current read-only attestation group for writable intents.
- Publish versioned, verified read-only owner binding snapshots and a signed worker route manifest to the API; support revocation, deletion and worker quota reset without exposing the operator's registry or HMAC key to other users.
- Implement the **tenant-isolated Steel HTTP/CDP/WebSocket relay**. Current per-worker Docker control networks are not reachable from the public API. Never solve this by attaching the API to every tenant network or publishing unprotected Docker ports.
- Validate 2 real Auth0 reviewer users and isolated demo devices against ChatGPT, negative cross-tenant session/egress tests, idle expiry, restart/rollback and private/public parity.
- Approve and publish actual `/privacy` and `/terms` policies, rerun OpenAI draft MCP Rescan and supply complete reviewer evidence before submission.

The added tests exercise synthetic OAuth principals, actor-signed intents, operator acceptance stubs, replay/unknown-outcome suppression, bad credential files, bounded pending admission, per-worker encrypted lease recovery and cross-chat refusal. Tests do not exercise a real OAuth identity provider, live operator allocation or physical CDP relay.
