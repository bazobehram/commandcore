# Agent-initiated enrollment protocol

The primary candidate flow is `commandcore-agent enroll https://server`.
Legacy administrator-issued enrollment tokens remain a break-glass compatibility
path; ordinary onboarding needs no token copy, public-key paste or database edit.

1. Agent generates an Ed25519 key, UUID and random device credential locally,
   persisting pending state owner-only before any server request.
2. It signs `commandcore-enroll-init-v1\n` plus sorted compact UTF-8 JSON metadata.
3. Server validates proof/protocol/ceiling and returns distinct random 256-bit
   review and polling credentials, a secondary eight-character code and expiry.
4. The review secret travels in the `/enroll/#...` fragment, not access-log URLs.
5. An authenticated STANDARD-scoped operator reviews the specific identity.
   The first reviewer binds the enrollment to that principal.
6. Approval/rejection checks that reviewer, the code, expiry and pending state.
   The unchecked initial-grant choice is recorded explicitly and audited.
7. Agent signs `commandcore-enroll-claim-v1\n{id}\n{poll-token}`. One transaction
   creates identity/manager/optional grant and consumes both server-side hashes.
8. Server stores only the locally generated credential's SHA-256 hash. The raw
   credential and private key remain on the Agent. The Agent promotes its pending
   identity and starts outbound authenticated WSS.

Pending enrollments expire within ten minutes. Short codes alone authorize nothing.
Raw review/poll credentials and private keys never enter server storage or audit.
Persistent rate limits cover start, review/decision and polling. Cookie mutations
require same-origin evidence; OAuth login uses state + PKCE S256.

## Failures and recovery

Expired/rejected enrollments need a new attempt after removing only the local
pending-enrollment file, retaining any established identity. Replays and duplicate
public identities fail. Review by another principal fails. New enrollment permits
READ_ONLY/STANDARD only; FULL_CONTROL setup is a separate local operation.

If a claim response is lost, rerun the same enrollment command. New Python and
Rust agents retain the device ID, credential and private key in protected pending
state. They authenticate through the normal WebSocket nonce/signature handshake
before promoting that state. Enrollment polling remains single-use and replayed
claims still fail. Recovery creates no new identity, grants or approval.

Older pending states with server-generated credentials still require manager
investigation/revocation and a fresh enrollment after a lost claim response. A
revoked device cannot recover through this path. Never delete established state
to bypass revocation.

The dashboard lists only enrollments previously reviewed by the current account.
Its ID-based decision route also requires that exact reviewer binding and code;
knowing an enrollment ID confers no authorization.
