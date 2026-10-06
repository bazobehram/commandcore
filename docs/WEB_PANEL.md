# Web panel

Status: **implemented in the 0.9 release-candidate family**.

The panel is an operator surface, not the execution architecture. AI clients use MCP/API and all privileged actions still resolve identity/policy server-side.

## Implemented

- devices: online/offline/pending/revoked, identity, host/platform/architecture;
- Agent/protocol version, implementation and recommended-version drift;
- key generation/rotation status;
- capabilities, helper and local maximum profile;
- READ_ONLY/STANDARD/FULL_CONTROL profile management subject to local ceiling;
- enrollment create/list/cancel and approval;
- OAuth subject device grants/revoke;
- device token rotation/revoke;
- live `system.info` / `system.metrics` snapshot through the Agent path;
- jobs, recent activity and audit;
- update trust readiness and local rollout state;
- **fleet rollout create/list/detail/advance/resume/skip/cancel** with per-device ring/state visibility.

Fleet eligibility requires FULL_CONTROL plus device-advertised local update trust. The panel never sees the trusted private signing key and cannot replace the device's root-owned release public key/origin policy.

## Panel authentication

The bootstrap API token is exchanged for a signed HttpOnly/SameSite=Strict panel session cookie. State-changing panel requests use same-origin protections. OAuth/client API auth remains separate.

## Rollout UX rule

Fleet rollout is deliberately operator-driven. One `advance` performs at most one durable remote lifecycle action. This keeps canary/ring progress observable and prevents a single browser/API call from silently pushing an entire fleet. A future controller may automate repeated safe advances without changing the stored rollout state machine.
