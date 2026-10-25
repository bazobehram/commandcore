# Linux Full Control onboarding — implementation gates

Status: implementation plan; **not** an available installation or remote elevation flow.

## Authority model

The locally authorized ceiling, server device policy, per-account grant, and OAuth scope independently constrain effective access. Installing a privileged helper is a **device-local** operation and must not be triggered remotely without meaningful local authorization. Having the helper installed does not activate FULL_CONTROL for an account.

## Existing installations

1. Discover agent implementation, local maximum and authenticated helper health without modifying device settings.
2. Display the capability setup state in Device Details; distinguish local preparation from the active permission selector.
3. Provide an authenticated, expiring device-scoped request and locally displayed explanation of root-level powers; require direct confirmation on the Linux computer.
4. Only install helper code whose provenance and integrity have been verified through the signed release chain. Never run remotely supplied shell snippets or a user-owned executable as root.
5. Install the helper/policy with root-owned paths and strict permissions; preserve identity, grants and device state. Verify local authenticated helper health and Agent reconnection.
6. Keep server policy and account grant at STANDARD until the user separately selects FULL_CONTROL in the panel. A failed upgrade must leave STANDARD functional.

## Fresh installations

Offer READ_ONLY, STANDARD (default) or optional Full Control *capability* during an interactive install. Never claim that the public normal-user installer can already provision a root helper. Unattended installs must require explicit opt-in, not an implicit default.

## Panel and API

The UI must use a real supported, authorized permission mutation route with owner checks, CSRF protections, audit entries, explicit current-state comparison and server/local maximum enforcement. A server-grant update alone cannot raise a locally restricted ceiling. Offline devices must not be shown as successfully activated.

## Acceptance before production release

- Unit tests: permission intersection, unauthorized escalation rejection, invalid/local approval expiry, request replay and revocation.
- Linux integration: signed helper provenance, root path ownership, privileged IPC authentication, local confirmation, rollback on failure, agent reconnect, STANDARD -> FULL_CONTROL -> STANDARD.
- UI: clear helper prerequisites, effective permission, pending approvals, account grant changes and mobile rendering.
- Independent deployment verification: production health, no device reenrollment, no broad helper/service changes on other devices.

Release gate: do not expose a functional 'Enable Full Control' button until these tests pass and a signed privileged-helper installation path exists.
