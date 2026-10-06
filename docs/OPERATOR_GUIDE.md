# Operator guide

The operator panel is the human administration surface for devices, enrollment,
grants, audit summaries, and release state.

## First deployment

1. Configure the server and persistent database.
2. Put it behind verified HTTPS/WSS.
3. Configure an OAuth/OIDC provider for remote users.
4. Keep public bootstrap/recovery disabled except during a deliberate recovery
   workflow.
5. Enroll a non-critical test device first.
6. Grant READ_ONLY or STANDARD explicitly.
7. Validate revocation before onboarding critical devices.

## Enrollment

Review:

- device display name;
- platform and architecture;
- local public identity;
- verification code;
- requested local ceiling.

Approval claims the device identity. Operational account access is a separate
grant choice.

Never auto-grant FULL_CONTROL during enrollment.

## Device access

A manager can administer a device without necessarily having shell authority on
it. Management and operation grants are separate concerns.

Effective authority remains bounded by OAuth scope, explicit device grant, server
profile, and device-local ceiling.

## Revocation and rotation

Revocation disconnects the device and removes operational visibility for accounts
that no longer have access.

Device key rotation is initiated locally. Treat emergency credential replacement
as a separate recovery action.

## Audit

Use audit/activity views for execution identity, status, duration, and redacted
operation metadata.

Audit systems should not retain raw access tokens, refresh tokens, private keys,
environment secrets, file payloads, or unredacted shell secrets.

## Backups

Before a server upgrade:

- take a verified SQLite backup;
- record the running server version/image;
- retain the previous application artifact;
- keep configuration backup owner-only;
- verify database restore in an isolated path.

Do not overwrite a live SQLite database file while the server is running.

## Release operations

Release signing private keys must stay off the internet-facing server.

Before rolling out an Agent update, confirm the device advertises trusted update
configuration. Use canary/ring rollout only after local trust is configured and
rollback has been tested.

## Production acceptance

Fixture tokens and simulated Agents validate code paths but do not replace
end-to-end acceptance with the actual OAuth provider, MCP client, reverse proxy,
and operating system used by the deployment.

Start acceptance on a disposable or non-critical device and escalate authority
only after read-only/standard behavior is proven.
