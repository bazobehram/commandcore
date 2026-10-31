# M1: Two-account OAuth/MCP acceptance gate

This work belongs to release master issue #122 and authorization issue #125.
CI checks are useful but must never be represented as real public user validation.

## Offline security regression (implemented)

Run: python -m pytest tests/test_oauth_signed_two_user_mcp.py -q

The tests generate signed disposable access tokens and a local SQLite database;
they exercise the real JWT verifier, MCP handler and tool service across Alice
and Bob, while stubbing external JWKS and Agent dispatch. Invalid audience,
issuer, expiration and signature must return 401. Device IDs, selection
handles, grants and permission ceilings must prevent cross-user execution.
No real Auth0 accounts, credentials, devices or external endpoints are used.

## Real external acceptance (NOT YET DONE)

Perform these cases on an isolated test deployment with **two independent Auth0
accounts and disposable devices**; verify the public issuer, audience, scopes,
RBAC settings and resource metadata first:

1. A and B log in separately, enumerate only their own devices, and cannot
   query each other's managed-device endpoints or audit records.
2. Guess device IDs and replay the other account's selection handle, including
   shell operations. Verify zero unauthorized Agent dispatch.
3. Grant B READ_ONLY or STANDARD on A's test device, test the expected limited
   access, then downgrade/revoke. Reuse prior handles and unexpired JWTs: access
   must stop immediately.
4. Attempt FULL_CONTROL without provider scope, panel manager permission,
   local helper readiness and local Agent ceiling. All must be denied.
5. Browser sessions, screenshots, frames, handoffs and approvals for A must
   remain inaccessible to B, before and after logout/reconnect.
6. Test missing, expired, wrong issuer/audience, and revoked credentials.
   Confirm 401 or documented denial with no side effects.
7. Test concurrent operations, disconnection, session expiration and OAuth
   logout. Verify recorded audit without leaking tokens or sensitive payloads.
8. Confirm non-admin public accounts never get commandcore:admin authority.

Record only redacted audit IDs, tool names, HTTP codes and supported trace
evidence. Do not place real JWTs, OAuth client secrets, test screenshots,
personal agent identities or production data in GitHub Actions artifacts.

**Stop-ship rule:** Keep issue #125 open until both synthetic CI and real
two-account acceptance pass and critical/high security findings are resolved.
A green test suite is necessary but not sufficient.
