# Live two-account OAuth/MCP acceptance (M1 release gate)

**Status: NOT YET VERIFIED.** This is a repeatable test procedure, not a
claim of public Auth0 acceptance. Automated signed-token and mock-Agent tests
must not be substituted for real separate-account evidence.

## Isolation prerequisites

Use **two independent Auth0 user identities** (A and B), separate browser
profiles or private sessions, and **disposable** test devices/agents, with no
access to personal production machines. A and B must authenticate through the
actual public MCP resource. Use the production-equivalent configuration, but
never grant broad test privileges to unrelated users or devices.

Record only redacted evidence: test timestamp, build/digest, OAuth issuer and
audience identifiers (not raw tokens), actor A/B aliases, device aliases,
HTTP/MCP status or safe error codes, and correlation IDs. Do not put cookies,
JWTs, selection handles, screenshots containing private material, or device
keys into issues or CI artifacts. Store sensitive raw traces outside the
public repository under restricted access.

Confirm the two identities produce distinct verified issuer/subject pairs.
Create and register test devices A and B under their respective accounts.
Initial grant and local ceilings should be READ_ONLY. Record the exact
permission and expected result before raising a ceiling.

## Acceptance matrix

| ID | Actor and operation | Expected invariant |
| --- | --- | --- |
| A01 | A authenticates, calls `auth.whoami`, `devices.list` | Only A's grants and device identities appear |
| A02 | B authenticates, calls `auth.whoami`, `devices.list` | Only B's grants and device identities appear |
| A03 | A requests `devices.info` / `system.info` for B's immutable ID | Denied; no B agent dispatch |
| A04 | B requests A's device by immutable ID | Denied; no A agent dispatch |
| A05 | A attempts to use B's `selection_id`, then reverse | Both denied, including after reconnect |
| A06 | READ_ONLY user requests STANDARD shell / privileged action | Denied; no dispatch |
| A07 | A device grant downgraded from STANDARD to READ_ONLY after selection | Previously issued selection no longer authorizes STANDARD |
| A08 | A's device grant revoked after selection | Device hidden; operation denied even with old handle |
| A09 | Logout, expiry, and fresh login as a different account in same browser | No stale device, task, activity, Browser frame or permissions leaked |
| A10 | Concurrent A/B calls to independently owned devices | Outputs and operation receipts remain isolated |
| A11 | Attempt Browser session/frame/watch/close across owners and clients | No cross-owner or cross-client session takeover |
| A12 | Browser private human takeover/approval and return | AI cannot bypass private control or reuse expired approval |
| A13 | Valid FULL OAuth token with READ_ONLY grant/local ceiling | Cannot exceed either permission ceiling |
| A14 | Invalid JWT issuer, audience, expiry, scope, and no token | Authentication/authorization fails closed |
| A15 | Public discovery of `commandcore:admin` vs actual Auth0 API permissions | Metadata matches intentional policy; ADMIN never implied by FULL |

For A07/A08, use only disposable resources and test grant-management
interfaces already authorized for the test operator. Do not grant ADMIN
to ordinary test accounts to make a scenario pass. For A11/A12, use a
dedicated disposable Browser worker and non-sensitive sites.

## Procedure

1. Save the exact reviewed source commit and **deployed** image digest; do not
   assume merging `main` deployed either environment.
2. Verify HTTPS, OAuth protected-resource metadata, actual issuer/audience
   and least-privilege scopes; confirm public bootstrap and recovery are off.
3. Complete Code + PKCE login independently as A and B. Call `auth.whoami`
   and record *redacted* identity evidence and authorized device counts.
4. Run A01-A06 using read-only probes first. Confirm deny events are audited
   and no foreign Agent received an execution.
5. Grant only the disposable device the minimum STANDARD scope/ceiling needed
   for A07/A08, and test downgrade/revoke immediately.
6. Run A09-A12 in separate Browser sessions and explicitly test cross-client
   access, expired approvals, and private human handoff.
7. Run A13/A14 with disposable credentials/fixtures in an isolated test
   environment; do not copy or publish real bearer tokens.
8. Compare discovery scope metadata with real Auth0 RBAC and API permissions
   for A15. Do not enable `commandcore:admin` just to satisfy metadata.
9. Capture pass/fail per matrix ID, redacted trace reference, timestamp and
   tester. Restore/revoke test grants and dispose of test devices/sessions.
10. If any cross-user execution or data disclosure succeeds, **STOP SHIP**,
    preserve restricted evidence, and follow `SECURITY.md`; do not file
    exploit steps in a public issue.

## Repeatable real-account preflight (A01–A06 subset)

The repository includes `scripts/live_mcp_two_user_probe.py`, a manually
invoked, read-only-scoped MCP test against the real HTTPS resource. It checks
independent OAuth issuer/subjects, own/foreign grants and device lists,
cross-user device references, foreign selection handles, and refusal of a
harmless `shell.exec true` request under READ_ONLY scope.

**Prerequisites:** two independently authenticated disposable test accounts,
two separate disposable enrolled test devices, and **READ_ONLY-only** OAuth
scopes for both accounts. Never point this test at personal machines. Obtain
the two real access tokens through the normal OAuth/PKCE flow and supply them
through a restricted, temporary operator environment. Do not paste them into
chat, shell command arguments/history, issue comments, CI variables or logs.

The script requires these five environment variables (values intentionally
omitted from public documentation):

```text
COMMANDCORE_TEST_ORIGIN
COMMANDCORE_TEST_A_TOKEN
COMMANDCORE_TEST_B_TOKEN
COMMANDCORE_TEST_A_DEVICE_ID
COMMANDCORE_TEST_B_DEVICE_ID
```

Then, in the restricted operator session:

```bash
python scripts/live_mcp_two_user_probe.py
```

Without a fixture it exits with `NOT_RUN` (status 2). The script prints only
test labels and PASS/FAIL (no tokens, users, device identifiers, selection
handles or raw HTTP bodies). Exit 0 requires the tested subset to pass.
HTTP errors, Cloudflare challenges, malformed protocol results, same-account
tokens and unexpected execution **fail**, not count as authorization denials.

This **does not** test A07–A15, Browser ownership, logout, operator audit,
real agent dispatch-denial evidence, or release digest parity. Record those
manually under this matrix. A passing probe alone never closes M1.

## Release decision

M1 remains open until A01-A15 are evidenced on real independent accounts,
the deployed digest is recorded, all failed checks are remediated/retested,
and the reviewer records explicit sign-off in the private acceptance report.
Link only a sanitized summary to issues #122 and #125.

Automation already covers parts of this matrix in
`tests/test_oauth_and_grants.py` and other MCP/Browser regression suites.
Those are helpful characterization tests, **not** live Auth0 acceptance.

Related: [OAuth/MCP](OAUTH_MCP.md), [ChatGPT](clients/CHATGPT.md),
[Security model](SECURITY_MODEL.md), [Browser](BROWSER.md).
