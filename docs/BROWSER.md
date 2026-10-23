# Managed Browser

The managed Browser is an optional Linux deployment candidate. It runs in a
separately provisioned browser worker, not in an enrolled device's signed-in
desktop Chrome. The ordinary Agent and server package versions are independent
of the Browser UI build.

## User flow

Ask the AI to research a topic, inspect documentation, compare public product
pages, or follow a search result. A workflow opens one compact CommandCore card.
The card shows current activity and an inline page preview while browsing.
Expand it for Browser controls, Back/Forward, fit/zoom, preview pause/refresh,
recent navigation, or private control. Preview pause only pauses preview updates.

Search uses public terms in a Google search URL. Page links have short-lived
references checked against the current visible page before GET navigation.
Changed or expired links require another page inspection. Back/Forward opens
recorded public addresses without replaying form submissions.

For sign-in, verification, forms, basket changes, checkout, or other website
actions that require human control, choose **Use privately**. The AI loses
screen access and action authority until the authenticated owner chooses
**Resume AI control**. Closing or expiring the private link does not resume AI
control. A blocked action is not retried automatically.

Completed cards retain a small display summary without reconnecting. A saved
legacy card cannot prove its old conversation and stays neutral. An active
connection problem offers **Details → Retry live updates**. Retrying reads
status; it does not replay a website action or device command.

## Operator requirements

Browser is disabled by default. Enabling `COMMANDCORE_BROWSER_ENABLED` alone is
insufficient. The existing deployment must provide all of these boundaries:

- OAuth/OIDC, HTTPS, account grants, and verified conversation viewer scope;
- a distinct private Steel process and immutable owner binding per worker;
- isolated browser, control, and outbound networks, with no public CDP/Steel
  port and no Docker socket in the API container;
- the deny-private HTTPS CONNECT proxy for every browser egress path, including
  redirects/subresources; no direct browser internet or internal-network route;
- the reviewed Chromium sandbox/seccomp profile, resource limits, an explicitly
  configured host allowlist, and fresh signed operator worker-identity proofs;
- persistent private worker bindings and encrypted session journals, backed up
  with their configuration. A recovered private session stays paused.

The API validates the operator manifest, owner bindings, proof freshness and
physical worker identities. Missing or stale evidence denies Browser access.
The operator orchestrator is separate from MCP. This source release does not
provide a one-command fresh Browser infrastructure installer. Retain an already
verified deployment or complete the boundary acceptance before enabling it.

`COMMANDCORE_BROWSER_ALLOW_HOSTS=*` means public DNS destinations only. It does
not authorize private IPs, local names, metadata endpoints, arbitrary protocols,
or non-443 ports. Prefer a narrower allowlist when possible. Page content is
untrusted data and cannot authorize sending information or changing accounts.

## Task history, backup and rollback

`COMMANDCORE_UI_TASK_DB` defaults to `ui-tasks.sqlite3` beside `COMMANDCORE_DB`.
The adjacent `.session-key` is a random private conversation-tag key. Back up
and restore the database and key together, using a consistent SQLite backup
while quiescent. Preserve owner-only permissions. Never put either in source,
release archives or diagnostic output. Viewers and live screenshots are not
persisted. Native Windows server test/runtime keeps task summaries in memory only;
there is no durable card history or supported native Browser worker deployment.
Losing the key cannot be repaired by rebinding old task IDs.

Before changing a service, close its test Browser sessions, retain the previous
image and exact source hashes, and back up state. Apply via an independent
operator process, verify health plus OAuth/core/browser acceptance, and restore
the previous artifact if health fails. Do not delete journals to bypass a
recovery or ownership failure.

## Verification and limits

Run Python tests, repository policy/secret checks and the MCP contract gate.
For isolated UI tests:

```sh
npm ci --prefix tests/ui
npx --prefix tests/ui playwright install --with-deps chromium
PYTHONPATH=apps/server python scripts/ui_smoke.py
```

Fixtures cover 320/390/940-pixel widths, inline height/preview, private shielding,
history, stale responses, expiry recovery and completed-card restore. These are
responsive web checks, not native Android acceptance. A deployment still needs
real client acceptance and security review of its network topology. Arbitrary
sites may deny automation, require verification, or require private control.
Automatic purchases and automatic basket mutation are not supported flows.
