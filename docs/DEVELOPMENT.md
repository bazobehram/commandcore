# Development

## Requirements

- Python 3.11+
- Rust toolchain pinned by `rust-toolchain.toml`
- Node.js for web-panel syntax checks
- Docker for container/release acceptance work
- dependencies in `requirements-dev.txt`

## Run server

```bash
export COMMANDCORE_API_TOKEN=$(./scripts/generate-secret.sh)
export COMMANDCORE_DB=/tmp/commandcore-dev.sqlite3
PYTHONPATH=apps/server python -m commandcore_server.main
```

## Verification

```bash
make lint
make format-check
PYTHONPATH=apps/server:agent pytest -q tests
PYTHONPATH=apps/server:agent python scripts/integration_smoke.py
cargo fmt --manifest-path agent/rust/Cargo.toml --check
cargo clippy --locked --manifest-path agent/rust/Cargo.toml --all-targets --all-features -- -D warnings
cargo test --locked --manifest-path agent/rust/Cargo.toml
python scripts/public_repo_check.py
python scripts/secret_scan.py --history
```

For the MCP wire contract, run the focused characterization suite before
changing protocol framing or response shapes:

```bash
PYTHONPATH=apps/server:agent pytest -q tests/test_mcp_protocol.py tests/test_mcp.py
```

`commandcore_server/mcp_protocol.py` owns JSON-RPC envelopes, modern MCP
header/metadata validation, and legacy/modern response shaping. It does not
authenticate principals, authorize tools, or dispatch operations. These tests
prove protocol compatibility only; OAuth, device grants and Browser ownership
require their separate server-side security suites.

For MCP task lifecycle and persistence changes, run the owner-scoped ledger and
restart suites:

```bash
PYTHONPATH=apps/server:agent pytest -q tests/test_mcp_task_ledger.py tests/test_task_lifecycle.py tests/test_task_memory_ledger.py tests/test_task_restart_identity.py
```

`commandcore_server/mcp_task_ledger.py` stores only task/call summaries. It
must not persist command arguments, output, file paths, screenshots, browser
tokens or credentials. Owner identity includes issuer, subject and client ID;
all task lookups and history queries must remain conversation-scoped. On
restart, in-flight remote calls are marked interrupted, never assumed complete.

The repository treats Pyflakes-class Ruff rules (`F`) as a whole-tree correctness
gate and `ruff format` as the canonical Python formatter. Use `make format` before
submitting Python changes and keep formatting-only changes separate from behavior
changes when practical.

## Server tool scope policy

The tool_scope_policy.py module centralizes the FULL/READ/STANDARD OAuth
classification. Both published MCP securitySchemes and the ToolService
execution path use it, preventing drift between advertised metadata and
runtime checks. The existing tools.py exports and all schema definitions
remain compatible.

Classification is not authorization: the server still validates a signed
principal, active device grant, permission profile, local Agent maximum
and approval gates. MCP read-only/destructive annotations only describe
UX, not actual permissions.

Before editing scopes, run the focused Python tests in
tests/test_tool_scope_policy.py, tests/test_oauth_and_grants.py and
tests/test_mcp.py, plus scripts/mcp_release_gate.py. New scope changes need
positive and negative authorization tests and review of the MCP contract.

## Device authorization and execution: contributor map

The MCP-facing `mcp.py` handles protocol requests and task/UI tracking.
`ToolService` in `tools.py` remains the authoritative execution boundary.
Review changes in this order:

1. `_require_scope` checks authenticated OAuth scopes against
   `tool_scope_policy.py`; published annotations are not authorization.
2. `_resolve_device` resolves a principal-scoped selection or explicit device
   ID; explicit IDs take priority. Foreign or stale selections must fail.
3. `_effective_device_profile` intersects server permission, account grant,
   local Agent ceiling and OAuth ceiling. `auth.whoami` reports this result,
   while execution enforces it using `allowed(profile, tool)`.
4. Capability/argument validation happens before `AgentManager.dispatch`.
   The forwarded request excludes device selection handles.
5. Audit and operation tracking remain on the server side. Never move
   authorization into the Angular UI or trust client-supplied permissions.

For changes to this boundary, run:

```bash
PYTHONPATH=apps/server:agent pytest -q tests/test_tool_service.py tests/test_tool_scope_policy.py tests/test_oauth_and_grants.py tests/test_mcp.py tests/test_browser_journey.py
```

Add negative cases for denied scopes, missing/revoked/foreign devices, stale
selections, downgraded grants, local ceilings and unsupported arguments.
These tests do not replace full CI or real multi-account OAuth acceptance.

### ToolService fingerprint review

`tests/test_browser_journey.py` intentionally checks a source fingerprint
of `ToolService`. Any legitimate class change requires an explicit baseline
review: inspect the precise security/ownership/dispatch diff, add regression
tests, document unchanged guarantees, and **only then** update the expected
hash with a review comment. Never change the hash solely to silence CI.
Run the release-candidate gate before merging.

## Angular workspace: API and session boundary

The Angular SPA is at `apps/workspace-angular`. The root component in
`src/app/app.ts` owns view state and calls `request()` from
`src/app/api-client.ts` for same-origin JSON requests. This transport helper
intentionally does **not** own OAuth redirection, token refresh, permission
checks or automatic retries of mutations. It forwards cookies on the same
origin, sets `cache: no-store`, and preserves the HTTP `status` on errors.
Callers handle the expired-session view and the explicit sign-out flow;
backend authorization remains authoritative.

From a clean checkout with Node.js 24+ and npm:

```bash
cd apps/workspace-angular
npm ci
npm run test:api   # Node built-in tests: login/session, logout, mutation, HTTP errors
npm run test:unit  # Angular component/DOM session lifecycle tests (Vitest/jsdom)
npm run build      # Angular AOT production compilation
```

`test/api-client.test.mjs` uses mocked `fetch`: it makes no external requests
and uses no real user credentials. The public-site CI build runs this suite
before packaging the Angular app. Add a negative test for any change that
could affect the session cookie, error handling, retry behavior or privilege
boundaries. The UI must never be treated as the authorization authority.

## Workspace session lifecycle and stale-response protection

The Angular workspace uses `src/app/session-epoch.ts` to track a monotonically
increasing session generation. A request that was started before logout,
HTTP 401 expiry or an account switch must not repopulate the UI with stale
device details, permissions, audit records, Browser frames or activity data.

`App.endSession()` invalidates the generation and clears user-specific state.
The backend continues to enforce all authorization; these guards are a
**client-side privacy and correctness defense**, not a substitute for
server-side access control. Network timeouts or HTTP 503 do not imply an
expired session, and authentication is not reattempted automatically.

Run `npm run test:api` for deterministic, credential-free tests of the
session generation contract, and `npm run build` for Angular type-checking.
Run `npm run test:unit` for component-level login, account-menu, expiry,
logout and stale-request protections. Unit tests use synthetic API responses
and a simulated DOM: they do **not** verify native mobile viewport rendering,
physical Browser worker boundaries or real Auth0 multiuser access. Those
end-to-end acceptance gates remain separately tracked under the 1.0 roadmap.

## Dependency and CI reproducibility

Use `npm ci`, not a populated developer `node_modules` tree, to validate
the Angular dependency lockfile. GitHub CI runs API tests, component tests
and the production build after a clean install. When updating dependencies,
regenerate the lockfile with the project's declared npm major version, then
run a fresh `npm ci` again before reviewing the change. Do not broaden
runtime dependencies merely to support test fixtures.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the source-module ownership map,
managed Browser boundaries and independent public/private release topology.

## Code boundaries

Do not put provider/client-specific behavior into device registry, job dispatcher, policy or Agent protocol. Client integration belongs under `docs/clients/` and future northbound adapter packages.

Do not add privileged operations to the network-facing Agent merely because `FULL_CONTROL` is desired. Privileged operations belong in the helper boundary.

## Versioning

Version independently when evolution requires it:

- product/server version: `VERSION`
- Agent version: Agent package version
- Agent protocol: currently `1`
- MCP protocol: external standards revision
- individual capability versions: Agent advertisement fields
