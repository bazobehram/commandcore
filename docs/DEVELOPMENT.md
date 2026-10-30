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

The repository treats Pyflakes-class Ruff rules (`F`) as a whole-tree correctness
gate and `ruff format` as the canonical Python formatter. Use `make format` before
submitting Python changes and keep formatting-only changes separate from behavior
changes when practical.

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
npm run test:api  # Node built-in tests: login/session, logout, mutation, HTTP errors
npm run build     # Angular AOT production compilation
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
The two-account Browser/authorization end-to-end acceptance tests are tracked
separately in the 1.0 release-readiness program.

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
