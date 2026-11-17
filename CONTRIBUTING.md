# Contributing to CommandCore

Thank you for helping improve CommandCore.

CommandCore controls real computers and can cross important security boundaries.
Changes are reviewed with that risk in mind. Small, focused pull requests with
clear test evidence are strongly preferred.

## Ground rules

- Use a pull request. Do not develop directly on the default branch.
- Keep each pull request focused on one coherent change.
- Do not include secrets, production configuration, device identities, private
  keys, access tokens, databases, backups, or private deployment logs.
- Do not weaken authorization, transport verification, update verification, or
  local privilege boundaries to make a test pass.
- Do not claim a platform or client is supported unless the documented acceptance
  criteria have actually passed.
- New behavior requires tests. Security-sensitive behavior requires negative tests
  as well as success-path tests.
- Public interfaces and protocols require compatibility notes.

## First contribution: fork, test, and open a PR

A fork is a separate copy of CommandCore. Do not point a local evaluation
server at someone else's production devices, database, OAuth tenant, or signing
keys. Start from the public repository and test in a disposable environment.

1. Fork [bazobehram/commandcore](https://github.com/bazobehram/commandcore)
   on GitHub, then clone **your fork** (substitute your own account name):

   ~~~bash
   git clone https://github.com/YOUR-USERNAME/commandcore.git
   cd commandcore
   git remote add upstream https://github.com/bazobehram/commandcore.git
   git switch -c docs/my-first-contribution
   ~~~

2. Read [AGENTS.md](AGENTS.md) if you use an AI coding agent. That file defines
   the project's permission and deployment boundaries; do not let an agent
   modify real devices or expose a service simply to run tests.
3. Install the development dependencies below and run the checks relevant to
   your change. For a documentation-only PR, run
   `python scripts/public_repo_check.py` and check changed Markdown links.
4. Commit with your own verified Git author identity and **DCO sign-off**:
   `git add <changed-files>`, then `git commit -s -m "docs: explain example"`.
   Do not copy another person's Signed-off-by identity.
5. Push the branch to your fork and open a pull request against
   `bazobehram/commandcore:main`. Fill in the PR template with actual test
   evidence and any compatibility or permission impact. GitHub Actions checks
   must pass before a maintainer can merge.

For a later contribution, fetch `upstream/main` before branching; do not
force-push or rewrite the original repository's history. If CI fails, open the
failed job log and fix the underlying issue. Do not skip security or DCO gates.

## Developer Certificate of Origin

CommandCore uses the Developer Certificate of Origin 1.1 instead of a separate
contributor license agreement.

Every commit must include a Signed-off-by trailer certifying that you have the
right to submit the contribution under the project's license.

Example:

~~~text
Signed-off-by: Contributor Name <contributor@example.com>
~~~

Git can add the trailer automatically:

~~~bash
git commit -s
~~~

By signing off, you certify the Developer Certificate of Origin 1.1 published at
https://developercertificate.org/.

## Development setup

Requirements:

- Python 3.11 or newer
- Rust toolchain pinned by `rust-toolchain.toml`
- Node.js 24+ and npm for the Angular workspace (Node.js also checks legacy panels)
- Docker for the locked container build and selected integration tests

Setup:

~~~bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements-dev.txt -e . -e ./agent
~~~

Core verification:

~~~bash
make lint
make format-check
pytest -q
python scripts/enrollment_smoke.py
node --check apps/web/panel.js
node --check apps/web/legacy-admin.js
node scripts/legacy_admin_smoke.mjs

cargo fmt --manifest-path agent/rust/Cargo.toml --check
cargo clippy --locked --manifest-path agent/rust/Cargo.toml --all-targets --all-features -- -D warnings
cargo test --locked --manifest-path agent/rust/Cargo.toml
cargo build --locked --release --manifest-path agent/rust/Cargo.toml

python scripts/public_repo_check.py
python scripts/secret_scan.py --history
~~~

Angular workspace verification (isolated API contract tests run before the
production build):

~~~bash
cd apps/workspace-angular
npm ci
npm run test:api
npm run test:unit
npm run build
~~~

Angular component tests use Vitest and a simulated DOM (no live OAuth accounts or real devices). New components/services generate tests by default; keep these tests isolated and include negative session cases. CI runs API tests, component tests, and the production build.

The API boundary lives in `src/app/api-client.ts`. Preserve its same-origin
cookie, no-cache, HTTP-status and error semantics when refactoring. The server,
not the Angular UI, enforces OAuth scopes and per-device permissions. See
[Development](docs/DEVELOPMENT.md) for the architecture and testing contract.

Privileged helper tests must run only in a disposable VM/container or another
explicitly isolated test environment. Never run privileged acceptance against
unrelated host workloads.

## Pull request titles

Use a short conventional prefix so release notes remain readable:

- feat: new user-visible capability
- fix: defect correction
- security: security-boundary correction or hardening
- perf: performance improvement
- refactor: behavior-preserving internal change
- docs: documentation only
- test: test-only change
- build: build, packaging, CI, or dependency change
- chore: repository maintenance

Optional scope is encouraged, for example:

~~~text
feat(agent): persist managed process output across reconnect
security(auth): reject audience mismatch before device lookup
docs: add generic OIDC deployment guide
~~~

## Pull request requirements

A pull request is mergeable only when:

1. required CI checks pass;
2. every commit has DCO sign-off;
3. review conversations are resolved;
4. the change is documented when behavior or public interfaces change;
5. tests cover the changed behavior;
6. security-sensitive changes receive explicit security review;
7. protocol changes document compatibility and migration impact;
8. platform-support claims include real acceptance evidence.

Squash merge is the default for ordinary pull requests. The pull request title
should therefore be suitable as the final commit subject.

Maintainers may require a rebase, split, additional tests, or a design discussion
before review continues.

## MCP and device authorization review checklist

For `ToolService`, OAuth scope, device-selection or dispatch changes:

- [ ] Check that principal, device-grant and local ceiling enforcement remain server-side.
- [ ] Verify `auth.whoami` and tool execution use consistent effective permissions.
- [ ] Include negative tests for affected authorization boundaries.
- [ ] Review the `ToolService` source fingerprint deliberately rather than
      replacing it just to make CI pass.
- [ ] Follow the [device authorization contributor map](docs/DEVELOPMENT.md#device-authorization-and-execution-contributor-map)
      and run the relevant release gates.

Real two-user OAuth acceptance remains a distinct release requirement.

## Security-sensitive areas

Changes in these areas receive stricter review:

- OAuth/OIDC validation and MCP authorization;
- device enrollment, identity, revocation, and key rotation;
- account-to-device grants and permission ceilings;
- privileged helper IPC and FULL_CONTROL;
- release signing, installers, update/rollback, and fleet rollout;
- protocol canonicalization and signature verification;
- path traversal, symlink handling, shell/process execution;
- audit/redaction behavior.

A security change should explain the threat being addressed, the trust boundary,
failure behavior, and negative test evidence.

## Protocol changes

For MCP contract, Agent Protocol, enrollment, signing, or update-manifest changes:

- preserve backward compatibility where practical;
- version incompatible wire changes;
- update schema/reference documentation;
- add cross-language vectors when signatures or canonicalization change;
- state upgrade and downgrade behavior;
- never silently reinterpret an existing permission.

## Issues

Use GitHub issues for reproducible, non-sensitive bugs and scoped feature
requests. Search existing issues first.

Do not report vulnerabilities, credentials, exploit details, or private deployment
data in a public issue. Follow SECURITY.md instead.

## Licensing of contributions

Unless explicitly stated otherwise in a file, accepted contributions are
licensed under GNU AGPL-3.0-or-later, the same terms as the project.
