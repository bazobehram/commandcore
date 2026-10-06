# Public repository readiness

Date: 2026-10-06  
Candidate version: `0.9.0-rc7`

## Verdict

**PUBLIC SOURCE REPOSITORY: READY AFTER EXPLICIT OWNER APPROVAL.**

The sanitized source candidate is suitable for creating a new repository from a
fresh history. The previous private Git history must not be imported, grafted, or
force-pushed into the public repository.

**RELEASE ARTIFACT PUBLICATION: CONDITIONAL.**

Before publishing a tagged binary/container release, create the approved public
repository, apply the required repository rules, run the first public CI from the
fresh history, and generate the release artifacts, checksums, signatures/Sigstore
attestations, SBOMs, and provenance from that public commit/tag.

No repository publication, visibility change, or remote push was performed during
this review.

## PASS

- Public repository policy scanner passes.
- Markdown relative-link validation passes through the policy scanner.
- No forbidden private branding, deployment identifiers, private environment
  references, removed internal acceptance documents, generated archives, or
  generated Python bytecode are present in the public candidate.
- CommandCore code and package metadata use `AGPL-3.0-or-later`.
- DCO 1.1 sign-off checking works for a fresh root commit.
- Version consistency is enforced against `VERSION=0.9.0-rc7` for the server,
  Python Agent, Rust Agent, Compose image default, and recommended Agent version.
- Public bootstrap and recovery default to disabled in both configuration and
  `.env.example`.
- Public Compose binds the application port to loopback by default.
- The documented quick start is Compose-first and was validated from a clean
  source copy.
- Python full test suite passes.
- CI-style Python smoke chain passes.
- Python compile/Ruff/format gates pass.
- Rust fmt, strict Clippy, locked tests, and locked release build pass.
- Python dependency audit passes with no known vulnerabilities.
- Rust dependency audit passes against the RustSec advisory database.
- Runtime and Rust SBOMs were regenerated from the final locks.
- Runtime SBOM contents match all 28 locked Python runtime distributions.
- Rust SBOM contents match all 209 registry crates in the Rust lock.
- Container/OS-layer review found Debian copyright metadata for all 87 installed
  OS packages.
- A clean temporary Git repository was built while explicitly excluding the
  existing working-tree Git metadata.
- Source secret scan passes before commit.
- Reachable-history secret scan passes after the root commit.
- The verification repository has one root commit, one reachable commit, a clean
  worktree, and no imported history.

## Exact validation executed

### Python

Full suite in a clean Python 3.13 container with curl and editable project/Agent
installs:

```text
240 passed
1 skipped
1 warning
```

The warning is the known Starlette/FastAPI TestClient deprecation warning.

CI-style smoke scripts completed successfully for:

- MCP/server/Agent round trip and Git operations;
- READ_ONLY/restricted mode;
- OAuth/JWKS validation and per-account grants;
- panel/session and management APIs;
- device-key rotation and reconnect;
- signed update activation and rollback;
- fleet canary/ring rollout;
- enrollment, revocation, reconnect, managed processes, transfer, and system info.

Static Python gates:

```text
python -m compileall -q apps/server agent
ruff check --select F apps agent scripts tests install
ruff format --check apps agent scripts tests install
```

Result: PASS; 107 files already formatted.

### Rust

Executed in a disposable Rust container:

```text
cargo fmt --manifest-path agent/rust/Cargo.toml --check
cargo clippy --locked --manifest-path agent/rust/Cargo.toml --all-targets --all-features -- -D warnings
cargo test --locked --manifest-path agent/rust/Cargo.toml
cargo build --locked --release --manifest-path agent/rust/Cargo.toml
```

Result:

```text
25 passed
0 failed
release build PASS
```

### Dependency/security audits

Python:

```text
pip-audit -r requirements-server.lock
No known vulnerabilities found
```

Rust:

```text
cargo audit --file agent/rust/Cargo.lock
RustSec advisory database loaded
scan completed with exit code 0
```

### Docker / clean-checkout setup

A `.git`-free clean source copy was used with a separate temporary Compose
project, image name, loopback port, network, and volume.

Result:

```json
{"status":"ok","version":"0.9.0-rc7","agents_online":0}
```

Validated defaults:

```text
COMMANDCORE_PUBLIC_BOOTSTRAP_ENABLED=false
COMMANDCORE_RECOVERY_ENABLED=false
```

The temporary container, network, volume, and verification image were removed
after validation.

### Secret/history verification

A new temporary Git repository was initialized from the sanitized source with the
existing source Git metadata explicitly excluded.

Final verification:

```text
final source paths: 234
source secret scan: PASS
DCO root commit check: PASS
history secret scan: PASS
reachable commits: 1
root commits: 1
worktree changes: 0
branch: main
```

This check was repeated after the readiness report and documentation-index update.
Repeat it again immediately before the first remote push if any file changes.

## Source changes made during this review

Security and onboarding:

- defaulted public bootstrap to disabled in server configuration;
- kept public recovery disabled;
- changed the README quick start to Compose-first;
- clarified controlled first-time bootstrap behavior;
- made the secret generator executable;
- expanded `.gitignore` and `.dockerignore` coverage for local databases,
  WAL files, coverage/cache output, environment helpers, and private-key formats;
- updated isolated smoke fixtures to opt into bootstrap explicitly rather than
  relying on an unsafe global default.

Repository policy:

- strengthened the public policy scanner with version consistency, safe defaults,
  localhost Compose binding, additional private-artifact checks, and legacy
  one-off acceptance exclusions;
- made the DCO checker handle a fresh root commit correctly.

Documentation:

- updated the native Rust Agent status from stale pre-validation language to the
  current candidate state;
- updated Linux privilege-helper status;
- updated self-hosting guidance for separate API/panel secrets and fail-closed
  bootstrap defaults;
- regenerated both application SBOMs.

Cleanup:

- removed five fixed-environment, one-off historical Linux acceptance harnesses
  that referenced old release-candidate evidence directories, fixed disposable
  host assumptions, and private feed/service conventions. Reusable CI smoke tests
  remain.

Tests:

- updated browser-auth fixtures for a distinct panel session secret;
- added a regression test proving public bootstrap defaults to disabled.

## Exact files added, modified, or removed

Added:

- `docs/PUBLICATION_READINESS.md`

Modified:

- `.dockerignore`
- `.env.example`
- `.gitignore`
- `README.md`
- `agent/privileged-helper/README.md`
- `agent/rust/README.md`
- `apps/server/commandcore_server/config.py`
- `docs/README.md`
- `docs/SELF_HOSTING.md`
- `docs/sbom/rust-agent.cdx.json`
- `docs/sbom/server.cdx.json`
- `scripts/check_dco.py`
- `scripts/enrollment_smoke.py`
- `scripts/full_control_smoke.py`
- `scripts/generate-secret.sh` (executable mode)
- `scripts/integration_smoke.py`
- `scripts/key_rotation_smoke.py`
- `scripts/oauth_smoke.py`
- `scripts/panel_smoke.py`
- `scripts/public_repo_check.py`
- `scripts/restricted_mode_smoke.py`
- `scripts/rust_agent_smoke.py`
- `scripts/rust_full_control_smoke.py`
- `scripts/signed_rust_canary.py`
- `tests/test_browser_auth_hardening.py`
- `tests/test_config.py`

Removed from the public candidate:

- `scripts/linux_installer_lifecycle_acceptance.py`
- `scripts/linux_resilience_acceptance.py`
- `scripts/linux_systemd_lifecycle.py`
- `scripts/linux_transport_pressure_acceptance.py`
- `scripts/linux_user_manager_acceptance.py`

## Dependency and license review

CommandCore code is licensed under `AGPL-3.0-or-later`; dependencies retain their
own licenses.

The regenerated runtime SBOM contains 28 locked Python packages. Some Python
distributions do not populate the modern `License-Expression` metadata field even
though their package metadata/license files identify their licenses. The Rust
inventory contains license data for all recorded Rust packages.

The container OS layer contains 87 Debian packages and all 87 include packaged
copyright metadata under `/usr/share/doc`.

This is an engineering inventory/review, not a legal opinion. Release packaging
must continue to preserve applicable third-party license and notice obligations.

## Known limitations

These are documented limitations, not publication blockers for the source
repository:

- ChatGPT remote MCP/OAuth integration is live validated.
- Claude, Gemini, and Codex remain remote MCP integration targets pending real
  project acceptance.
- Linux is the primary supported/candidate platform family.
- Windows Python Agent remains preview.
- Windows Rust Agent/helper remains preview/incomplete; FULL_CONTROL must not be
  advertised before real privileged-helper acceptance.
- macOS Agent remains planned.
- Interactive desktop control exists but remains experimental and disabled by
  default until its real interactive-session acceptance matrix is complete.
- Browser automation has no supported backend.
- Platform support is evidence-based; compilation alone does not establish
  support.

## Remaining publication blockers

There are no source-hygiene or test blockers currently known.

Administrative/publication blockers remain:

1. explicit owner approval to create/publish the new public repository;
2. create the repository from the sanitized fresh history only;
3. apply default-branch protection/rules before normal development;
4. run public CI on the actual initial public commit;
5. enable private vulnerability reporting/security advisories;
6. configure release signing/provenance permissions and secrets;
7. publish signed release artifacts only from the approved public tag.

## Recommended GitHub settings

For `main`:

- require pull requests;
- require at least one approval;
- require CODEOWNERS review for sensitive paths;
- dismiss stale approvals after material changes;
- require all conversations resolved;
- require CI and DCO status checks;
- require linear history;
- disable force pushes;
- disable branch deletion;
- use squash merge by default;
- enable Dependabot;
- enable private vulnerability reporting;
- enable security advisories;
- keep merge permissions aligned with CODEOWNERS and security-sensitive paths.

## Publication decision

**Safe to create a new public CommandCore repository from the sanitized fresh
history after explicit owner approval: YES.**

**Safe to reuse or expose the existing private repository/history: NO.**

**Safe to publish a binary/container release before the new public repository,
branch protections, first public CI, and signed/provenance release pipeline are in
place: NO.**
