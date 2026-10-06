# GitHub repository setup

This document describes the recommended one-time GitHub configuration for the
public CommandCore repository.

## Publication rule

Publish from the reviewed clean repository history only.

Do not convert an older private development repository to public visibility if
its history contains deployment-specific configuration, credentials, internal
hostnames, private evidence, or other material that is intentionally absent from
the public tree.

Recommended migration:

1. keep the old development repository private and rename/archive it;
2. create a new empty public-target repository named `commandcore`;
3. push the reviewed clean `main` history;
4. let Actions run before enabling required status checks;
5. configure rules and security settings below;
6. verify a fresh public clone independently;
7. only then announce the repository or publish binary releases.

## Repository settings

Recommended:

- default branch: `main`;
- Issues: enabled;
- Discussions: optional;
- Wiki: disabled unless it has a defined maintenance purpose;
- squash merge: enabled and default;
- merge commits: disabled;
- rebase merge: disabled;
- automatically delete head branches after merge: enabled;
- allow auto-merge: optional after branch rules are active;
- Actions workflow permissions: read-only by default, with per-workflow elevation
  only when a workflow genuinely needs it.

## Default branch rules

Protect `main` with a ruleset or branch protection rule.

Require:

- pull request before merge;
- at least one approval;
- stale approval dismissal after new commits;
- CODEOWNERS review for owned paths;
- all review conversations resolved;
- successful required checks;
- branch up to date before merge;
- linear history;
- signed commits if the project later standardizes on cryptographic signing;
- no force push;
- no branch deletion.

Do not allow ordinary maintainer bypass. Emergency security work may use GitHub's
private security-advisory workflow, but still requires review and regression
tests before public merge.

After the first Actions run, require the checks corresponding to:

- Python 3.11;
- Python 3.13;
- Linux FULL_CONTROL isolation;
- Rust Agent parity;
- Windows candidate gate;
- dependency/security audit;
- public repository policy;
- DCO sign-off.

GitHub check display names can change with workflow/matrix formatting; select the
actual check names produced by the current workflows rather than guessing them
manually.

## Security settings

Enable:

- Private Vulnerability Reporting;
- Dependabot alerts;
- Dependabot security updates;
- dependency graph;
- secret scanning and push protection when available for the repository/account;
- code scanning if/when a maintained CodeQL configuration is added.

Do not add production secrets to Actions merely to make integration tests pass.
Real-provider acceptance should use a deliberately scoped test environment and
document its boundary.

## Repository metadata

Description:

> Self-hosted, vendor-neutral remote computer control plane for MCP and AI clients.

Suggested topics:

- `mcp`
- `model-context-protocol`
- `remote-control`
- `self-hosted`
- `ai-agents`
- `rust`
- `python`
- `systems-administration`
- `oauth`
- `open-source`

License detection should resolve from the root `LICENSE` file as
AGPL-3.0-or-later.

## Release settings

Do not create a GitHub Release merely because the source repository is public.

A release follows `docs/RELEASE.md` and `docs/PUBLIC_RELEASE_CHECKLIST.md` and
must be traceable to the reviewed source commit. Signed Agent artifacts, hashes,
SBOM, provenance, platform evidence, and known limitations belong with the
release.
