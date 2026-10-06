# Project governance

CommandCore uses a maintainer-led open-source governance model.

## Roles

### Contributor

Anyone who reports issues, improves documentation, submits code, reviews changes,
or helps other users.

### Maintainer

A contributor trusted to review and merge changes, manage releases, triage
security reports, and protect project quality. Maintainer access is granted based
on sustained technical contribution, review quality, reliability, and respect for
the security model.

## Decision making

Routine decisions are made through pull-request review.

Changes that materially affect protocol compatibility, authorization, privilege
boundaries, licensing, release signing, or supported-platform promises should be
documented before merge and receive explicit maintainer approval.

For difficult technical decisions, maintainers should prefer written rationale,
testable acceptance criteria, and reversible changes over informal consensus.

## Merge policy

The default branch is intended to be protected.

Expected repository rules:

- pull request required;
- required CI checks must pass;
- at least one approving review;
- stale approvals dismissed after material changes;
- review conversations resolved;
- linear history;
- force pushes and branch deletion disabled;
- CODEOWNERS review for security-sensitive paths when practical.

Ordinary pull requests use squash merge by default.

## Releases

Maintainers own release signing and publication. Release keys must never be stored
in the repository or on the internet-facing control plane.

A release must satisfy the release checklist, dependency/security gates, public
repository scan, and documented platform-support claims before publication.

## Security

Maintainers may embargo security work in a private branch or security advisory.
Security fixes may bypass the normal public design-discussion process until a
patch is available, but they still require review and regression tests.

## Governance changes

Governance changes use the same pull-request process and should explain the
motivation and expected impact on contributors.
