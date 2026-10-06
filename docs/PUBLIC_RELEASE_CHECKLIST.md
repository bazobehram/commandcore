# Public release checklist

Use this checklist before making a source release or changing the repository to
public visibility.

## Repository hygiene

- [ ] Public source tree is generated from the intended release candidate.
- [ ] scripts/public_repo_check.py passes.
- [ ] scripts/secret_scan.py --history passes on the repository that will become public.
- [ ] No private deployment configuration, databases, backups, keys, tokens, or device identities exist in source or history.
- [ ] No private brand/domain/environment references remain.
- [ ] Generated archives and local build artifacts are excluded.
- [ ] README and documentation links pass.

## Licensing

- [ ] LICENSE contains GNU AGPL v3 text.
- [ ] Project metadata declares AGPL-3.0-or-later.
- [ ] CONTRIBUTING documents same-license inbound contributions and DCO.
- [ ] Third-party notices are current.
- [ ] Python, Rust, container, and OS-layer license obligations for distributed artifacts are reviewed.
- [ ] SBOMs are regenerated for the exact release.

## Security

- [ ] SECURITY.md is current.
- [ ] GitHub Private Vulnerability Reporting is enabled before public launch.
- [ ] Threat model and security model match current behavior.
- [ ] OAuth, enrollment, grants, helper IPC, path handling, and signed update negative tests pass.
- [ ] Dependency vulnerability audits pass or accepted exceptions are documented.

## CI and collaboration

- [ ] Required CI runs on pull requests.
- [ ] DCO sign-off check is required.
- [ ] CODEOWNERS is correct.
- [ ] Default branch protection is configured.
- [ ] At least one review is required.
- [ ] Force pushes and default-branch deletion are disabled.
- [ ] Dependabot is enabled.
- [ ] Issue forms and pull request template render correctly.

## Product documentation

- [ ] 5-minute local/development quick start works from a clean checkout.
- [ ] Self-hosting guide works without private infrastructure assumptions.
- [ ] Generic OIDC/OAuth setup is documented.
- [ ] Linux Agent install/upgrade/uninstall flow is reproducible.
- [ ] Platform support table is evidence-based.
- [ ] Client guides distinguish protocol compatibility from live acceptance.
- [ ] Desktop Commander comparison remains factual and source-linked.

## Release engineering

- [ ] Python tests pass.
- [ ] Rust fmt, Clippy, tests, and locked release build pass.
- [ ] Linux x86_64 real lifecycle acceptance passes.
- [ ] Linux ARM64 real/native acceptance evidence is current.
- [ ] Signed manifest verification passes.
- [ ] Artifact hashes and sizes are recorded.
- [ ] Update activation and failed-health rollback pass.
- [ ] Server database backup/restore rehearsal passes.
- [ ] Release signing key is isolated from the public server and repository.

## Publication

- [ ] Create a clean public repository/history rather than exposing private development history.
- [ ] Push the reviewed source commit.
- [ ] Enable branch protection and private vulnerability reporting.
- [ ] Publish release notes with known limitations.
- [ ] Publish only artifacts produced from the reviewed source commit.
- [ ] Verify public clone -> test -> build from a separate clean environment.
- [ ] Verify public documentation and release downloads after publication.

## Post-release

- [ ] Monitor installation/reconnect failures.
- [ ] Triage first-user onboarding friction.
- [ ] Track unsupported-platform requests separately from regressions.
- [ ] Do not broaden support claims until acceptance gates pass.
