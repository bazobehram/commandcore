# CommandCore Release Completion Gates

Updated 2026-10-25. This document distinguishes evidence from release approval.

## Verified in this pass
- PR #43 head 59f6b48 is draft and production private server remains healthy.
- GitHub CI on PR #43: policy, DCO, release candidate, Windows, security, Browser UI, Rust, Linux, Python passed at the last check.
- Actual browser.open -> browser.observe -> browser.close succeeded for a disposable browser session.
- `PYTHONPATH=apps/server:agent pytest -q tests/test_onboarding_routes.py tests/test_update_lifecycle.py tests/test_browser_security_boundaries.py`: 36 passed.
- Public `/install/linux` and current tracked `install/linux.sh` have **different SHA-256 hashes**. This is a deployment version difference; not, by itself, proof of broken installation.

## Hard release gates (not yet accepted)
1. Compare public Linux installer to signed release artifact and exact published manifest. Test installer in a disposable machine; verify first-time install, reconnect after restart, upgrade, legacy install, key identity preservation, signature enforcement, and rollback. Do not modify live device identity.
2. Verify real Browser lifecycle with authenticated session: owner checks, active task, pause/resume, private takeover, concurrent chat conflict and idle expiry. Confirm Stop terminates the actual browser and that no cross-conversation leakage occurs.
3. Run Android Chrome and installed standalone mode manually or through an actual Android device. Test soft keyboard, viewport, pointer, scroll, controls, safe areas and orientation.
4. Test Activity inline cards during actual operation, command/output timing, accurate exit codes, overflow, performance and privacy redaction; inspect in Chrome and Android.
5. Confirm live enrollment (not a mock), device list real-time updates, loss/reconnect and permissions locally at all layers.
6. Public release requires independently configured Oracle Free instance, separate URLs, OAuth clients and volumes; Browser disabled publicly initially; signed build, CI, monitoring, backups and rollback validated. Do not use private branding in public artifacts.
7. Review scope of PR #43 (consolidated backend overlays) before merge. Green CI is not an approval to merge.

## UX polish before public beta
- Consolidate design tokens; keyboard focus, reduced motion, 375/768/1440/1920 snapshots.
- One coherent shell/Browser/Activity state model, no stale previews or duplicated controls.
- Accessible error/reconnect feedback and guided recovery.
- Revisit 2-second polling versus server push/SSE and cancellation; use backoff when idle.
- Keep owner Full Control explicitly constrained by local device consent/policy.

## Reproducible checks
- `npm --prefix tests/ui run test:graphite`
- `PYTHONPATH=apps/server:agent pytest -q tests/test_onboarding_routes.py tests/test_update_lifecycle.py tests/test_browser_security_boundaries.py`
- `python3 scripts/public_repo_check.py`
- Verify public service health and compare installer SHA-256 in read-only mode.

Do not merge, restart, upgrade agents, or deploy Oracle merely because these checks are green.
