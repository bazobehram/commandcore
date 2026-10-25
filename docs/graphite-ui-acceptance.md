# Graphite Control Plane UI — acceptance and recovery

## Scope
The source of truth is `apps/web/index.html`, `apps/web/panel.css`, and `apps/web/panel.js`.
This update is frontend-only. Do not migrate device identities, alter OAuth scope enforcement,
replace persistent volumes, or change other devices to deploy this UI.

## Visual and interaction requirements
- Compact graphite device cards with matching permission-panel heights.
- Full Control uses sage, Standard uses amber; machine permission enums remain unchanged.
- Owner-only device permission management retains a confirmation step.
- Browser has active, empty, error and private-control UI states.
- Browser session switches must reject outdated responses from the previous session.
- Private control must hide screenshots and URLs and retain the private-control link
  until the owning session changes or ends.
- Browser Refresh re-queries session ownership, not just the current frame.
- Mobile controls have no horizontal overflow.

## Regression tests
Install dev dependencies in `tests/ui`, then run:

```sh
npm --prefix tests/ui ci
npm --prefix tests/ui run test:graphite
```

If Playwright Chromium is not installed, set `COMMANDCORE_CHROME_BIN` to a
locally installed trusted Chromium binary. The tests serve local static UI
files, simulate API responses, and never modify live device policies.

## Operational verification
Before and after deployment, confirm Control Plane health and inspect
the UI at desktop and mobile widths. Avoid recreating the production container
while its unrelated bind-mounted backend overlays are unverified.

## Recovery
The production environment maintains time-stamped `panel.js` and `panel.css`
backups alongside the bound UI files. Restore both from the same known-good
snapshot and verify the original service health if a regression appears.
