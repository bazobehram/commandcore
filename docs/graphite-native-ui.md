# Graphite native-feel UI acceptance

Changes: wider responsive desktop grid, restrained first-paint and dialog motion
with prefers-reduced-motion, stable keyed card refresh without recreation,
per-tab URL history (hash devices/activity/browser/pending),
and keyboard placement beside the private Browser viewport on desktop,
immediately below it on phones/tablets.

Private Browser retains the original secured owner-only input handler:
no key logging added, no clipboard reads added, human/AI handoff remains enforced
by the server. Layout changes are presentation-only.

## Progressive Web App
The commandcore.webmanifest file is served by a minimal GET route.
Standalone display and navigation shortcuts are enabled where supported.
Online connection is required. No service worker is registered, so sensitive
API responses, sessions and Browser screenshots are never offline-cached.

## Tests
Run npm --prefix tests/ui ci and npm --prefix tests/ui run test:graphite.
Set COMMANDCORE_CHROME_BIN to a trusted Chromium executable if required.
The suites use mock API data: Browser session isolation, handoff privacy,
owner permission form confirmation, no horizontal overflow and keyboard
location, card DOM preservation, hash/back navigation and manifest availability
at 375, 768, 1440 and 1920px.

## Production safety
UI assets live as production bind mounts, with timestamped backups adjacent
to the files. The PWA manifest route was activated by a guarded in-place
restart, cutover PASS. No volumes, OAuth grants or device keys changed.
Do not recreate production Docker containers without verifying backend overlays.
