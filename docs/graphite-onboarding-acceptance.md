# Linux onboarding and real-time Control Plane UX

- Colored permission panels open device details on click, Enter, and Space.
- Device details use a compact overview and collapsible access, agent, capability and management sections; no authorization controls were removed.
- Add Device contains the original public installer plus seven independently copyable commands for verification, activity, diagnostics and PATH fallback.
- Never claim the old public Linux installer is fixed or that an installation succeeded solely from the panel. Its deployment is separately verified.
- Installing runs as the normal user. Preserve existing identities and recognize verified legacy services. Never advise deleting agent.json for routine troubleshooting.
- Device and enrollment lists poll every two seconds only while the page is visible; requests are coalesced. A reconnect/focus triggers refresh. This is near-real-time polling, not an SSE stream.
- The panel displays pending enrollments and an online authorized-device summary; online status does not independently prove installer correctness.
- Incoming enrollment changes preserve the entered verification code and grant checkbox. Unchanged device cards retain DOM identity.
- Activity refreshes while visible without rebuilding unchanged rows. Browser session monitoring remains scoped to its own tab.
- Test with npm --prefix tests/ui run test:graphite; full desktop and mobile suites use mocked API responses and a real headless Chromium renderer.
- No persistent database, OAuth scope, agent identity, privileged helper, or secondary workstation configuration changes.
