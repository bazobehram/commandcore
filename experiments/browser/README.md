# CommandCore Browser — isolated visual-control proof of concept

Status: **experimental; NOT integrated into CommandCore MCP or the production Agent**.

This experiment evaluates the self-hosted [Steel Browser](https://github.com/steel-dev/steel-browser)
runtime for visual browser automation. It is deliberately separate from the
CommandCore server and production Compose stack.

## What was actually validated

On a separate Linux Docker container we launched Steel with its UI/API exposed
only on the host's loopback `127.0.0.1:3010`; the Chrome DevTools/debug port was
not published. Through Chromium's internal CDP endpoint, Puppeteer performed:

1. create a temporary page with an offline HTML fixture;
2. render the page at 900×600;
3. move the mouse to a button in 12 steps;
4. click it at screen coordinates;
5. confirm the page changed to `CLICK ACCEPTED`;
6. capture a 900×600 PNG screenshot.

No production server, OAuth configuration, database, device grant, or Agent
binary was changed. This establishes the browser runtime and mouse/screenshot
path, **not** a working ChatGPT browser MCP tool.

## Reproduce in a disposable environment

Requires Docker and a Linux host with at least 4 GiB memory available. Review
the upstream container image before running third-party software.

```bash
docker compose -f experiments/browser/compose.yaml up -d
curl -fsS http://127.0.0.1:3010/
docker cp experiments/browser/visual-smoke.cjs \
  commandcore-browser-poc:/tmp/visual-smoke.cjs
docker exec commandcore-browser-poc node /tmp/visual-smoke.cjs
docker cp commandcore-browser-poc:/tmp/commandcore-browser-smoke.png \
  ./commandcore-browser-smoke.png
docker compose -f experiments/browser/compose.yaml down
```

The Steel base image starts Chromium internally. The PoC script uses its bundled
`puppeteer-core` dependency; no credentials are needed. Image tags should be
pinned to reviewed digests in CI/production; the default `latest` tag is ONLY
an experimental convenience and may change.

The PoC uses an ephemeral browser profile. It is intentionally not configured
to retain GitHub logins, cookies, secrets, or user accounts.

## Target architecture

```text
MCP client (ChatGPT / Claude / Codex)
      |
      | OAuth + browser-specific scopes/grants
      v
CommandCore MCP + Browser Gateway
      |
      | authenticated, bounded session control
      v
isolated browser worker (Steel + Chromium)
      |
      +-- observe screenshot / accessibility snapshot
      +-- mouse move / click / scroll / keyboard
      +-- operator handoff + resume
```

A future personal-browser extension adapter would be an additional backend,
not a replacement for the worker.

## Required before MCP exposure

- Define separate browser session ownership and authorization; do not inherit
  host shell, filesystem, or FULL_CONTROL grants.
- Add `browser.sessions/open/observe/move/click/type/scroll/close` through
  reviewed CommandCore MCP definitions and authorization checks.
- Return screenshots as MCP image content, with bounded dimensions and payloads.
- Restrict navigation and network egress to prevent localhost, private-network,
  metadata-endpoint, and other SSRF-style access from untrusted page context.
- Introduce short-lived operator handoff for CAPTCHA/MFA and privileged actions.
- Treat website content as untrusted, not as instructions to the controlling AI.
- Do not expose Steel/CDP debugging ports or unauthenticated viewer URLs.
- Isolate user profiles and browser contexts; do not share cookie jars.
- Run negative tests for arbitrary-network access, cross-user leakage, revoked
  grants, and unauthorized clicks/writes.
- Add integration/acceptance against real ChatGPT MCP image-tool messages.

The upstream container's Chromium may use `--no-sandbox`. Container isolation
alone is insufficient for hostile websites without additional hardening.
Do not connect personal accounts in this experimental build.

## Do not overclaim

This PoC does **not** bypass CAPTCHAs, MFA, anti-bot controls, or client plan
limits. Mouse movement does not make automation indistinguishable from a person.
Human completion of verification challenges is the supported design goal.

See [Security model](../../docs/SECURITY_MODEL.md) and
[Platform support](../../docs/PLATFORM_SUPPORT.md) for product trust boundaries.
