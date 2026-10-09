# Visual Browser preview (experimental)

Status: **development PoC; not enabled by default, not production-ready**.

CommandCore can optionally control an isolated Steel/Chromium browser through CDP.
This is visual computer-use style control, not a CSS-selector automation API.
The MCP client receives actual PNG screenshot content plus bounded, explicitly
untrusted page text and can choose coordinates for subsequent operations.

This integration is **not** a CAPTCHA bypass or a guarantee of access to sites
with bot protection. MFA, CAPTCHA, account consent and sensitive operations
should be performed by the human operator, not circumvented by automation.

## Current capabilities

- `browser.open`: new HTTPS page, with an explicit initial-host allowlist.
- `browser.observe`: PNG screenshot, current URL/title, bounded visible text.
- `browser.move`, `browser.click`: physical CDP mouse events by pixel coordinates.
- `browser.type`, `browser.keypress`, `browser.scroll`: input events.
- `browser.close`: release the caller's Steel session.
- `browser.handoff`: pause the AI and issue a 10-minute authenticated
  operator takeover link (experimental).
- `browser.*` appears on MCP surfaces only when enabled in server settings.
- All browser tools require the `commandcore:standard` OAuth scope; no
  device FULL_CONTROL grant or Agent control is implied.
- Browser text is untrusted; screenshots are returned as MCP `image/png` content.
- Actions are recorded in the existing audit trail with redacted argument
  summaries. Typed values are never copied into audit records.

## Known security limits

**Do not use saved credentials, authenticated private sites, or sensitive browsing
sessions with this release-candidate implementation.**

The self-hosted Steel CDP proxy was observed to share its active browser across
distinct API session identifiers. A two-owner test demonstrated that one owner
could see the other's page. Therefore this integration hard-fails if configured
for more than **one active owner**. A second owner gets a capacity error.

Even with one owner, the initial URL allowlist is **not a network security
boundary**. Redirects, frames and resource requests can reach other hosts.
The browser is separate from the CommandCore process, but default Docker
outbound networking does not prevent access to local/private IP space. Before
production use, add tested egress isolation, network-level private-range deny,
redirect/frame/download policy, per-user browser isolation and resource limits.

The Steel live viewer/debug endpoint can control the browser and is **not
exposed** by the example Compose file. An authenticated, short-lived handoff
proxy and ownership lock are required before offering live viewer access.
Do not paste a raw debug URL into ChatGPT or expose CDP port 9223.

This preview includes an early authenticated human-handoff console but does
not yet have externally accepted MFA flows, encrypted persisted profiles,
Windows personal Chrome extension support, cross-restart session recovery or
per-site click approval. Do not advertise them as complete.

## Run in a disposable evaluation environment

Use a **separate checkout and disposable Docker Compose project**. Never apply
this override to an existing production deployment without a dedicated
review and a backup/rollback plan.

Requirements: Docker Compose, 4 GiB or more available RAM, 10 GiB disk free.

~~~bash
git clone https://github.com/bazobehram/commandcore.git
cd commandcore
cp .env.example .env
# Fill .env with two different unique generated secrets and local URLs.
# Follow docs/SELF_HOSTING.md; never check .env into Git.

export COMMANDCORE_BROWSER_ALLOW_HOSTS=example.com

docker compose -p commandcore-browser-eval \
  -f docker-compose.yml -f docker-compose.browser.yml \
  --profile browser up -d --build

docker compose -p commandcore-browser-eval \
  -f docker-compose.yml -f docker-compose.browser.yml \
  --profile browser ps
~~~

The Steel API/CDP ports are internal to the Compose network. The normal
CommandCore service continues to bind its application port to loopback. The
browser container has no mount of your real Chrome profile.

To stop the disposable evaluation project:

~~~bash
docker compose -p commandcore-browser-eval \
  -f docker-compose.yml -f docker-compose.browser.yml \
  --profile browser down
~~~

Do not run this sample alongside another CommandCore instance with the same
published loopback port without changing the **evaluation** project port first.

## Example AI client flow

After separately configuring OAuth and connecting a client to the evaluation
MCP endpoint:

~~~text
browser.open   {"url":"https://example.com"}
browser.observe {}
browser.move   {"x":150,"y":150}
browser.click  {"x":150,"y":150}
browser.scroll {"delta_y":240}
browser.close  {}
~~~

Coordinates are relative to a 1280x800 browser viewport. Calls after
`browser.open` are scoped to one authenticated subject + issuer + client ID.

The caller makes decisions from actual screenshots; CommandCore does not
pretend to autonomously interpret them.

## Evidence

An isolated self-hosted Steel instance was used for this initial engineering
probe. A direct CDP connection navigated to `https://example.com`, returned a
PNG signature and the `Example Domain` title. The new BrowserGateway
completed open, move, click, scroll, observe and close on that page.

A separate test with two Steel API sessions **failed session isolation**. This
is an explicit blocking security finding and the reason for the hard
single-owner gate.

Unit tests in `tests/test_visual_browser_poc.py` verify URL validation, opt-in
configuration, ownership capacity rejection, OAuth scope, and MCP screenshot
format. These do not constitute a production browser security audit.

## Next acceptance gates

1. Move the browser execution client into an independent least-privileged
   worker instead of running the CDP bridge inside the server process.
2. Prove genuine separate browser-context/container isolation for multiple users,
   with no cross-user screenshots, cookies, history, or CDP target visibility.
3. Enforce outbound private-network deny **at the network layer**, including
   DNS rebinding, redirects, WebSockets, downloads, localhost and metadata IPs.
4. Harden authenticated human handoff with real OAuth/mobile acceptance,
   restart/reconnect behavior, rate limits, and single-controller fencing.
5. Require site/action approval for sensitive mutation and file transfer.
6. Run end-to-end security, OAuth, audit and reconnect tests against disposable
   accounts and public test websites.
7. Validate Windows personal-browser mode separately rather than reusing
   Linux headless assumptions.

Until those gates pass, the browser preview must remain disabled on public
CommandCore deployments.

## Additional public-site visual acceptance (October 8, 2026)

The disposable Steel/Chromium container was tested with a separate disposable
Python test client, not with any existing production CommandCore service.

- **GitHub public PR navigation:** opened the public PR #19 and captured its
  actual rendered screenshot; clicked the visible *Files changed* tab by
  coordinates; verified navigation to `/pull/19/files`; scrolled and observed.
- **Public Selenium demo form:** opened the Selenium example form, clicked
  the text input by coordinates, typed a non-secret test string, clicked
  Submit, and verified the next page displayed `Received!`.
- **Session release:** discovered that the self-hosted Steel API requires
  `POST /v1/sessions/{id}/release`. Using DELETE led to HTTP 404 and a
  false success report. The gateway now requires an acknowledged release.
- **Transient navigation failure:** heavy pages occasionally delayed
  screenshot capture; an initial form attempt returned `about:blank`.
  Navigation and screenshot failures must be reported as errors, never
  as successful page visits.

No real account login, MFA/CAPTCHA handoff, saved browser profiles, arbitrary
websites, concurrent owners, Windows desktop Chrome or private application
actions have passed acceptance. These remain explicit blockers.

## End-to-end MCP acceptance: local-only staging

A second CommandCore instance with disposable local credentials and a disposable
SQLite database was started on loopback (`127.0.0.1`). The existing production
CommandCore deployment and its OAuth, grants, database and Agents were not changed.

Using MCP JSON-RPC over real HTTP (not an in-process fake), the test completed:

1. `tools/list`: confirmed all eight optional `browser.*` definitions.
2. `browser.open`: opened a public GitHub pull request.
3. `browser.click`: clicked the visible *Files changed* tab using a freshly
   observed coordinate; URL changed to the corresponding `/files` route.
4. `browser.observe`: returned the current screenshot and URL.
5. `browser.close`: acknowledged the session release.

Each observation provided a genuine `image/png` MCP content item. The image
base64 was not duplicated into `structuredContent`.

A separate Selenium public demo form test clicked and typed into two fields,
changed a checkbox, submitted with a coordinate click, and verified the
`Form submitted / Received!` result. No real account or credential was used.

**A significant limitation of coordinate actions:** dynamic GitHub tab layouts
shifted between runs, causing a previously valid x-coordinate to click *Checks*
instead of *Files changed*. Agents must inspect a fresh screenshot before
each important click and verify the resulting URL/page. Hardcoded screen
coordinates are not reliable automation scripts.

**Status of human handoff:** A short-lived authenticated console PoC now
exists, with pause, human-only screenshot/action, same-subject cookies,
same-origin checks and explicit resume. Do not expose Steel's raw debug viewer
or use sensitive accounts before production authentication and outbound
network isolation are implemented and tested.

**Status of general deployment:** still a single-operator, opt-in technical
preview. Production and the default ChatGPT connection remain unchanged.

## Experimental authenticated human handoff

The development branch includes a **10-minute, owner-bound human handoff**
preview. This is not an unattended CAPTCHA bypass. The operator performs
authentication, MFA or other account verification manually:

1. An authenticated AI client opens a visual browser session.
2. The AI calls `browser.handoff` and receives a short-lived CommandCore URL.
3. AI browser operations pause while handoff is active.
4. The operator opens that URL and authenticates with **the same CommandCore
   account** via the normal panel session. Other accounts are denied.
5. The operator sees fresh screenshots, taps coordinates to click, types text,
   uses limited keys and scrolls.
6. The operator explicitly selects **Resume AI control**.
7. The handoff token becomes invalid; the original MCP client can now observe
   and control the same tab again.

The console is served by CommandCore and does **not** publish raw Steel/CDP
debug endpoints. It uses same-origin requests, HttpOnly panel session cookies,
CSRF checks, no-store responses, frame restrictions and redacted audit summaries.
The AI cannot request screenshots or issue actions while human control is active.

**Local staging acceptance:** MCP `browser.handoff` was followed by a denied
AI observe call, unauthenticated HTTP 401, authenticated panel access, PNG
screenshot, user-origin click/type, cross-origin HTTP 403, explicit resume,
expired handoff URL and resumed MCP observe/close. Only the Selenium public
form and disposable local credentials were used.

**Not yet a production claim.** Human takeover still needs real external OAuth
provider acceptance, production HTTPS/reverse proxy acceptance, mobile-browser
usability testing, session restart/reconnect recovery, stronger rate limits,
network-level browser sandbox isolation and actual operator acceptance with
a dedicated noncritical account. No real personal login/CAPTCHA was attempted.

When a handoff expires, the token becomes unusable **without automatically
unpausing the AI**. This avoids exposing partially entered private credentials
back to the model. The client can request another handoff token (or close the
whole browser session); ordinary AI actions remain blocked until a human
explicitly resumes.

## ChatGPT inline visual monitor (MCP Apps preview)

The optional `browser.watch` MCP render tool advertises an embedded
[MCP Apps](https://modelcontextprotocol.io/docs/extensions/apps) resource,
`ui://commandcore/browser-view-v1.html`. The server supports
`resources/list` and `resources/read` on both MCP endpoints only when the
browser feature is enabled. Disabled deployments never list this tool or
publish its UI resource.

After `browser.open`, the AI may call `browser.watch` to request a
**read-only monitor** in hosts that implement MCP Apps, including compatible
versions of ChatGPT. The widget calls `browser.observe` through the MCP Apps
bridge; screenshot payloads remain normal MCP `image/png` content, not raw
browser/Chrome debugging ports.

- Manual **Refresh now** always available.
- **Auto-refresh** is opt-in, one screenshot every four seconds while the
  widget is visible, with a one-inflight-request limit.
- **Take control** is an explicit user click that requests the existing
  authenticated `browser.handoff` and opens a separately authenticated
  CommandCore console. The widget never becomes a privileged Chrome console.
- While human control is active, AI screenshot/control requests are denied.
- Host UI resource metadata supports inline and fullscreen display.
- If the host does not support MCP Apps, ordinary `browser.observe` still
  returns a screenshot to the model. No UI rendering is promised.

**Acceptance boundary:** MCP resource listing/read, render-tool metadata,
widget JavaScript parsing, and MCP image-output tests are automated. Actual
ChatGPT inline mounting, OAuth identity consistency between model-triggered
and widget-triggered calls, fullscreen rendering and mobile behavior **must
be verified against the connected ChatGPT app before release**. This is not a
screen-recording service or uninterrupted video stream.
