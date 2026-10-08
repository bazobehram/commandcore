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

This preview does not yet implement human-handoff, encrypted persisted profiles,
MFA flows, Windows personal Chrome extension support, cross-restart session
recovery or per-site click approval. Do not advertise them as complete.

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
4. Introduce authenticated human handoff with single-controller locking,
   short-lived viewer tokens and an explicit resume action.
5. Require site/action approval for sensitive mutation and file transfer.
6. Run end-to-end security, OAuth, audit and reconnect tests against disposable
   accounts and public test websites.
7. Validate Windows personal-browser mode separately rather than reusing
   Linux headless assumptions.

Until those gates pass, the browser preview must remain disabled on public
CommandCore deployments.
