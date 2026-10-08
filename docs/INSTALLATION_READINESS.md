# Installation readiness

Review date: 2026-10-08. This is an onboarding review of the public source and
its automated checks, not an independent security audit or a new platform
certification. Recheck release availability before relying on this snapshot.

## Verdict

CommandCore is usable by technical Linux operators who can configure a server,
HTTPS/WSS, identity provider, and device enrollment. It is not yet a turnkey
installer for arbitrary PCs. Passing CI establishes tested behavior; it does
not replace a clean end-user installation of a published release.

The server is the control plane. Each managed computer needs its own agent.
One Linux machine can host both roles, but server installation alone does not
enroll that machine or grant access to it.

| User goal | Current path | Remaining work |
|---|---|---|
| Run the server on Linux | Docker Compose build from source | Set secrets and deployment URLs, configure operator login |
| Use a remote MCP client | HTTPS/WSS edge plus external OAuth/OIDC | Provider registration, client consent, explicit device grants |
| Evaluate a Linux device | Python reference agent from reviewed source | Manual foreground enrollment/run; no managed service or signed lifecycle |
| Install a managed Linux agent | Signed native installer and deployment feed | Publish signed artifacts, pin the key, configure feed mount, verify platform lifecycle |
| Manage a Windows PC | Preview agent | Full install/reboot/update/rollback release acceptance remains gated |
| Manage a Mac | Planned | No supported agent release |
| Control desktop/browser | Experimental desktop; browser backend absent | Do not present as stable functionality |

## Findings that affect a new installation

1. **No public release/tag at review time.** The GitHub releases and tags lists
   were empty. A source checkout and passing builds are available; a public
   signed end-user distribution cannot be assumed. Publish accepted artifacts,
   signed manifests, installer hashes, public-key fingerprints, SBOMs, provenance,
   and limitations following [the release procedure](RELEASE.md).
2. **Installer routes are unpublished by default.** The Compose template neither
   sets `COMMANDCORE_DISTRIBUTION_DIR` nor mounts a release feed. A fresh server
   returns 404 for `/install/linux`. Follow [feed publication](RELEASE_DOWNLOADS.md#publish-a-deployment-feed)
   or use the explicitly documented source evaluation path.
3. **The enrollment server must be selected explicitly.** The installer template
   defaults to an example hostname. Every deployment-specific install/upgrade
   command must pass `--server`; the download origin does not set this value.
4. **Remote authentication requires operator work.** `.env.example` has OAuth,
   bootstrap, and recovery disabled. This is deliberate, but a healthy server
   does not imply a usable panel or an authenticated MCP client. Configure the
   external provider, exact `/auth/callback` URL, panel public client, issuer,
   audience, JWKS, and scopes. Account-bound configuration needs real credentials
   and consent, not values invented by an installation agent.
5. **Linux prerequisites are narrower than the name suggests.** The native
   installer checks glibc >= 2.36 and curl >= 8.4, plus Python/OpenSSL; default
   service installation needs systemd user services. Check the target machine
   before selecting the installer. Windows remains preview and macOS planned.
6. **Trust material is deployment-specific.** Verification examples must use the
   operator's independently trusted public key and fingerprint. A key copied
   from another deployment is not a universal CommandCore trust anchor.

## Agent-assisted installation

The root [AGENTS.md](../AGENTS.md) and [agent-assisted guide](AGENT_ASSISTED_INSTALL.md)
give agents a useful discovery, deployment, acceptance, and rollback workflow.
Explicitly ask an agent to read AGENTS.md: support for automatic discovery varies.

An installation agent should check platform prerequisites, release/feed availability,
and operator authentication before promising completion. It should distinguish
"server healthy", "device enrolled", and "MCP client authenticated" in its final
report. It must not solve missing release material by skipping signature checks,
or solve missing OAuth by leaving bootstrap publicly enabled.

## Evidence and limits

The public CI matrix covers Python 3.11/3.13, Linux helper behavior, native Rust
parity, Windows candidate runtime, dependency audits, secret scanning, and locked
container builds. See [validation status](VALIDATION_RESULTS.md) for the existing
project evidence and [platform support](PLATFORM_SUPPORT.md) for the support promise.

This review traced the Compose configuration, installer arguments/prerequisites,
distribution route behavior, source enrollment path, release listings, and agent
instructions. Targeted tests passed locally (38 passed, one Linux-only symlink
check skipped on Windows). The OAuth smoke passed with a disposable JWT/JWKS
provider, including issuer/audience/expiry rejection. The Python agent enrollment
smoke passed on Windows, covering explicit grants, outbound WebSocket, core file/
process/transfer/Git operations, agent/server restart, and revocation. Those smoke
tests did not exercise a published signed installer, a real external identity
provider/client login, systemd/reboot persistence, or Windows signed update/rollback.

This review did not repeat an end-user Linux install/reboot/signed-upgrade
cycle or certify every OAuth provider/client combination. Those are remaining
release acceptance gates, not assumptions to hide behind a passing unit suite.
