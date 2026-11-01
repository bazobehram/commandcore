# Optional private-only owner access restriction

CommandCore is multi-user by default. An operator who runs a dedicated **private**
instance can set `COMMANDCORE_PRIVATE_OWNER_SUBJECT` to the exact verified OAuth
`sub` of the sole owner. Leave it **unset on public and shared instances**.

Do not commit a real person's subject, identity tokens or session cookies. Set
the value only in the private deployment environment.

When enabled, the following authenticated paths require the same subject:

- OAuth bearer token authentication, including the canonical `/mcp/core`
  ChatGPT plugin and API routes;
- signed panel cookies;
- OAuth panel callback, before issuing any session cookie.

A different valid Auth0 user is denied even if they request the same scopes.
The public endpoint for OAuth discovery stays accessible to ChatGPT so OAuth
can begin normally. Agent transport, health checks and signed device enrollment
do not receive an extra CAPTCHA, Cloudflare Access or basic-auth prompt.

**Safety rules:** enable only after verifying that the subject exactly matches
the owner observed in `auth.whoami`. Do not confuse the OAuth user's `sub`
with legacy `bootstrap-admin`, device IDs or a client ID. The server refuses
this option unless OAuth is enabled and public bootstrap login is disabled.

## Safe deployment

1. Test the new code and the currently working private OAuth+MCP connection
   against an isolated candidate backend with a **copy** of its database and
   secrets, not the live DB. Do not expose test tokens or secrets in logs.
2. Check owner login and panel cookie access, `/mcp/core` tool calls, device
   listing, device permission changes (read-only inspection preferred), browser
   handoff, OAuth callback, and unauthenticated/foreign-user denial.
3. Keep the existing production backend active. Apply the private-only setting
   via the authorized guarded release with rollback and full identity
   preservation. Never require users to reinstall/re-pair Agents.
4. Monitor 401/403 behavior, MCP round trips, heartbeat and health.
   Roll back the application/configuration on regression.

This policy is **off by default**, including on the public `commandcore.app`.
Adding this source code does **not** enable the setting or deploy the backend.

The separate private Nginx `noindex` and workspace-HTML gate is defense in
depth; neither `robots.txt` nor hiding the login page substitutes for the
server's verified identity check.
