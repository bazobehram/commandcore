# Public MCP edge preflight (M1)

This diagnostic separates CDN/WAF denials from CommandCore OAuth denials. It
does **not** prove real two-account authorization or device isolation.

## Safe, unauthenticated probes

Use a disposable test client with a deliberately approved outbound network.
Never supply access tokens, cookies, client secrets or device IDs to these
checks. Record the exact UTC time, deployed digest (if available), endpoint,
HTTP status, and sanitized error classification only.

```bash
curl --silent --show-error --output /dev/null --write-out '%{http_code}\n' \
  https://commandcore.example.com/healthz
curl --silent --show-error --output /dev/null --write-out '%{http_code}\n' \
  https://commandcore.example.com/.well-known/oauth-protected-resource/mcp
curl --silent --show-error --output /dev/null --write-out '%{http_code}\n' \
  https://commandcore.example.com/privacy
curl --silent --show-error --output /dev/null --write-out '%{http_code}\n' \
  https://commandcore.example.com/terms
```

Replace the example origin with the intended **public test deployment**, not a
private operator instance. The health check and discovery status alone do not
test MCP authorization. Inspect protected-resource metadata locally, without
copying sensitive configuration or user data into issues.

To distinguish an unauthenticated MCP request from an unrelated Cloudflare
block, send one harmless `tools/list` POST, without any bearer token, through
the same route that the test client uses:

```bash
curl --silent --show-error --include --max-time 12 \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  --data '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' \
  https://commandcore.example.com/mcp/core
```

**Inspect the output locally**, then redact before sharing. HTTP 401 with the
intended OAuth challenge indicates the request reached the auth boundary; it
does not prove login, permissions or two-user isolation. A Cloudflare response
with `error-1010` means the edge blocked the request, so it cannot be counted
as an OAuth denial. Other 403s require source attribution before conclusions.

## Cloudflare review without weakening the boundary

1. At the exact failed-request time, inspect the matching Cloudflare security
   event and relevant bot/WAF/access rule. An edge HTTP 403 is not automatically
   a CommandCore authorization defect.
2. Determine whether the affected test client is actually intended to be
   supported; do not bypass bot policy based only on a claimed user agent.
3. If a change is required, prefer the narrowest reviewed identity-based test
   allowance supported by the configured Cloudflare product. Keep broad
   firewall and bot protections in place.
4. Repeat the same unauthenticated MCP POST. Confirm the **origin's**
   authentication challenge; do not make `tools/list` publicly accessible.
5. Then perform the independent Auth0-user acceptance matrix in
   [LIVE_TWO_USER_ACCEPTANCE.md](LIVE_TWO_USER_ACCEPTANCE.md), using disposable
   device/Browser resources. Record deny events and redacted traces.
6. Restore any temporary test allowances. Verify normal client behavior and
   unchanged private deployment security independently.

## Stop conditions

Stop on unexpected unauthenticated success, cross-user data/device visibility,
widened OAuth scopes, unreviewed Cloudflare bypasses, or missing audit trails.
Follow [SECURITY.md](../SECURITY.md) for sensitive findings.

Related tracking: [#149](https://github.com/bazobehram/commandcore/issues/149),
[#125](https://github.com/bazobehram/commandcore/issues/125),
[#122](https://github.com/bazobehram/commandcore/issues/122).
