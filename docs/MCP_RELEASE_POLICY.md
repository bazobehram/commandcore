# CommandCore ChatGPT release policy

## What changes propagate without tool refresh?
An MCP tool call reaches the currently deployed handler, so implementation-only
updates become visible on the next successful call. Deployment does not push a
new ChatGPT conversation, tool inventory or iframe reload.

## Compatibility gate
Run `python3 scripts/mcp_release_gate.py` before deployment. CI runs it on
every push/PR. The checked surface is **CORE_TOOL_DEFINITIONS** served by
`/mcp/core`, not the full internal tool list.

- Pass: tool names, descriptions, titles and input schemas match the approved
  source baseline. This is a prerequisite, not proof that ChatGPT is refreshed.
- Fail: stop automatic deployment; review and explicitly update the baseline
  using `--write-baseline` only as part of an approved interface migration.
- Never update the baseline automatically in CI.
- UI resource URI, caching, OAuth, plugin metadata, server/runtime health, and
  the *live deployed* schema require separate verification. This gate cannot
  refresh ChatGPT or assert that a private connector has rediscovered tools.
- Changes to output semantics or permission behavior require dedicated tests
  even when schemas are identical.

## Release procedure
1. Validate the chosen deployment commit and confirm its Git worktree is clean.
2. Run full tests and MCP compatibility gate.
3. Build and deploy the candidate using the established approved pipeline.
4. Verify server health and call pre-existing canonical tools through ChatGPT.
5. Verify rendered Activity/Browser UI version independently; open panels may
   retain cached assets until reloaded.
6. Record commit, build ID, schema fingerprint, rollback target and verification.
7. For changed MCP schemas, initiate the supported plugin-update/Refresh tools
   flow and re-run acceptance checks.

Do not use speculative server-to-client MCP notifications to bypass host refresh.
MCP Events, if supported by the hosting environment, are a separate optional
notification workflow and not a substitute for tool rediscovery.

## Post-deployment read-only verification
On the deployment host, run:
```sh
python3 scripts/verify_mcp_release.py --expected-version 0.9.0-rc7 --output /tmp/commandcore-release-evidence.json
```
Substitute the **expected release version** for each deployment. This checks
local source contract compatibility and the live HTTP health/version endpoint,
but does **not** establish that the live MCP `tools/list` matches the source
snapshot, that the deployed Git commit matches, or that ChatGPT refreshed its
cached registry. Those require authenticated endpoint and ChatGPT acceptance
tests before claiming a complete release.
