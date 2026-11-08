# ChatGPT shell timeout: deployment verification

`shell.exec` is intentionally a **short, synchronous** tool in OAuth/MCP sessions.
An LLM host may stop awaiting a response before a longer command completes on
the device, creating an uncertain result and a risk of duplicate execution.

The backend policy introduced in [PR #216](https://github.com/bazobehram/commandcore/pull/216)
sets an 8,000 ms default, rejects values over 10,000 ms **before dispatch**,
and bounds the shared Agent WebSocket send-lock wait to 3 seconds and the
cancellation wait to 2 seconds. Non-OAuth local clients retain their original
shell contract. No device permission ceiling is changed. A 10-second Agent
execution may still involve transport overhead and is not a promise about the
ChatGPT host UI's own timeout.

For work expected to exceed a few seconds, use `process.start` and retain the
returned `process_id`; inspect it with `process.status` and read bounded output
with `process.output`. Never repeat a timed-out non-idempotent command without
checking whether it already took effect. Do not use shell commands that sleep
solely to poll GitHub Actions; use the GitHub connector directly.

## Guard against stale deployments

After any private or public rollout, execute the **read-only**, local Docker
postflight. It reports only the tool count and policy constants; no credentials,
Agent output, database records, or environment variables are printed.

```bash
# On the private homeserver (currently 50 core tools):
python3 scripts/verify_shell_timeout_deployment.py \
  --container commandcore-commandcore-1 --expected-tools 50

# On the public netti host (currently 48 core tools):
python3 scripts/verify_shell_timeout_deployment.py \
  --container commandcore-public-commandcore-1 --expected-tools 48
```

The counts above describe existing deployed variants, **not** an invariant
for new releases. When the mainline tool contract changes, review its expected
count rather than bypassing the check. A successful verification does not
replace live OAuth authorization, genuine device acceptance, or a clean
Browser/ChatGPT UI test.

The original private and public controllers retain custom code and do not
necessarily match the current `main` image. Both received a narrowly scoped
bind-mounted hotfix after isolated canary checks. Replacing either image or
recreating its Compose stack without the override can silently undo the fix.
Before deploying, check the **actual** running `docker inspect` Compose labels,
image, mounts, and environment. Preserve existing mounts and identity settings;
use an isolated canary and health-gated rollback for any image or override
change. Once the new mainline version is fully accepted and contains this
policy, remove the temporary override in a separate reviewed deployment.

Do not put signing keys or OAuth tokens in the verification script or use a
legacy public Agent release as evidence of signed, production-ready binaries.
