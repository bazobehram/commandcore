# Agent update lifecycle

Status: **signed verify/stage/activate/health/rollback and fleet canary/ring coordination are implemented for supported Linux release candidates**.

## Security boundary

Remote Agent replacement is a supply-chain and root-control boundary. An MCP caller cannot supply an arbitrary binary. Device-local root policy must contain a trusted Ed25519 release public key and allowed HTTPS manifest origin. The unprivileged Agent stages data; the privileged updater independently re-verifies trust and artifact integrity before activation.

## Manifest v1

Schema: `packages/protocol/update-manifest-v1.schema.json`.

A manifest identifies product, version, signing-key ID, platform/architecture artifact URL, size, SHA-256 and Ed25519 signature over canonical manifest JSON excluding `signature`. The signing private key stays outside this repository. `scripts/sign_update_manifest.py` supports offline signing.

## Single-device flow

```text
agent.update.stage / update-stage
  -> allowed HTTPS origin
  -> signature verify
  -> artifact download
  -> size/SHA-256 verify
  -> atomic stage

agent.update.activate / local update-activate
  -> signature/origin/artifact verify AGAIN at privileged boundary
  -> reject downgrade by default
  -> install versioned release
  -> atomic `current` switch
  -> restart commandcore-agent
  -> fresh authenticated health
     -> PASS: commit
     -> FAIL: restore previous release + restart + rollback record
```

The updater runtime is deliberately separate from `current`.

## Fleet flow

A fleet rollout stores target version, signed-manifest URL, rings and per-device state in SQLite. The first ring is the canary set. `advance` performs at most one remote action, making transitions durable and operator-observable.

Default behavior:

- canary must commit before later rings;
- failures pause the rollout (`stop_on_failure=true`);
- offline devices wait instead of failing;
- operator may skip/resume/cancel;
- stale `staging` recovers to safe idempotent retry after timeout;
- transport loss while staging is retryable;
- activation transport loss is expected and commit is determined by authenticated reconnect/health state.

The fleet controller does **not** distribute signing keys or trust arbitrary origins.

## Commands

```bash
commandcore-agent update-check --manifest <HTTPS_URL>
commandcore-agent update-stage --manifest <HTTPS_URL>
commandcore-updater update-status
sudo commandcore-updater update-rollback
```

The panel/API manages fleet rollout state. `--allow-downgrade` remains a local recovery override only.

## Current limits

Linux is the primary signed-update target. Windows update/helper packaging remains a preview and macOS is not yet supported. Remote rollout never substitutes for local release trust or platform-specific acceptance.
