# CI/CD bootstrap status

All contributors (ChatGPT, Codex and humans) use Git commits and the same
checks. The release workflow currently produces a tested candidate archive;
it **does not deploy** to production.

## Required before enabling CD
1. Connect the canonical CommandCore GitHub repository as `origin` and
   protect `main` with required CI checks and reviewed PRs.
2. Establish a narrowly scoped, isolated deployment runner on deployment host.
   Do not expose Docker socket access to arbitrary pull requests.
3. Inventory the actual production Compose file, project, bind mounts,
   volumes, Browser/Activity overrides, service images and rollback policy.
   Do not deploy the generic repository Compose file over a live customized
   service without verifying parity.
4. Add a protected GitHub environment named `production` with approval
   requirements and configured deployment identity.
5. Make the CD job download only a successful release candidate, verify
   archive digest and Git SHA, take a rollback checkpoint, deploy the
   reviewed image, and run post-deploy checks.
6. Verify canonical live `tools/list` vs source registry using authorized
   credentials, and separately verify ChatGPT UI cache / Browser / Activity.
7. Test failed release and rollback without touching existing sessions.

Only then enable deploy-on-merge. Deployment updates existing MCP handler
behavior on the next tool call; it never forces ChatGPT to rediscover tools.

## Production topology preflight
The running production Compose project uses multiple overlays from distinct
worktrees. A stock `docker compose up` from this repository is **not** approved.

Before the eventual production job runs, configure an operator-approved
private JSON manifest on the deployment runner:

```json
{"compose_files": ["/absolute/path/primary-compose.yml", "/absolute/path/overlay.yml"]}
```

Then check the live container label against the approved file, in the same
order, with:

```sh
python3 scripts/deployment_topology_gate.py --container commandcore-commandcore-1 --approved-file /secure/commandcore-deploy-topology.json
```

This preflight is read-only. It blocks topology drift; it does not authorize
deployment or replace tests, rollbacks, protected GitHub environments, or
explicit production approval. Do not commit the private manifest.

## Live application-code overlay preflight

The Compose-topology gate checks approved Compose **paths**, not mounted Python or
web code. Before each production promotion, run the separate read-only
code-overlay audit on **each deployment host** against a local checkout of the
reviewed source commit:

```sh
python3 scripts/runtime_overlay_audit.py \
  --container commandcore-public-commandcore-1 \
  --source-root /path/to/reviewed/source \
  --strict
```

Use the corresponding private container name on the private host. The audit
reports only application-code target names and match status; it does not print
credentials or inspect databases, user files or data volumes. The default mode
reports differences; `--strict` also rejects source-matching code overlays,
so a release cannot quietly depend on mutable hotfix mounts outside its image.
A nonzero result **blocks promotion**, not the currently healthy live service.
Never remove or replace an active overlay merely to make the audit pass.
Consolidate each needed hotfix into reviewed source, test a clean immutable
candidate, verify signed image provenance, rehearse rollback, then remove old
mounts in a separate protected production deployment.

A clean overlay audit **does not prove code parity on its own**. It must be used
with immutable image identity checks, OAuth/MCP acceptance, database migration
and Browser/UI checks. CI cannot inspect private runtime containers; this gate
belongs to the protected deployment runner on each host.

## Candidate artifact integrity gate

Before any future deployment, the deployment runner must independently
verify the downloaded GitHub Actions artifact using:
```sh
python3 scripts/verify_release_artifact.py \
  --archive /release/commandcore-release.zip \
  --checksum /release/commandcore-release.sha256 \
  --manifest /release/release-manifest.txt \
  --expected-git-sha "$APPROVED_GIT_SHA"
```
Only use the SHA from the approved GitHub workflow run. The checksum and
manifest are integrity and provenance consistency checks, **not a cryptographic
signature or independent proof of GitHub's identity**. The trusted workflow,
GitHub artifact provenance and protected release approval remain necessary.
Do not extract or execute unverified packages.

## Dedicated runner isolation preflight

Run `python3 scripts/runner_readiness.py` before considering runner enrollment.
A runner account must be a dedicated non-root identity **without** Docker
socket access and without membership in equivalent privileged groups. Never
register a general-purpose runner as a production deployment identity. A
separate protected deployment executor with narrowly delegated operations is
required; no untrusted pull request code may access production credentials.

The preflight reports only local prerequisites, not approval for installation,
network enrollment or deployment. Configure a separate runner service and
validate GitHub environment protection before connecting it to releases.
