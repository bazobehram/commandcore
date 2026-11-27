# Runtime release parity

Private and Public must consume the same independently verified immutable server image, not different source trees or per-host Python/HTML patches. Keep identity, storage, enrollment, credentials, host networking, feature policy and permission boundaries separately configured. Never transfer private account state or owner bindings into Public.

## Promotion gate

Use a clean checkout of the exact reviewed release commit and the image ID obtained from the independently verified release image digest (verify the signed GHCR provenance first). On each target host, before accepting a deployment, run:

```sh
python scripts/runtime_release_parity.py \
  --container <running-container-name> \
  --source-root <clean-release-checkout> \
  --expected-image-id sha256:<verified-image-id>
```

The command is read-only. A PASS requires the expected local immutable image ID, OCI revision label matching the checkout, exact installed application package and web/MCP asset bytes, and no mounts intersecting those application roots. It detects missing, extra and changed files, including untracked runtime edits. The GHCR publication workflow records the same check for its exact image before releasing its promotion evidence. Do not derive the expected ID from an untrusted running container when deciding readiness.

A BLOCK must stop promotion; do not copy old runtime files over the reviewed release or disable the gate. Inventory working reference behavior and selectively reconcile missing features into reviewed source, preserving newer authorization and isolation fixes. Test against an isolated canary and retain rollback to the existing image/configuration. Do not change the actual public origin until its host identity is verified.

## Behavioral acceptance (separate from byte parity)

Both deployments must pass device enrollment/approval, supported signed installation and uninstall, OAuth/owner isolation, device selection, filesystem/shell/process operations, activity and per-operation widgets in real ChatGPT, reconnect, and browser operations where securely enabled. Verify the independently deployed Angular frontend and signed agent artifacts separately. A public browser worker must satisfy the public isolation policy before enabling it; byte equality alone does not prove safe runtime parity. Preserve the existing reviewer identity and demo device throughout a release.

This gate does not verify external frontend assets, installer signatures, configuration equivalence, database migrations, live agent behavior, or the OpenAI review status. Never describe a successful byte check as successful end-to-end acceptance.
