# Chromium container seccomp policy

`chromium-sandbox-seccomp-probe.json` is a pinned, reviewed policy used by the isolated public Browser worker operator. It is based on the standard Docker/Moby seccomp policy structure and syscall rules, with Chromium namespace sandbox allowances and other operator-specific adjustments; it is **not** an unmodified upstream profile.

Upstream comparison/attribution: [Moby default seccomp profile](https://github.com/moby/profiles/blob/main/seccomp/default.json), Apache License 2.0. Preserve upstream attribution and the corresponding license notice in `THIRD_PARTY_NOTICES.md`. Confirm original historical source/provenance before publishing a redistributable release, since a structural comparison alone cannot prove its original derivation.

Operator code checks SHA-256 `a48b434d0ed34bdd1020fd5f73af8f2060c680fafabfa2e278d3866b6d9a2476` before permitting worker provisioning. Any policy update requires an intentional review of changed syscalls, new digest, negative network/namespace tests, and a new operator release; do not loosen `--security-opt`, inject Docker socket access into the API, or copy the private Browser policy/keys into public production.

The canonical repo tracks the policy for review and reproducibility. Adding it does not enable public Browser or authorize user-account provisioning.
