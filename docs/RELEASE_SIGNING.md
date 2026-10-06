# Release signing

CommandCore Agent releases use Ed25519-signed manifests and immutable artifacts.

The release signing private key must be isolated from:

- the public Git repository;
- the internet-facing CommandCore server;
- enrolled Agents;
- ordinary application backups.

## Trust chain

A release process should:

1. build from a reviewed source commit and committed dependency locks;
2. record source commit, toolchain, target, artifact size, and SHA-256;
3. create a versioned manifest containing exact platform/architecture artifacts;
4. sign the canonical manifest offline or in an isolated signing environment;
5. independently verify the signature;
6. package installers with the trusted public verification key;
7. publish manifest and immutable artifacts over verified HTTPS;
8. retain previous known-good releases for rollback.

The signed manifest excludes its own signature field from the canonical payload.

## Device verification

Before activation, the installer/updater verifies:

- manifest signature;
- expected product/schema;
- supported platform and architecture;
- HTTPS artifact URL;
- exact artifact size;
- SHA-256;
- version ordering;
- locally trusted release key/origin policy where required.

A successful download is not sufficient evidence of authenticity.

## Key custody

Repository scripts may assist with signing, but no repository workflow should
require placing a private signing key on the public CI runner.

If a software key vault is used, document:

- key creation;
- encryption at rest;
- who can decrypt/sign;
- backup and recovery;
- rotation;
- compromise response.

Hardware-backed or isolated signing can replace a software vault without changing
the Agent trust model.

## Bootstrap limitation

Embedding a public verification key in an installer protects subsequent manifest
and artifact verification, but an attacker who can replace the installer through
the same bootstrap channel may also replace its embedded key.

For stronger bootstrap assurance, publish the installer hash and release-key
fingerprint through an independent channel and document manual verification.

## Release evidence

Each release should retain:

- source commit;
- CI run;
- toolchain versions;
- signed manifest;
- public-key fingerprint;
- artifact hashes and sizes;
- SBOM;
- dependency/vulnerability audit;
- platform acceptance results;
- update/rollback result;
- provenance record.

See RELEASE.md and PUBLIC_RELEASE_CHECKLIST.md.
