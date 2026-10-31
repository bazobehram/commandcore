# Release procedure

This procedure applies to public CommandCore source and binary releases.

## 1. Freeze the candidate

- choose the source commit;
- update VERSION and package metadata consistently;
- update CHANGELOG.md;
- confirm platform support claims;
- stop unrelated feature work on the candidate.

## 2. Repository gates

Run:

~~~bash
python scripts/public_repo_check.py
python scripts/secret_scan.py --history
~~~

Then run the complete CI matrix, including Python, Rust, security, and platform
candidate jobs.

No release proceeds with unexplained failing required checks.

## 3. Dependency and license review

Regenerate dependency inventory and SBOMs from the exact candidate.

Run Python and Rust vulnerability audits. Review licenses for the exact binary and
container distribution, including container/OS layers where applicable.

## 4. Platform acceptance

Run the acceptance matrix promised by PLATFORM_SUPPORT.md.

At minimum for a supported Linux Agent release, verify:

- clean install;
- enrollment;
- outbound reconnect;
- MCP core operations;
- revocation;
- service restart;
- host reboot behavior where claimed;
- signed upgrade;
- failed-health rollback;
- uninstall/reinstall behavior.

Use disposable or explicitly authorized machines.

## 5. Build artifacts

Build from the reviewed commit with committed locks.

Record:

- source commit;
- target triple/platform;
- toolchain;
- artifact filename;
- size;
- SHA-256.

Do not hand-edit a binary after recording provenance.

## 6. Sign

Create the versioned release manifest and sign it in the isolated release-signing
environment. Keep the private signing key off the public server, Agent, repository,
and ordinary CI logs/artifacts.

Independently verify the signature and every artifact hash.

## 7. Publish

Publish:

- source release/tag;
- release notes;
- signed manifest;
- immutable Agent artifacts;
- installer;
- SHA-256 values;
- SBOM/provenance;
- known limitations.

Do not publish unsupported-platform binaries in a way that implies stable support.

## 8. Post-publication verification

From a separate clean environment:

1. clone the public repository;
2. run public repository checks;
3. run representative tests/builds;
4. download the published installer;
5. verify signing material;
6. enroll a disposable device;
7. run safe MCP acceptance;
8. test upgrade/rollback when relevant.

## Versioning

Until 1.0, release-candidate versions may make incompatible changes when clearly
documented. Protocol compatibility should still be preserved where practical and
wire-incompatible changes must be explicitly versioned.

## Rollback

Keep the previous known-good server image/artifact and database backup before
production upgrades. Agent releases retain versioned known-good executables and
use fresh-health validation before committing activation.


## Immutable GHCR release image metadata

The tagged GHCR workflow uses an immutable registry digest and verifies
the pulled image's OCI source and revision labels. It records both the
registry manifest digest reference (ghcr.io/...@sha256:...) and the pulled
platform-specific Docker image ID (sha256:...) in a CI artifact, together
with the source commit. These **different digest types are not interchangeable**.

A release job fails if the image has a missing/mismatched revision or
unexpected repository source label. The assertion is made against a freshly
pulled image at the exact registry digest, not a mutable image tag.

The uploaded report is evidence of the workflow's own consistency check.
It is not a signed third-party provenance attestation, does not approve
deployment, and does not demonstrate that the same image is running on
Netti or the private homeserver. Independent promotion, protected approval,
runtime image-ID checks and backup/rollback acceptance remain mandatory.
