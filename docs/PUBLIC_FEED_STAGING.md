# M3: offline signed public Linux Agent feed pre-publication gate

**Status:** candidate integrity verification only. This is **not** permission
to publish, an automatic signer, a release attestation, or an Agent lifecycle
acceptance report. See [public onboarding blocker #157](https://github.com/bazobehram/commandcore/issues/157).

An HTTP 200 from the public endpoint does not prove anything about the key,
signature, binaries or installer. Before mounting a feed on a public server,
the operator must independently review and approve the exact source commit,
signed release, key custody, target binaries, signing provenance and runtime
installation/update/rollback evidence.

## Native unsigned x86_64 review candidate (CI; not a release)

The manually dispatched
[unsigned Linux Agent review workflow](../.github/workflows/unsigned-linux-native-candidate.yml)
also makes a **one-time** candidate when its reviewed packaging script/workflow
is first merged into `main`. It builds the Rust Agent using the checked-in
Cargo.lock on an Ubuntu 22.04 runner, runs the actual native localhost
enrollment/reconnect/MCP smoke test, and produces a 14-day GitHub Actions
artifact named `unsigned-linux-x86_64-agent-review-candidate`.

The artifact contains an **unsigned** Linux x86_64 executable,
`UNSIGNED_BUILD_METADATA.json`, `SOURCE_COMMIT.txt` and `SHA256SUMS.txt`.
It records exact bytes, source SHA, Cargo.lock digest, package version,
toolchain versions and maximum referenced GLIBC version, with a fail-closed
ceiling of GLIBC 2.36 because the Linux installer advertises glibc 2.36+.
It refuses ARM64/32-bit/non-PIE binaries and unrecognized runtime symbol
requirements. The workflow has read-only repository permissions and cannot
create GitHub Releases, write deployment data, or access signing secrets.

An artifact from this job is **not signed**, not an independent provenance
attestation, and not approved for installation. Its Cargo package version
may still be `0.9.0-rc7` even when source changes postdate that tag; the
reviewer must set a distinct actual release version and reconfirm all
version/source metadata **before** independent signing. Do not rename or
silently reuse this development binary as a previously signed release.
External acceptance of the exact built bytes, clean-install/update/rollback
behavior, SBOM/license checks and signing provenance remain required.

After downloading an artifact, compare its recorded source SHA to the
reviewed `main` commit of the build run; verify every SHA256SUMS entry and
run `scripts/package_unsigned_native_candidate.py verify` on the extracted
candidate. The later signed-feed staging verifier below works only with a
**separately signed** release manifest and an independently trusted public
verification key.

## Real systemd service restart verification

The native Linux GitHub CI `rust-agent-parity` job already starts the real
unprivileged Rust Agent under a disposable **user systemd manager**. The
`COMMANDCORE_ENROLLMENT_SYSTEMD=true` acceptance mode now additionally
runs `systemctl --user restart` on its own randomly named test service,
checks that `MainPID` changed, and executes a fresh MCP shell command after
reconnection. It preserves and tests the same enrolled device identity and
is completely separate from production services. This tests a real service
restart, **not** a version upgrade or real signed-release rollback. Those
remain blocked until a two-version systemd lifecycle test passes.

## Rust Agent reconnection and local-controller restart acceptance

The native CI candidate builder runs `scripts/rust_agent_smoke.py` against its
compiled Rust executable and an ephemeral localhost CommandCore controller,
not any production device. Besides enrollment, core tools, managed processes,
permission ceiling and key rotation, the smoke now requires the Agent to
**become offline** after an actual process stop, then reconnect with its
rotated key. It also restarts the local controller while keeping the same
Agent process running, and verifies a fresh MCP device selection and a shell
round trip after the controller returns. An online status alone is **not**
accepted as proof of reconnection.

The source file is a watched CI workflow path, so changes to this connection
acceptance test trigger an updated build/check. This does not exercise an
actual systemd unit, a hardware restart, a full binary upgrade/rollback,
external Auth0 accounts, or production signing. Keep those as stop-ship
requirements until independently verified.

## Disposable clean-install acceptance for each unsigned CI candidate

The `unsigned-linux-native-candidate` workflow now includes a dependent
Ubuntu 24.04 job to test the **exact uploaded candidate bytes** using the
real `install/linux.sh` script. Ubuntu 24.04 is needed because the public
installer requires curl 8.4+ and glibc 2.36+, while the build stays on
Ubuntu 22.04 to enforce conservative glibc symbol requirements.

`scripts/native_linux_disposable_install.py` verifies candidate source and
SHA256SUMS, creates a temporary **test-only** Ed25519 key, and serves the
candidate over loopback for a no-service, no-enrollment clean install in a
fresh temporary HOME. It checks the installed binary/version, refuses a
wrong trust key, and refuses a tampered binary without installation. The
key, served bundle and installed files are deleted with the temporary test
workspace. This check neither needs nor handles a production signing key,
controller identity, user account, or external hostname.

The dependent CI job also runs the existing `scripts/installer_smoke.py`
with `COMMANDCORE_TEST_NATIVE_BINARY` pointing to the exact downloaded CI
candidate, after rechecking the source SHA. That disposable fixture-based
suite covers wrong signing key, tampering, unrelated-service protection,
same-version install, injected `systemctl daemon-reload` failure with rollback,
existing Agent identity preservation, isolated install namespace, version
ordering, uninstall identity preservation, and real Rust Agent install,
version/digest validation and uninstall. It uses an ephemeral test Ed25519 key
and a fixture system manager, not the host's actual user systemd service.
The CI runner is disposable; the test must never be executed as root on an
enrolled production workstation.

The gate is **not** a real signed production installation: it does not
exercise Agent enrollment, reboot persistence, connected-service health,
version upgrade or rollback. These remain stop-ship operator acceptance
requirements. A test-only key cannot satisfy the release signer/trust pin.

## Dual-architecture signing review handoff (no key material)

After both unsigned CI review bundles have been independently checked and the
operator has selected a **new, approved** release version, this read-only-input
helper can prepare a draft *without a signer or release key*:

~~~bash
python scripts/prepare_linux_release_review.py \
  --x86-candidate /review/x86_64 \
  --arm64-candidate /review/arm64 \
  --source-sha <exact-review-commit-sha> \
  --release-version <operator-approved-release-version> \
  --origin https://commandcore.example.com \
  --output /review/manifest.UNSIGNED.json
~~~

It independently reruns each bundle's source, hash, architecture and glibc
checks, requires matching source commits and both Linux architectures, pins
immutable HTTPS artifact URLs and refuses to overwrite an existing output.
The resulting JSON deliberately has **no** `signature` or `signing_key_id`.
It is **not** a signed release manifest, publication approval, or a release
version assignment. The handoff now **rejects** any candidate whose Cargo package version differs
from the approved release version. A fresh build from a reviewed version-bumped
source commit is required; the operator cannot silently relabel an older binary.

The offline authorized signer must separately establish trusted key custody,
record the independent public-key fingerprint, add the exact `signing_key_id`,
sign the canonical manifest, and run all signed-feed and lifecycle acceptance
gates. The signing key must never be introduced to CI, the public server, this
review command, or the candidate directories.

## Inputs and custody

The reviewer obtains independently from the signed-release process:

- a **separately trusted** Ed25519 public key (Base64, 32 decoded bytes) in a
  local file **outside the candidate feed**;
- the exact expected SHA-256 of those 32 decoded key bytes, confirmed through
  an independent trusted channel (not copied from the candidate feed);
- a previously signed JSON manifest for product `commandcore-agent`, version
  and `signing_key_id` matching that key, with only Linux x86_64 and optional
  ARM64 executable metadata;
- accepted binary bytes matching every signed filename, size and SHA-256;
- an installer generated from the same verified manifest and trusted key using
  `scripts/package_installers.py --linux-only`.

Never put the signing **private key**, vault, private deployment secrets, or
enrollment identities into this folder, your Git history, Actions logs, or the
public host.

## Minimal staging layout (not yet publishable)

~~~text
candidate-feed/
  linux.sh
  manifest.json
  0.9.0-rc8/                         example only: use actual signed version
    commandcore-agent-linux-x86_64
    commandcore-agent-linux-arm64     optional only if signed and accepted
~~~

The exact signed artifact URLs must be
`https://<approved-origin>/releases/agent/<version>/<filename>`. This gate
does not accept artifact URLs at a different origin or mutable/unsigned paths.
Use a separate folder with **only these files**, no prior releases or extra
configuration. The outer key file must not be inside this directory.

Example, after signing and acceptance have already happened independently:

~~~bash
python scripts/package_installers.py manifest.signed.json \
  --public-key "$(cat /reviewed/agent-public-key.b64)" \
  --manifest-url https://commandcore.example.com/releases/agent/manifest.json \
  --linux-only --output /reviewed/candidate-feed

# Copy only the exactly signed, accepted binaries to
# /reviewed/candidate-feed/<signed-version>/<signed-filename>.
python scripts/verify_public_feed_staging.py /reviewed/candidate-feed \
  --trusted-public-key-file /reviewed/agent-public-key.b64 \
  --expected-key-sha256 <independently-confirmed-64-hex-fingerprint> \
  --expected-origin https://commandcore.example.com \
  --expected-version <exact-signed-version>
~~~

The verifier makes **no network requests**, invokes **no installers**, writes
**nothing**, and does not use a private key. It rejects symlinks, special
files, duplicate JSON keys, wrong origin/version/product, untrusted key,
incorrect Ed25519 signature, stale/wrong installer pins, extra files, and
artifact size/hash mismatches. Output success means
`PUBLIC_FEED_STAGING=OFFLINE_INTEGRITY_VERIFIED` alongside
`PROVENANCE_AND_LIFECYCLE_APPROVAL=NOT_VERIFIED` and
`PUBLICATION=NOT_PERFORMED`.

This deliberately narrow candidate feed does not include the optional
uninstaller, helper configuration, Windows Preview, retained older versions,
or SBOM. Those are **separate release gates** and must be independently
reviewed before a final served distribution is created. No CI test with
ephemeral test keys constitutes a public release approval.

Only after the full [release signing](RELEASE_SIGNING.md), [platform support](PLATFORM_SUPPORT.md)
and [public release checklist](PUBLIC_RELEASE_CHECKLIST.md) acceptance gates
pass should an authorized operator prepare immutable, read-only deployment
mounts and separately verify the actual served endpoint bytes. Onboarding
remains stop-ship until that approval occurs.

### Explicit Linux x86_64-only closed-beta review

When the operator intentionally limits an **unpublished** closed-beta review to
Linux x86_64, a verified x86 candidate can be converted into an unsigned
single-architecture manifest draft without pretending an ARM64 build exists:

~~~bash
python scripts/prepare_linux_release_review.py \
  --x86-only \
  --x86-candidate /review/x86_64 \
  --source-sha <exact-reviewed-source-sha> \
  --release-version <actual-version-in-Cargo.toml> \
  --origin https://commandcore.app \
  --output /review/manifest.UNSIGNED.x86-only.json
~~~

The original mode, which requires both `--x86-candidate` and
`--arm64-candidate`, remains the default. `--x86-only` cannot be combined
with an ARM64 candidate. Both modes verify source identity, version, checksums
and executable architecture, and refuse to overwrite the review file.

This is a **signing-review handoff only**. The output is deliberately unsigned,
contains no signing key ID, does not authorize deployment, and does not pass
reboot, update or rollback acceptance. It must be independently signed and
verified before publication; the x86-only option must not be used to advertise
Linux ARM64 support.

### Choosing the signed artifact destination before offline signing

For the self-hosted CommandCore release feed, use `--origin https://commandcore.app`
so each artifact URL points to `https://commandcore.app/releases/agent/<version>/<filename>`.

For the **GitHub native Agent release publishing workflow**, use
`--github-repo bazobehram/commandcore` instead of `--origin`. This produces
`https://github.com/bazobehram/commandcore/releases/download/agent-v<version>/<filename>`
URLs required by `scripts/verify_native_agent_release.py`. These two destinations
are mutually exclusive and cannot share one signed manifest because the artifact
URLs are covered by its Ed25519 signature.

Example x86_64-only GitHub release review (still unsigned):

~~~bash
python scripts/prepare_linux_release_review.py \
  --x86-only \
  --x86-candidate /review/x86_64 \
  --source-sha <reviewed-source-sha> \
  --release-version <approved-version> \
  --github-repo bazobehram/commandcore \
  --output /review/github-release.UNSIGNED.json
~~~

Neither option signs or publishes anything. After independent signing, the
corresponding trusted-key verifier, artifact checks, lifecycle acceptance and
operator approval must pass. Never replace signed URLs after signing.
