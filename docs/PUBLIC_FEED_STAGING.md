# M3: offline signed public Linux Agent feed pre-publication gate

**Status:** candidate integrity verification only. This is **not** permission
to publish, an automatic signer, a release attestation, or an Agent lifecycle
acceptance report. See [public onboarding blocker #157](https://github.com/bazobehram/commandcore/issues/157).

An HTTP 200 from the public endpoint does not prove anything about the key,
signature, binaries or installer. Before mounting a feed on a public server,
the operator must independently review and approve the exact source commit,
signed release, key custody, target binaries, signing provenance and runtime
installation/update/rollback evidence.

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
