# Dependency inventory and license review

CommandCore is licensed under **GNU AGPL-3.0-or-later**. Third-party dependencies
remain under their own upstream licenses.

The repository keeps machine-readable dependency snapshots in:

- `docs/dependency-inventory.json`
- `docs/sbom/server.cdx.json`
- `docs/sbom/rust-agent.cdx.json`

These files are engineering inventories. They do not replace license review of
the exact binaries, containers, installers, and operating-system layers that are
published in a release.

## Rust

The Rust Agent uses a committed `Cargo.lock`. Resolved crates declare a mixture
of permissive and other open-source license expressions, including MIT/Apache,
BSD, ISC, Unicode, Zlib, CDLA-Permissive, BSL alternatives, and LGPL alternatives.

Before binary publication:

1. regenerate the inventory from the release commit;
2. review every resolved license expression and required notice;
3. preserve upstream notices required by the selected licenses;
4. run `cargo audit`;
5. archive the audit result with release provenance.

## Python

The server uses a hash-pinned runtime lock in `requirements-server.lock`.
Development/test dependencies are tracked separately in
`requirements-dev.txt`.

Some Python package metadata may omit or incompletely describe licensing. Missing
metadata must be resolved against the package's authoritative upstream license
before redistribution; it is not evidence of permission.

Before container or wheel publication:

1. regenerate the runtime inventory from the exact lock;
2. run `pip-audit`;
3. review package license files/notices;
4. inventory the base image and OS packages as part of the shipped container;
5. retain SBOM and provenance with the release.

## Regeneration

Use `scripts/dependency_inventory.py` in the controlled release environment.
The generated snapshot should match the release commit, dependency locks, and
toolchain used for the published artifacts.

Security/vulnerability databases change continuously, so a previously clean
audit is not a permanent release guarantee. Re-run audits for every release and
during supported-version maintenance.
