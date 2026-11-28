# Public Browser read-only worker publication

The operator publishes only the active worker routes and an immutable
minimal SQLite owner binding containing a worker ID and owner MAC.
The private registry, original owner ledgers and signing key are not mounted
into the API. Publish into a dedicated operator-owned 0750 directory;
manifest and binding files are 0640 with a dedicated publication group.
Mount this directory read-only at the same absolute path in the API.
The API requires the expected operator UID and publication GID and checks
the file identity and permissions. Set COMMANDCORE_BROWSER_PUBLICATION_GID
to the dedicated group, separate from the relay socket group.
Legacy direct private worker permissions are unchanged.

The publisher retains existing published owner bindings instead of
overwriting or reassigning them. Inactive routes are withdrawn; minimal
immutable published ledgers remain as tombstones. On an observed publication
failure, an empty routing manifest is published. A signed physical worker
proof remains separately mandatory for relay actions.

Run the operator publisher with --state-dir, --publication-dir,
--operator-uid and --publication-gid. It can run once or refresh every
two seconds. Use a protected operator service, not an API subprocess.
Actual service deployment, real cross-UID mounts, real Docker topology and
two-account acceptance are still required. No production enablement.
