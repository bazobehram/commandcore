# Versioning

CommandCore uses semantic-version-shaped release numbers:

~~~text
MAJOR.MINOR.PATCH[-prerelease]
~~~

Examples:

~~~text
0.9.0-rc7
0.9.0
1.0.0
~~~

## Before 1.0

The 0.x line is a public development series. Incompatible changes may still be
made when necessary, but they must be documented and migration impact must be
clear.

Wire formats, stored state, and security policy should not change incompatibly
without explicit versioning merely because the project is pre-1.0.

## 1.0 and later

A 1.0 release establishes a compatibility promise for documented stable
interfaces. After 1.0:

- MAJOR: incompatible stable interface/protocol changes;
- MINOR: backward-compatible capabilities;
- PATCH: backward-compatible fixes and hardening.

Security fixes may require behavior tightening in a patch release when preserving
the vulnerable behavior would be unsafe.

## Protocol versions

Product version and protocol version are separate.

Agent Protocol and MCP compatibility behavior are versioned/documented
independently so a server upgrade does not automatically require every Agent or
client to upgrade at once.

## Release candidates

Release-candidate tags are intended for real acceptance before a stable release.
An rc is not a guarantee of production support beyond the documented platform
matrix.

## Database/config migration

Every release note that changes stored state or configuration must state:

- whether migration is automatic;
- whether rollback to the previous server version is safe;
- whether backup is required;
- whether config keys were added, removed, or reinterpreted.
