# Compatibility policy

CommandCore has four compatibility surfaces:

1. MCP client <-> server;
2. server <-> Agent Protocol;
3. server <-> persisted database/configuration;
4. Agent <-> local helper/update state.

## MCP clients

Client-specific UI and OAuth registration can change outside this project.
CommandCore keeps provider-specific instructions in docs/clients/ and keeps the
core MCP contract vendor-neutral.

A new client should normally require acceptance evidence and documentation, not a
client-specific fork of the server.

## Agent Protocol

Servers should tolerate documented supported older Agent versions where practical.
A wire-incompatible change requires an explicit protocol revision and migration
plan.

Capabilities are negotiated/advertised so unsupported tools fail predictably
instead of being assumed available.

## Database

Schema migrations are numbered and monotonic. Before a server upgrade, operators
must retain a verified database backup and known-good server artifact.

A release must not claim downgrade safety unless it was explicitly tested.

## Configuration

New security-sensitive defaults should fail closed. Removed or renamed settings
must be documented in release notes.

The public .env.example is a template, not production configuration.

## Permission semantics

Existing permission names must never silently gain broader authority.

If a capability's risk meaning changes materially, the project should introduce
a new capability/profile gate or require an explicit migration rather than
reinterpreting an existing grant.

## Release support

See PLATFORM_SUPPORT.md for runtime/platform support and VERSIONING.md for
release-number semantics.
