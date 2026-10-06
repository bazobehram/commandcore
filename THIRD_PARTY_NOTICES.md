# Third-party notices

CommandCore includes and depends on third-party free/open-source software. Those
components remain under their respective upstream licenses.

The resolved Python and Rust dependency inventories, declared license metadata,
and CycloneDX application SBOMs are documented under docs/DEPENDENCY_LICENSES.md
and docs/sbom/.

## Desktop Commander

CommandCore is not a fork of Desktop Commander MCP and does not vendor Desktop
Commander source code.

The project has reviewed Desktop Commander as a related MCP computer-control
project and records that architectural comparison in
docs/COMPARISON_DESKTOP_COMMANDER.md. Desktop Commander is distributed upstream
under the MIT License. No Desktop Commander source is included in CommandCore.

## Release obligation

Before publishing binaries or container images, maintainers must regenerate the
dependency inventory for the exact release, preserve required upstream notices,
review container/OS-layer obligations, run vulnerability scans, and retain
artifact provenance/signing evidence.

This file is an engineering inventory notice, not a substitute for legal review
of a specific distribution.
