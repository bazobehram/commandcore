# CommandCore Golden Release — 2026-10-24 (V19)

**Status:** User visually accepted on ChatGPT Android. Immutable rollback checkpoint.

## Accepted product behavior

- **Browser V19**: standalone white Browser card, URL/viewport, single header, Minimize/Expand; minimized view reports compact height to the ChatGPT host.
- **Shell V16**: individual terminal cards with command, stdout/stderr, exit code and duration; restricted output does not produce fake command/output strings.
- **Routing V18**: ordinary @CommandCore browser uses browser.open / browser.watch, not legacy commandcore.watch; ordinary Shell uses shell.exec.
- The old aggregate Activity/task UI is opt-in only. Historical UI resources may exist for old conversation cards.

## Exact production capture

The manifest.json records the production Docker image ID and SHA-256 for the 13 production bind-mounted source and UI files in files/. These are frozen runtime inputs and NOT a rebuild from the original main tree. The referenced Docker image must remain available or be exported separately.

Production configuration, private volumes, and browser session state are deliberately excluded. Credentials, /data, and /browser-owner are not part of this release. A Git checkout by itself does not deploy or restore this runtime.

## Restore on the same homeserver

1. Back up the current deployed files and container configuration; save or close conversation-owned Browser sessions before changing the running Browser.
2. Check out this immutable tag into a clean directory and verify manifest.json and SHA-256 checksums.
3. Compare the current Docker image ID, bind mounts, and access policy against the manifest. Do not restore if the environment differs without a reviewed migration.
4. Stop the service safely, copy only the manifest-listed files over their mapped targets using appropriate privileges and atomic writes, preserving current backups.
5. Restart the exact approved container image; wait for healthy.
6. Refresh ChatGPT CommandCore tools; verify hostname; uname -sr Shell output and browser.open + browser.watch with https://www.google.com/, including Android Minimize/Expand and no legacy task card.
7. Roll back the attempted restoration if any acceptance check fails.

Avoid copying the full release over the repository main source tree: this checkpoint captures a multi-generation production set of bind mounts, not an independently built production image.

## Source provenance

- Git base: 4499d05.
- Production image name and immutable ID: manifest.json.
- Frozen production resources: Browser V19, Shell V16, routing V18.
- Separate experimental worktree feat/operation-id-render-isolation was intentionally not committed or altered.
