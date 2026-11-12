# CommandCore branding

**Single canonical symbol:** `assets/branding/octopus-head.svg`, an exact copy of
`apps/workspace-angular/public/brand/octopus-head.svg` and the octopus in the
public site header (`https://commandcore.app/brand/octopus-head.svg`).

Use this octopus, not the former CommandCore artwork, in all new placements.
The README references the repo-local SVG. Current Angular and public site pages
already use the matching `/brand/octopus-head.svg` and state-specific octopus
illustrations (`octopus-online.svg`, `octopus-working.svg`, etc.).

For the older self-hosted web pages the same symbol is packaged at:

- `apps/web/commandcore-mark.svg` (served at `/commandcore-mark.svg`)
- `apps/web/commandcore-icon.png` (PNG compatibility endpoint and MCP/ChatGPT icon)
- `apps/web/commandcore-wordmark.png` (octopus plus CommandCore label)
- `apps/web/commandcore-logo.webp` (WebP compatibility endpoint)
- `assets/branding/commandcore-logo.webp` (WebP branding copy)
- `assets/branding/commandcore-stacked.png` (stacked octopus plus label)
- `apps/workspace-angular/public/favicon.ico` (ICO browser fallback)

All raster variants above are generated from the canonical octopus design.
The old URLs and filenames remain for existing client compatibility, but no
old artwork should remain visible.

When updating the logo, regenerate all raster variants from the canonical
SVG, keep their transparency and existing public dimensions where required,
and verify MCP icon metadata and page asset URLs. Keep the wordmark's colors
consistent with the public site (#1D2A34 and #B9855F).
