# CommandCore branding

The turquoise mark in `assets/branding/commandcore-mark.png` matches the
CommandCore listing artwork. The same PNG is published at
`/brand/commandcore-mark.png` by the public site and the Angular workspace.

Use this mark in website headers and browser icons, and use the repository copy
in the README. The workspace uses state-specific illustrations such as
`octopus-online.svg` and `octopus-working.svg` for activity and device status.

For the older self-hosted web pages the same symbol is packaged at:

- `apps/web/commandcore-mark.svg` (served at `/commandcore-mark.svg`)
- `apps/web/commandcore-icon.png` (PNG compatibility endpoint and MCP/ChatGPT icon)
- `apps/web/commandcore-wordmark.png` (octopus plus CommandCore label)
- `apps/web/commandcore-logo.webp` (WebP compatibility endpoint)
- `assets/branding/commandcore-logo.webp` (WebP branding copy)
- `assets/branding/commandcore-stacked.png` (stacked octopus plus label)
- `apps/workspace-angular/public/favicon.ico` (ICO browser fallback)

The SVG and raster variants use the same artwork. Existing URLs and filenames
remain for client compatibility.

When updating the logo, regenerate variants from the source artwork. Keep
their transparency and public dimensions where required, verify the page
asset URLs, and include 16, 32, and 48 pixel frames in the favicon. Keep the
wordmark colors consistent with the public site (#1D2A34 and #B9855F).
