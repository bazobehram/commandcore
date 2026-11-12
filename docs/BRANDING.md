# CommandCore branding

**Canonical current symbol:** `assets/branding/octopus-head.svg`, matching the public site header at `https://commandcore.app/brand/octopus-head.svg`. Use this self-contained vector for new GitHub documentation and brand placements.

The PNG and WebP artwork below is legacy/compatibility material. Do not introduce new references to it; migrate remaining UI and client surfaces to the canonical symbol with appropriate raster fallbacks where SVG is unsupported.


The supplied original artwork is retained in the repository:

- `assets/branding/commandcore-logo.webp`
- `apps/web/commandcore-icon.png`: transparent square symbol for GitHub, favicons,
  and client icon surfaces.
- `apps/web/commandcore-wordmark.png`: original horizontal wordmark.
- `assets/branding/commandcore-stacked.png`: original stacked wordmark.

The self-hosted web interface packages the same Git blob at:

- `apps/web/commandcore-logo.webp`

Use the approved mark and the `CommandCore` wordmark together. Do not recolor,
distort, rotate, crop into a different mark, add effects, or combine it with
private deployment names, domains, or unrelated brands.

The root README pairs the canonical octopus symbol with the CommandCore heading. Dark web
headers pair that symbol with light text and a blue Core accent, avoiding a white
box behind the supplied navy wordmark. Packaged assets let installed servers
serve the branding without an external CDN or network dependency.

Use the supplied square symbol for small icon surfaces rather than inventing a
substitute mark. The WebP path remains available for compatibility.
