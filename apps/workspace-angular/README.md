# CommandCore Angular workspace

Angular 22 dashboard source shared by public and private deployments.

Build with `npm ci && npm run build` in this directory. The compiled `dist/commandcore-workspace/browser` files are served by an HTTPS reverse proxy; same-origin requests for `/api`, `/auth`, `/mcp`, `/agent`, `/enroll`, installer releases, and OAuth discovery are routed to the CommandCore backend.

Do not commit deployment secrets, session cookies or private device state. Public user sign-in requires an independent OAuth audience and panel callback. A dashboard build alone is not production enrollment acceptance.


## Live CommandCore octopus workspace

The source under `src/` and `public/brand/` reflects the production-tested
Angular 22 workspace and its octopus identity. The build runs
`scripts/postbuild.py` after Angular compilation to emit installable PWA
assets and a versioned service worker. It requires Python 3 and Pillow.

```bash
python3 -m pip install Pillow
npm ci
npm run build
```

Device connectivity is synchronized periodically; active jobs are sourced
from authorized device detail APIs. Browser sessions and account grants remain
subject to existing MCP and OAuth authorization. No separate arbitrary browser
filesystem control is introduced. The `qa/` directory contains Chromium
regression probes; QA fixtures do not belong in the production bundle.

The private reverse proxy, Cloudflare tunnel, local session stores, device
identity keys and operator-specific deployment files are deliberately excluded.
Use the published self-hosting guides and deployment examples to configure
your own installation.
