# CommandCore Angular workspace

Angular 22 dashboard source shared by public and private deployments.

Build with `npm ci && npm run build` in this directory. The compiled `dist/commandcore-workspace/browser` files are served by an HTTPS reverse proxy; same-origin requests for `/api`, `/auth`, `/mcp`, `/agent`, `/enroll`, installer releases, and OAuth discovery are routed to the CommandCore backend.

Do not commit deployment secrets, session cookies or private device state. Public user sign-in requires an independent OAuth audience and panel callback. A dashboard build alone is not production enrollment acceptance.
