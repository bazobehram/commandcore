# Frontend ownership and legacy transition

This document is a **source inventory and migration policy**, not evidence that every
user journey or deployment has passed acceptance.

## Canonical experience

The Angular workspace under `apps/workspace-angular/` is the intended user-facing
workspace and PWA. Its session/API boundary is `src/app/api-client.ts` and
`src/app/session-epoch.ts`, with application state rooted at `src/app/app.ts`.
The backend remains the sole authority for OAuth, device grants and permission
checks. Verify the current deployment's routing separately before claiming a
particular public URL is already serving the Angular build.

## Retained compatibility and operator surfaces

| Source | Current responsibility | Transition rule |
| --- | --- | --- |
| `apps/workspace-angular/` | Canonical workspace UI, sessions and device/browser views | Extend with isolated API/session tests and component tests |
| `apps/web/panel.js` | Retained legacy panel/operator functionality, including device policy visibility | Preserve until matching Angular flows pass acceptance |
| `apps/web/legacy-admin.js` | Retained legacy administrative/recovery operations | Do not remove operator/recovery actions without a secure replacement and rollback |
| `apps/server/commandcore_server/main.py` | Route and session handling for web clients | Treat server authorization and routes as the compatibility contract |

The existence of a legacy asset does **not** imply that it is safely removable
or that all routes remain externally exposed in every deployment. Verify actual
routing in `main.py`, deployment configuration and end-to-end tests before a
deprecation or removal decision.

## Acceptance required before retiring a legacy flow

1. Inventory its entry point, server API, users and privilege/recovery role.
2. Implement an Angular replacement without shifting authority into the browser.
3. Prove login, logout, expired session, account switch and stale response
   handling; ensure user data does not survive a changed session.
4. Exercise device enrollment, STANDARD/FULL_CONTROL changes, revocation,
   offline/reconnect and error paths using disposable devices and least privilege.
5. Preserve emergency/admin recovery behind the documented security boundary.
6. Run Angular API/unit/build, backend authorization and route compatibility
   checks; add real browser/mobile and two-user Auth0 acceptance evidence.
7. Document migration, rollback, and the exact supported route before deleting
   old assets. Do not equate GitHub CI alone with public/private deployment acceptance.

## Verification commands

```bash
cd apps/workspace-angular
npm ci
npm run test:api
npm run test:unit
npm run build
```

Run repository `make lint`, `make format-check`, focused backend security
tests and the release candidate gates for relevant implementation changes.
Public and private deployments require independent acceptance and rollback;
a merge into `main` is not an automatic production rollout.

Related: [Architecture](ARCHITECTURE.md), [Development](DEVELOPMENT.md),
[Security model](SECURITY_MODEL.md), and the 1.0 maintainability tracker #123.
