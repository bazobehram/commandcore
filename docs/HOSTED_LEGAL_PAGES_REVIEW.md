# Hosted privacy and terms pages — publication review gate

**Status: DRAFT. This source change must not be merged or deployed as legal
publication until the operator has reviewed and approved the actual policies.**
The review drafts live under:

- `apps/workspace-angular/public/privacy/index.html`
- `apps/workspace-angular/public/terms/index.html`

The Angular `angular.json` build copies `public/**/*` into its browser
distribution. A static-site publisher that copies the resulting browser
assets to the public web root can publish these pages without changing
CommandCore's OAuth or MCP routes. **This does not prove that the live public
site is serving them.**

## Required factual and legal review

- [ ] Confirm the hosted service's responsible legal operator, jurisdiction,
      verified email/contact channel, and who processes user requests.
- [ ] Verify the real deployed OAuth, edge, logs, security-audit, device and
      optional Browser data flows; identify subprocessors such as the actual
      configured identity and edge providers rather than assuming one stack.
- [ ] Measure and document actual retention, deletion, account closure, backup,
      and audit retention behavior, including any exceptions.
- [ ] Review access, correction, export and deletion mechanisms and applicable
      privacy-law notices, transfer disclosures and lawful bases with counsel.
- [ ] Approve service eligibility, user responsibilities, prohibited use,
      incident/support channels, service changes, liability and governing law.
- [ ] Remove draft and `noindex` markers only once the final content is
      approved, and link the pages from login, landing, and reviewer materials.
- [ ] Update the public static-site Nginx configuration deliberately so both
      `/privacy` and `/terms` resolve to their approved HTML without a
      redirect/404; keep authorization, MCP and agent proxies unchanged.
- [ ] Verify deployed HTTPS response, page titles, accessibility, cache
      behavior, no sensitive data, and both mobile/desktop layout.
- [ ] Independently validate the approved deployment digest and roll back the
      static-site release if legal links or login/agent routes regress.

Do not substitute a CI green badge for legal approval or for a public HTTPS
verification. The source review PR should remain a **draft** until those
requirements are satisfied. Public and private deployments do not share
legal-operator identity or user data.

Tracking: [#148](https://github.com/bazobehram/commandcore/issues/148),
[#122](https://github.com/bazobehram/commandcore/issues/122).
