# Public data-handling review

Engineering inventory for review only. Not a published privacy policy or terms of service.

## Confirmed in the source

- Device records include display name, hostname, platform, architecture, owner identifier, key metadata, last-seen status and last IP. See `apps/server/commandcore_server/migrations.py`.
- The database includes grants, enrollment, selections, jobs, audit and activity tables. See `migrations.py`.
- `Database.save_activity` removes activity events older than 30 days and limits that table to 10,000 most recent entries during writes. This does not establish retention for audit, jobs, backups or external systems. See `db.py`.
- OAuth settings and panel sessions are configurable. See `config.py` and `main.py`.
- Optional browser integration exists. Review enabled providers and session cleanup separately.

## Required operator verification before approval

- [ ] Legal operator identity, contact, governing jurisdiction.
- [ ] Actual public identity provider, hosting, CDN and subprocessors.
- [ ] Processing purposes, data categories, disclosures and legal bases.
- [ ] Retention and deletion for each category, including backups and external logs.
- [ ] Account removal, data requests and incident contact process.
- [ ] Browser data handling and third-party processing if enabled.
- [ ] Security descriptions of explicit Agent permissions, including FULL_CONTROL.
- [ ] Counsel or authorized reviewer approves exact privacy and terms HTML documents.
- [ ] Public server serves both pages and onboarding links reference them.

The routes deliberately return 404 until reviewed documents are published via `COMMANDCORE_LEGAL_PAGES_DIR`. This checklist does not authorize publishing unsigned Agent releases.
