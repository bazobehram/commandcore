# Operator legal review drafts — NOT FOR PUBLICATION

**Status: UNAPPROVED.** These working drafts are not the privacy policy or terms currently served by CommandCore. Do not copy them into `COMMANDCORE_LEGAL_PAGES_DIR` or expose them at `/privacy` or `/terms` until all bracketed items are resolved and an authorized reviewer approves the exact final HTML.

These drafts apply to the *public* CommandCore service only, not any private deployment. They are an editorial starting point, **not legal advice**. Facts not established by the code or operator review are deliberately left open.

## Privacy policy — review draft

### 1. Controller and contact

CommandCore public service operator: **[INSERT LEGAL NAME / ENTITY]**.
Privacy and support contact: **[INSERT WORKING CONTACT ADDRESS]**.
Effective date: **[INSERT DATE AFTER APPROVAL]**.
Applicable jurisdiction and contact for statutory rights: **[REVIEW AND INSERT]**.

### 2. Information processed

To provide account login and user-authorized device management, the service may process:

- Account identifiers and authorization metadata from the configured identity provider (currently Auth0 on the public deployment), including subject, issuer, token scopes and authentication/session state;
- Device information such as display name, hostname, platform, architecture, owner identifier, device-key metadata, last-seen status and last IP address;
- Device enrollment, per-account grants, selection handles, job state, audit records and activity/event information;
- Commands and bounded outputs submitted or received through authorized operations. **[VERIFY storage and retention separately; do not promise commands or outputs are never stored.]**
- Optional Browser/session information **[IDENTIFY enablement and processing; public Browser is currently disabled and must not be advertised as enabled]**.

**[VERIFY]** Any additional logs, analytics, cookies, support correspondence, crash reports or client-side telemetry in the actual public deployment.

### 3. Purposes and legal bases

Operational purposes include authentication, linking authorized devices, enforcing account and device permissions, handling requested operations, preventing misuse, and troubleshooting.

**[LEGAL REVIEW REQUIRED]** Specify the applicable legal bases for each purpose, whether data is mandatory, any marketing or analytics purposes, and any consent/withdrawal mechanism.

### 4. Third parties and cross-border processing

The operator must identify the live identity provider, hosting infrastructure, CDN/reverse proxy (currently Cloudflare is used for public HTTPS), logging/monitoring services and relevant subprocessors.

**[VERIFY]** Legal entity names, processing locations, onward transfer practices, and any applicable international transfer mechanisms. Do not imply personal device files are transferred unless this is verified for the feature used.

### 5. Retention and deletion

The source includes activity pruning older than 30 days and a 10,000-record bound **for that activity table during writes**. This is **not** a universal retention policy for audit, jobs, session data, third-party logs, backups or device commands.

**[REQUIRED BEFORE PUBLICATION]** A confirmed table of actual retention/deletion periods, backup expiration, log rotation, account closure, device revocation and authenticated rights requests. Do not promise automatic complete deletion until all systems and backups are accounted for.

### 6. Security and user permissions

CommandCore uses OAuth token validation, per-account device grants and device-local permission ceilings. STANDARD and FULL_CONTROL can authorize powerful actions on an enrolled device. Explain the operational consequences, user approvals, credential protection and limits without claiming perfect security.

**[VERIFY]** Incident contact, notification practices, actual encryption and access-control arrangements before legal approval.

### 7. User rights and changes

**[LEGAL REVIEW REQUIRED]** Describe rights applicable under the selected jurisdiction (including KVKK/GDPR where appropriate), request/appeal channels, response process, policy change notifications and effective dates.

---

## Terms of service — review draft

### 1. Provider and agreement

Public CommandCore service provided by **[INSERT LEGAL ENTITY, CONTACT, ADDRESS IF REQUIRED]**. Effective date: **[AFTER APPROVAL]**. Applicable law, venue, statutory consumer rights and dispute handling: **[LEGAL REVIEW]**.

### 2. Service scope

CommandCore is a self-hostable, AI-assisted device control plane. Public accounts may authorize Agents on devices they control. Some actions execute system commands or manage files and processes according to granted permissions. Product scope, supported OS versions and availability are limited to **[LINK APPROVED SUPPORT MATRIX]**.

### 3. User obligations

Users should connect only devices they own or are permitted to manage, protect their credentials, review privileged operations, comply with applicable laws, and avoid accessing devices or data without authorization.

### 4. Elevated permissions and automation

STANDARD/FULL_CONTROL permissions can make consequential changes to files, services and device state. Explain user approval controls, local permission ceilings, revocation, limitations of generated instructions and recovery procedures. **[VERIFY actual UI/Agent defaults before making guarantees.]**

### 5. Accounts, suspension and data removal

**[OPERATOR DECISION REQUIRED]** Eligibility, minimum age if applicable, account creation, user-initiated closure, operator suspension, data deletion and appeals.

### 6. Pricing, warranties and liability

**[OPERATOR + LEGAL REVIEW REQUIRED]** Free/paid terms, billing/refunds if any, uptime commitments, warranties, liability limits and any consumer-law exceptions. Do not assume the service is free forever or disclaim statutory rights.

### 7. Intellectual property and open source

The source code is licensed as documented in the repository (currently AGPL-3.0-or-later). Hosted service terms should distinguish open-source rights from service-account obligations and third-party components.

### 8. Changes and contact

**[REVIEW]** Notice of changes, effective date, support channel, security reporting, dispute resolution and legal jurisdiction.

---

## Prepublication approval record

- [ ] Operator identity, privacy contact and support channel approved.
- [ ] Actual deployed Auth0, hosting, CDN and subprocessors confirmed.
- [ ] Account, device, job, audit, activity, backup and external-log retention verified.
- [ ] User data access/erasure and account deletion processes demonstrated.
- [ ] Browser enablement and handling accurately described.
- [ ] Device permissions and risk language reviewed against production.
- [ ] Appropriate legal bases, age policy, law/jurisdiction and rights determined.
- [ ] Pricing, liability, warranty and consumer-rights clauses reviewed.
- [ ] Authorized reviewer approves final `privacy.html` and `terms.html`.
- [ ] Files published on **public** deployment only; GET/HEAD, response headers, frontend links and content verified.

References: [Public data handling review](PUBLIC_DATA_HANDLING_REVIEW.md), [Operator legal publication controls](OPERATOR_LEGAL_PAGES.md), [Security model](SECURITY_MODEL.md).

**Shipping gate:** Until the list is satisfied, both public routes intentionally remain unavailable. This file must not be treated as approval.
