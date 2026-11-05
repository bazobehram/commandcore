# Operator-reviewed public policy pages

CommandCore exposes `/privacy` and `/terms` **only** after the operator supplies
approved, accurate HTML documents. The integration does not ship placeholder
legal promises or imply that legal review is complete.

1. Review `privacy.html` and `terms.html` against actual data collection,
   processing, storage, retention, deletion, third-party services, and operator
   identity. Seek qualified legal review before public release.
2. Place the approved files in a dedicated public-deployment directory with no
   symlinks.
3. Set `COMMANDCORE_LEGAL_PAGES_DIR` to this directory on the **public** deployment.
   Do not point it to a private application's or secrets directory.
4. Verify GET and HEAD on both routes and confirm rendered content, links, and
   response headers before a public app submission.
5. Until approved documents exist, the routes intentionally return 404.

This does not authorize publication of unsigned Agent releases.
