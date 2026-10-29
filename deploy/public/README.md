# CommandCore public site distribution

This directory contains the public product landing page and the reference Nginx
reverse-proxy configuration for an independently deployed CommandCore instance.

Build with:

```bash
cd apps/workspace-angular
npm ci
npm run build
cd ../..
python -m pip install 'Markdown==3.9'
python scripts/build_public_site.py
```

The output at `dist/public-site/` contains the landing page, real Angular
dashboard assets and rendered documentation. Do not host the Docker backend
directly on a public TCP interface; it remains on loopback and is reached
through Cloudflare Tunnel and Nginx. Nginx configuration is a reference
template and uses a specific local path; validate it before adopting.

**This CI job builds an immutable artifact but does not deploy it**. Production
release requires an independent OAuth panel client, audience/resource,
authenticated device enrollment, approved release digest and server health
verification. Keep private server data and runtime secrets separate.
