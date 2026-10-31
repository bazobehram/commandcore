'use strict';

// Isolated Angular UI acceptance: built static assets and synthetic API only.
// Does not connect to OAuth, a live deployment, or any enrolled device.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const { chromium } = require('playwright');

const assets = path.resolve(__dirname, '../../apps/workspace-angular/dist/commandcore-workspace/browser');
const contentTypes = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml', '.json': 'application/json', '.png': 'image/png', '.ico': 'image/x-icon' };
const fixtureDevice = {
  id: 'fixture-laptop', display_name: 'Fixture Laptop', hostname: 'fixture-laptop',
  platform: 'Linux', architecture: 'x86_64', connected: true, status: 'online',
  is_owner: true, managed_by_me: true, permission_profile: 'READ_ONLY',
  access_max_permission_profile: 'READ_ONLY', capabilities: { desktop: true, services: false },
};
function apiPayload(pathname) {
  if (pathname === '/api/session') return { subject: 'fixture-owner', auth_kind: 'oauth2-panel', scopes: ['commandcore:read'] };
  if (pathname === '/api/devices' || pathname === '/api/managed-devices') return { devices: [fixtureDevice] };
  if (pathname === '/api/enrollment/pending') return { enrollments: [] };
  if (pathname.startsWith('/api/devices/')) return { device: fixtureDevice, events: [] };
  return { devices: [], events: [], activity: [], sessions: [] };
}
async function main() {
  assert.ok(fs.existsSync(path.join(assets, 'index.html')), 'Run npm run build in apps/workspace-angular first');
  const server = http.createServer((req, res) => {
    const pathname = new URL(req.url, 'http://localhost').pathname;
    if (pathname.startsWith('/api/')) {
      res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
      return res.end(JSON.stringify(apiPayload(pathname)));
    }
    const relative = pathname === '/' || pathname === '/workspace/' ? 'index.html' : pathname.replace(/^\//, '');
    const full = path.resolve(assets, relative);
    if (!full.startsWith(assets + path.sep) && full !== path.join(assets, 'index.html')) {
      res.writeHead(403); return res.end();
    }
    fs.readFile(full, (err, data) => {
      if (err) { res.writeHead(404); return res.end(); }
      res.writeHead(200, { 'Content-Type': contentTypes[path.extname(full)] || 'application/octet-stream' });
      res.end(data);
    });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const url = `http://127.0.0.1:${server.address().port}/`;
  let browser;
  try {
    browser = await chromium.launch({ headless: true });
    for (const width of [320, 390, 940]) {
      const page = await browser.newPage({ viewport: { width, height: 780 }, deviceScaleFactor: 1 });
      await page.goto(url, { waitUntil: 'domcontentloaded' });
      await page.locator('.account-trigger').waitFor({ timeout: 15000 });
      await page.locator('.device-tile').first().waitFor({ timeout: 15000 });
      const layout = await page.evaluate(() => {
        const rect = document.querySelector('.account-trigger').getBoundingClientRect();
        return {
          width: window.innerWidth,
          scrollWidth: document.documentElement.scrollWidth,
          accountLeft: rect.left,
          accountRight: rect.right,
          brandVisible: !!document.querySelector('.brand[role="button"]'),
        };
      });
      assert.ok(layout.brandVisible, `Missing keyboard navigable workspace brand at ${width}`);
      assert.ok(layout.accountLeft >= 0 && layout.accountRight <= width, `Account menu control outside viewport at ${width}: ${JSON.stringify(layout)}`);
      assert.ok(layout.scrollWidth <= width + 2, `Unexpected horizontal document overflow at ${width}: ${JSON.stringify(layout)}`);

      await page.getByRole('button', { name: /Browser/ }).first().click();
      await page.locator('.brand').focus();
      await page.keyboard.press('Space');
      await page.locator('.workspace-tabs button.current').first().waitFor();
      const selected = await page.locator('.workspace-tabs button.current').first().textContent();
      assert.match(selected, /Workspace/);
      console.log(`PASS width=${width}px, accessible account control + no page overflow + Space navigation`);
      await page.close();
    }
  } finally {
    if (browser) await browser.close();
    await new Promise(resolve => server.close(resolve));
  }
}
main().catch(err => { console.error(err); process.exitCode = 1; });
