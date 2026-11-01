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
let includeDevice = true;
function apiPayload(pathname) {
  if (pathname === '/api/session') return { subject: 'fixture-owner', auth_kind: 'oauth2-panel', scopes: ['commandcore:read'] };
  if (pathname === '/api/devices' || pathname === '/api/managed-devices') return { devices: includeDevice ? [fixtureDevice] : [] };
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
          brandVisible: !!document.querySelector('button.brand[aria-label="Go to workspace"]'),
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
    // Empty onboarding is a distinct route state, not a screenshot-only check.
    includeDevice = false;
    const emptyPage = await browser.newPage({ viewport: { width: 390, height: 780 } });
    await emptyPage.goto(url, { waitUntil: 'domcontentloaded' });
    await emptyPage.locator('.machine-empty').waitFor({ timeout: 15000 });
    assert.equal(await emptyPage.locator('.machine-empty').count(), 1, 'Expected one prominent onboarding card');
    assert.equal(await emptyPage.locator('.add-link').count(), 1, 'Expected toolbar Add device action');
    assert.equal(await emptyPage.locator('.add-tile').count(), 0, 'Unexpected redundant Add Device tile');
    assert.equal(await emptyPage.locator('.round-nav').count(), 0, 'No device arrows should appear without devices');
    await emptyPage.locator('.machine-empty').click();
    await emptyPage.getByRole('dialog', { name: 'Add device' }).waitFor();
    assert.equal(await emptyPage.getByRole('button', { name: 'Close dialog' }).count(), 1);
    await emptyPage.waitForFunction(() => document.activeElement?.matches('.sheet .x-close'));
    assert.equal(await emptyPage.locator('.sheet[aria-modal="true"]').count(), 1, 'Expected modal semantics');
    await emptyPage.keyboard.press('Shift+Tab');
    assert.equal(await emptyPage.evaluate(() => !!document.querySelector('.sheet')?.contains(document.activeElement)), true, 'Shift+Tab escaped the dialog');
    await emptyPage.keyboard.press('Escape');
    await emptyPage.waitForFunction(() => !document.querySelector('.sheet') && document.activeElement?.matches('.machine-empty'));
    await emptyPage.locator('.search-trigger').focus();
    await emptyPage.keyboard.press('Control+k');
    await emptyPage.waitForFunction(() => document.activeElement?.matches('.palette-search input'));
    await emptyPage.keyboard.press('Escape');
    await emptyPage.waitForFunction(() => !document.querySelector('.command-palette') && document.activeElement?.matches('.search-trigger'));
    const faviconPath = await emptyPage.locator('link[rel="icon"][type="image/svg+xml"]').getAttribute('href');
    assert.equal(faviconPath, '/brand/octopus-head.svg', 'Missing octopus SVG favicon');
    await emptyPage.close();
    console.log('PASS empty workspace: single onboarding card, active modal, favicon');
  } finally {
    if (browser) await browser.close();
    await new Promise(resolve => server.close(resolve));
  }
}
main().catch(err => { console.error(err); process.exitCode = 1; });
