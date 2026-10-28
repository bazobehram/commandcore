const { chromium } = require('playwright');
const assert = require('node:assert/strict');
const path = require('node:path');
const { pathToFileURL } = require('node:url');

(async () => {
  const browser = await chromium.launch({ headless: true, ...(process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {}), args: ['--no-sandbox'] });
  const page = await browser.newPage();
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.addInitScript(() => {
    window.timelineCalls = [];
    window.openai = {
      toolOutput: { structuredContent: { session_ref: 'viewer-first-1234567890' } },
      callTool: async (name, args) => {
        window.timelineCalls.push({name, args});
        return { structuredContent: { events: [
          {seq: 1, operation_id: 'test-operation', tool: 'shell.exec', device_id: 'fixture', kind: 'started', status: 'running', summary: {command: 'hostname', output_policy: 'bounded_visible'}},
          {seq: 2, operation_id: 'test-operation', tool: 'shell.exec', device_id: 'fixture', kind: 'output', status: 'running', stream: 'stdout', chunk: 'fixture-host'},
        ] } };
      },
    };
  });
  await page.goto(pathToFileURL(path.join(__dirname, '../../apps/web/execution-timeline.html')).href);
  await page.waitForFunction(() => document.querySelector('#counter').textContent === '1 operations');
  await page.locator('#feed summary').click();
  assert.match(await page.locator('#feed').innerText(), /fixture-host/);
  await page.evaluate(() => window.dispatchEvent(new CustomEvent('openai:set_globals', {detail: {globals: {toolOutput: {session_ref: 'viewer-second-123456789'}}}})));
  await page.waitForTimeout(1400);
  const calls = await page.evaluate(() => window.timelineCalls);
  assert(calls.length >= 2);
  assert(calls.every(call => call.name === 'execution.timeline' && call.args.session_ref === 'viewer-first-1234567890'));
  assert.deepEqual(errors, []);
  await browser.close();
  console.log('PASS timeline card renders bounded output and cannot rebind to a different viewer');
})().catch(error => { console.error(error); process.exit(1); });
