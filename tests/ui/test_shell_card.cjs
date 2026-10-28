const {chromium} = require('playwright');
const assert = require('node:assert/strict');
const path = require('node:path');
const {pathToFileURL} = require('node:url');
(async () => {
 const browser = await chromium.launch({headless:true, ...(process.env.CHROMIUM_PATH ? {executablePath:process.env.CHROMIUM_PATH} : {}), args:['--no-sandbox']});
 const page = await browser.newPage(); const errors = [];
 page.on('pageerror', e => errors.push(e.message));
 await page.addInitScript(() => {
  window.openai = {toolOutput:{shell_card:{operation_id:'12345678-1234-4234-8234-123456789abc',command:'hostname',stdout:'fixture-host',stderr:'',status:'completed',exit_code:0}}};
 });
 await page.goto(pathToFileURL(path.join(__dirname, '../../apps/web/shell-card.html')).href);
 await page.waitForFunction(() => document.querySelector('#out').textContent === 'fixture-host');
 assert.equal(await page.locator('#prompt').innerText(), '$ hostname');
 await page.evaluate(() => window.dispatchEvent(new CustomEvent('openai:set_globals', {detail:{globals:{toolOutput:{shell_card:{operation_id:'98765432-1234-4234-8234-123456789abc',command:'other',stdout:'other-output',status:'completed',exit_code:0}}}}})));
 assert.equal(await page.locator('#out').innerText(), 'fixture-host');
 assert.deepEqual(errors, []);
 const protectedPage = await browser.newPage();
 await protectedPage.addInitScript(() => {
  window.openai = {toolOutput:{shell_card:{operation_id:'12345678-1234-4234-8234-123456789abc',command:'',stdout:'',stderr:'',status:'completed',exit_code:0}}};
 });
 await protectedPage.goto(pathToFileURL(path.join(__dirname, '../../apps/web/shell-card.html')).href);
 await protectedPage.waitForFunction(() => !document.querySelector('#preview-note').hidden);
 assert(await protectedPage.locator('#terminal').isHidden());
 assert.match(await protectedPage.locator('#preview-note').textContent(), /protected/);
 await protectedPage.close();
 await browser.close();
 console.log('PASS shell card isolates operations and hides protected previews');
})().catch(error => {console.error(error); process.exit(1)});
