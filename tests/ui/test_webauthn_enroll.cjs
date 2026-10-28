const { chromium } = require('playwright');
const fs = require('fs');
const assert = require('assert');
const src=fs.readFileSync('/tmp/commandcore-release-work/apps/server/commandcore_server/collaboration_review_routes.py','utf8');
const match=src.match(/        source = r"""([\s\S]*?)"""/);
assert(match,'enrollment script not found');
(async()=>{
 const browser=await chromium.launch({headless:true,executablePath:'/usr/bin/google-chrome',args:['--no-sandbox']});
 try {
  const page=await browser.newPage();
  await page.route('https://panel.example.test/**',route=>route.fulfill({status:200,contentType:'text/html',body:'<button id="enroll-passkey">Enroll</button><p id="enrollment-status"></p>'}));
  await page.goto('https://panel.example.test/');
  await page.evaluate(script=>{new Function(script)()},match[1]);
  await page.getByRole('button').click();
  await page.waitForFunction(()=>document.querySelector('#enrollment-status').textContent.startsWith('Enrollment failed:'));
  assert.match(await page.locator('#enrollment-status').innerText(),/Enrollment failed/);
  assert.equal(await page.getByRole('button').isDisabled(),false);
  console.log('BROWSER_ENROLLMENT_FAILURE_PATH_PASS');
 } finally {await browser.close();}
})().catch(e=>{console.error(e);process.exit(1)});
