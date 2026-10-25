const {chromium}=require('playwright'),{startServer}=require('./graphite-server.cjs'),assert=require('node:assert/strict');
(async()=>{
 const local=await startServer();
 const browser=await chromium.launch({headless:true,...(process.env.COMMANDCORE_CHROME_BIN?{executablePath:process.env.COMMANDCORE_CHROME_BIN}:{}),args:['--no-sandbox']});
 for(const width of [390,1440]){
  const page=await browser.newPage({viewport:{width,height:840}}),errors=[];
  let events=[{tool:'shell.exec',status:'ok',operation_id:'ok-1',duration_ms:21},{tool:'browser.open',status:'failed',operation_id:'bad-2',duration_ms:33}];
  page.on('pageerror',e=>errors.push(e.message));
  await page.route('**/api/**',route=>{
   const p=new URL(route.request().url()).pathname;
   const d={id:'test-device',display_name:'test-device',hostname:'test-device',platform:'Linux',architecture:'x86_64',connected:true,permission_profile:'STANDARD',access_max_permission_profile:'STANDARD',capabilities:{local_max_permission_profile:'STANDARD'}};
   const data=p==='/api/session'?{subject:'tester',scopes:['commandcore:read','commandcore:standard'],auth_kind:'oauth'}:p==='/api/devices'?{devices:[d]}:p==='/api/managed-devices'?{devices:[]}:p==='/api/enrollment/pending'?{enrollments:[]}:p.includes('/activity')?{events}:{events:[]};
   return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(data)});
  });
  await page.goto(local.url);await page.locator('#activityTab').click();
  const entries=page.locator('.activity-entry');await entries.first().waitFor();
  assert.equal(await entries.count(),2);
  await entries.first().evaluate(e=>e.dataset.acceptanceIdentity='retained');
  await page.waitForTimeout(4200);
  assert.equal(await entries.first().getAttribute('data-acceptance-identity'),'retained','unchanged timeline was recreated');
  await page.locator('select[aria-label="Filter operation status"]').selectOption('error');
  assert.equal(await entries.count(),1);
  assert.match(await entries.first().innerText(),/browser.open/);
  await page.locator('select[aria-label="Filter operation status"]').selectOption('all');
  await page.locator('input[aria-label="Search operations"]').fill('shell');
  assert.equal(await entries.count(),1);
  await page.locator('input[aria-label="Search operations"]').fill('');
  events=[...events,{tool:'git.status',status:'running',operation_id:'run-3'}];
  await page.waitForFunction(()=>document.querySelectorAll('.activity-entry').length===3,null,{timeout:7000});
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
  assert.deepEqual(errors,[]);
  console.log('ACTIVITY_PASS',width,'STABLE_DOM','FILTER','SEARCH','LIVE_EVENT','NO_OVERFLOW','NO_ERRORS');
  await page.close();
 }
 await browser.close();await local.close();
})().catch(e=>{console.error('ACTIVITY_FAIL',e.stack);process.exit(1)});
