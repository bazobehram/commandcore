const {chromium}=require('playwright');
const {startServer}=require('./graphite-server.cjs');
const assert=require('node:assert/strict');
(async()=>{
 const local=await startServer(),browser=await chromium.launch({headless:true,...(process.env.COMMANDCORE_CHROME_BIN?{executablePath:process.env.COMMANDCORE_CHROME_BIN}:{}),args:['--no-sandbox']});
 const commands=['curl -fsSL '+new URL(local.url).origin+'/install/linux | sh','commandcore-agent status','systemctl --user status commandcore-agent.service','commandcore-agent activity','journalctl --user -u commandcore-agent.service -f','journalctl --user -u commandcore-agent.service -n 100 --no-pager','~/.local/bin/commandcore-agent activity'];
 for(const width of [390,1440]){
  const context=await browser.newContext({viewport:{width,height:900},permissions:['clipboard-read','clipboard-write']});
  const page=await context.newPage(),errors=[];page.on('pageerror',e=>errors.push(e.message));
  await page.route('**/api/**',route=>{
   const p=new URL(route.request().url()).pathname;
   const d=n=>({id:n,display_name:n,hostname:n,platform:'Linux',architecture:'x86_64',connected:true,permission_profile:n==='homeserver'?'FULL_CONTROL':'STANDARD',access_max_permission_profile:n==='homeserver'?'FULL_CONTROL':'STANDARD',agent_version:'0.9.0-rc7',capabilities:{local_max_permission_profile:n==='homeserver'?'FULL_CONTROL':'STANDARD'}});
   const data=p==='/api/session'?{subject:'qa',auth_kind:'oauth',scopes:['commandcore:read','commandcore:standard','commandcore:full']}:p==='/api/devices'?{devices:[d('homeserver'),d('other')]}:p==='/api/managed-devices'?{devices:[]}:p==='/api/enrollment/pending'?{enrollments:[]}:{events:[]};
   return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(data)});
  });
  await page.goto(local.url,{waitUntil:'domcontentloaded'});
  await page.locator('.permission-standard .permission-effective').click();
  assert.equal(await page.locator('#detailTitle').innerText(),'other');
  await page.locator('#close').click();
  await page.locator('.permission-full-control .permission-effective').focus();
  await page.keyboard.press('Enter');
  assert.equal(await page.locator('#detailTitle').innerText(),'homeserver');
  await page.locator('#close').click();
  await page.locator('#add').click();
  assert.equal(await page.locator('.onboard-command').count(),7);
  for(let i=0;i<commands.length;i++){
   if(i===4)await page.locator('.onboard-troubleshooting > summary').click();
   await page.locator('.onboard-command').nth(i).locator('button').click();
   const copied=await page.evaluate(()=>navigator.clipboard.readText());
   assert.equal(copied,commands[i],'copy mismatch '+i);
  }
  await page.screenshot({path:'/tmp/cc-onboarding-'+width+'.png',fullPage:true});
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
  assert.deepEqual(errors,[]);
  console.log('ONBOARDING_PASS',width,'CARD_CLICK_KEYBOARD','7_EXACT_COPIES','NO_OVERFLOW','NO_JS_ERRORS');
  await context.close();
 }
 await browser.close();await local.close();
})().catch(e=>{console.error('FAIL',e.stack);process.exit(1)});
