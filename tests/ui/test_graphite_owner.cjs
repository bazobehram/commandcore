const {chromium}=require('playwright');
const {startServer}=require('./graphite-server.cjs');
const assert=require('node:assert/strict');
(async()=>{
const local=await startServer();
const browser=await chromium.launch({headless:true,...(process.env.COMMANDCORE_CHROME_BIN?{executablePath:process.env.COMMANDCORE_CHROME_BIN}:{}),args:['--no-sandbox']});
for(const width of [1440,390]){
 const page=await browser.newPage({viewport:{width,height:850}}),errors=[];let writes=0;
 page.on('pageerror',e=>errors.push(e.message));
 const device={id:'mock1',display_name:'homeserver',hostname:'homeserver',platform:'Linux',architecture:'x86_64',connected:true,permission_profile:'FULL_CONTROL',access_max_permission_profile:'FULL_CONTROL',capabilities:{local_max_permission_profile:'FULL_CONTROL',privileged_helper:true},grants:[]};
 await page.route('**/api/**',async route=>{
 const p=new URL(route.request().url()).pathname;
 const v=p==='/api/session'?{subject:'owner-test',auth_kind:'oauth',scopes:['commandcore:read','commandcore:standard','commandcore:full']}:p==='/api/devices'?{devices:[device]}:p==='/api/managed-devices'?{devices:[device]}:p==='/api/enrollment/pending'?{enrollments:[]}:{events:[]};
 if(p.endsWith('/permissions')&&route.request().method()==='POST')writes++;
 await route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(v)});
 });
 await page.goto(local.url,{waitUntil:'domcontentloaded'});await page.locator('.view-device').first().click();
 await page.locator('#cc-device-management > summary').click();
 const form=page.locator('#detailBody .device-permission-form');
 assert.equal(await form.count(),1);assert.equal(await form.locator('select').inputValue(),'FULL_CONTROL');
 await form.locator('select').selectOption('STANDARD');
 await form.locator('button').click();await page.waitForTimeout(150);
 assert.equal(writes,0,'permission changed without explicit confirmation');
 assert.equal(await page.locator('#detail').isVisible(),true);
 await page.screenshot({path:'/tmp/cc-owner-policy-'+width+'.png'});
 assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
 assert.deepEqual(errors,[]);
 console.log('OWNER_UI_PASS',width,'FORM_VISIBLE','CONFIRM_REQUIRED','NO_WRITE','NO_JS_ERROR','NO_OVERFLOW');
 await page.close();
}
await browser.close();await local.close();
})().catch(e=>{console.error('OWNER_UI_FAIL',e.stack);process.exit(1)});
