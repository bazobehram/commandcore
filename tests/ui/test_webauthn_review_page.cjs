const {chromium}=require('playwright');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const source=fs.readFileSync('apps/server/commandcore_server/collaboration_review_routes.py','utf8');
const js=source.match(/async def registration_script[\s\S]*?source = r"""([\s\S]*?)"""/)?.[1];
assert(js,'actual enrollment script missing');
const snippet=source.match(/'<section><h2>Register a passkey<\/h2>'([\s\S]*?)'<\/section><ul>'/ )?.[0];
assert(snippet,'page enrollment section missing');
assert(snippet.includes('id="enroll-passkey"')&&snippet.includes('id="enrollment-status"'));
assert(snippet.includes('<script src="/collaboration/webauthn-enroll.js" defer></script>'));
(async()=>{
 const browser=await chromium.launch({headless:true,executablePath:'/usr/bin/google-chrome',args:['--no-sandbox']});
 try{
  const page=await browser.newPage();
  const calls=[];
  await page.route('https://panel.example.test/**',route=>{
   const path=new URL(route.request().url()).pathname;
   if(path==='/collaboration/webauthn-enroll.js')return route.fulfill({status:200,contentType:'application/javascript',body:js});
   if(path.endsWith('/register/begin')){calls.push('begin');return route.fulfill({status:503,body:'unconfigured'});}
   return route.fulfill({status:200,contentType:'text/html',headers:{'content-security-policy':"default-src 'none'; script-src 'self'; connect-src 'self'"},body:'<!doctype html><html><body><section><h2>Register a passkey</h2><button id="enroll-passkey">Enroll passkey</button><p id="enrollment-status" role="status"></p><script src="/collaboration/webauthn-enroll.js" defer></script></section></body></html>'});
  });
  await page.goto('https://panel.example.test/collaboration/review');
  await page.evaluate(()=>{Object.defineProperty(window,'PublicKeyCredential',{value:function(){}});Object.defineProperty(navigator,'credentials',{configurable:true,value:{create:async()=>{throw Error('should not create')}}});});
  await page.getByRole('button',{name:'Enroll passkey'}).click();
  await page.waitForFunction(()=>document.querySelector('#enrollment-status').textContent.startsWith('Enrollment failed'));
  assert.deepEqual(calls,['begin']);
  assert.equal(await page.getByRole('button',{name:'Enroll passkey'}).isDisabled(),false);
  assert.match(await page.locator('#enrollment-status').innerText(),/503/);
  console.log('BROWSER_REVIEW_PAGE_SCRIPT_LINKAGE_FAIL_CLOSED_PASS');
 }finally{await browser.close()}
})().catch(e=>{console.error(e);process.exit(1)});
