const {chromium}=require('playwright');
const {startServer}=require('./graphite-server.cjs');
const assert=require('node:assert/strict');
const screenshot='iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIHWP4z8DwHwAFgAI/ScL/nwAAAABJRU5ErkJggg==';
(async()=>{
 const local=await startServer();
const browser=await chromium.launch({headless:true,...(process.env.COMMANDCORE_CHROME_BIN?{executablePath:process.env.COMMANDCORE_CHROME_BIN}:{}),args:['--no-sandbox']});
 for(const width of [1440,390]){
  const page=await browser.newPage({viewport:{width,height:850},deviceScaleFactor:1});
  const errors=[],reads=[];let listMode='active',frameMode='normal',delayA=true;
  page.on('pageerror',e=>errors.push(e.message));
  await page.route('**/api/**',async route=>{
   const url=new URL(route.request().url()),p=url.pathname;
   let body={};
   if(p==='/api/session')body={subject:'auth0|browser-acceptance',scopes:['commandcore:read','commandcore:standard','commandcore:full'],auth_kind:'oauth'};
   else if(p==='/api/devices')body={devices:[{id:'d1',display_name:'homeserver',hostname:'homeserver',platform:'Linux',architecture:'x86_64',connected:true,permission_profile:'FULL_CONTROL',access_max_permission_profile:'FULL_CONTROL',capabilities:{local_max_permission_profile:'FULL_CONTROL'}}]};
   else if(p==='/api/managed-devices')body={devices:[]};
   else if(p==='/api/enrollment/pending')body={enrollments:[]};
   else if(p==='/api/browser/sessions')body={enabled:true,sessions:listMode==='empty'?[]:[{client_id:'A',session_id:'aaa111111'},{client_id:'B',session_id:'bbb222222'}]};
   else if(p==='/api/browser/handoff')body={handoff_path:'/browser/console/testtoken123'};
   else if(p==='/api/browser/frame'){
    const id=url.searchParams.get('client_id');reads.push(id);
    if(id==='A'&&delayA){await new Promise(r=>setTimeout(r,850));delayA=false;}
    body=frameMode==='awaiting'?{state:'awaiting_human',changed:false}:{
      state:'running',changed:true,sequence:1,title:id==='A'?'Alpha private':'Beta correct',
      url:id==='A'?'https://example.org/alpha':'https://example.org/beta',
      action:'Viewing '+id,screenshot_base64:screenshot
    };
   }else body={events:[]};
   await route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(body)});
  });
  await page.goto(local.url,{waitUntil:'domcontentloaded'});
  await page.locator('#browserTab').click();
  await page.locator('#browserSession option').first().waitFor({state:'attached'});
  assert.equal(await page.locator('#browserSession option').count(),2);
  await page.locator('#browserSession').selectOption('B');
  await page.waitForFunction(()=>document.querySelector('#browserPage').textContent.includes('Beta correct'),null,{timeout:5000});
  await page.waitForTimeout(1000);
  assert.match(await page.locator('#browserPage').innerText(),/Beta correct/,'stale A frame leaked into B');
  assert.doesNotMatch(await page.locator('#browserPage').innerText(),/Alpha private/);
  const currentSrc=await page.locator('#browserImage').getAttribute('src');assert.ok(currentSrc?.startsWith('data:image/png;base64,'));
  await page.locator('#browserTakeover').click();
  await page.waitForFunction(()=>document.querySelector('#browserAction a')?.getAttribute('href')==='/browser/console/testtoken123',null,{timeout:5000});
  assert.equal(await page.locator('#browserImage').getAttribute('src'),null,'handoff request leaked screenshot');
  assert.equal(await page.locator('#browser').evaluate(e=>e.classList.contains('browser-private')),true);
  frameMode='awaiting';
  await page.locator('#browserRefresh').click();
  await page.waitForFunction(()=>document.querySelector('#browserStatus').textContent.includes('Private human control'),null,{timeout:5000});
  assert.equal(await page.locator('#browserImage').getAttribute('src'),null,'handoff screenshot not cleared');
  await page.screenshot({path:'/tmp/cc-browser-handoff-'+width+'.png',fullPage:true});
  assert.equal(await page.locator('#browserPage').innerText(),'','handoff page URL not cleared');
  assert.equal(await page.locator('#browserAction a').getAttribute('href'),'/browser/console/testtoken123','private control link lost during polling');
  listMode='empty';
  await page.locator('#browserRefresh').click();
  await page.waitForFunction(()=>document.querySelector('#browser').classList.contains('browser-empty'),null,{timeout:5000});
  assert.equal(await page.locator('#browserPause').isDisabled(),true);
  assert.equal(await page.locator('#browserSession').isDisabled(),true);
  assert.equal(await page.locator('#browserTakeover').isDisabled(),true);
  assert.equal(await page.locator('#browserImage').getAttribute('src'),null);
  await page.screenshot({path:'/tmp/cc-browser-empty-accepted-'+width+'.png',fullPage:true});
  listMode='active';frameMode='normal';
  await page.locator('#browserRefresh').click();
  await page.waitForFunction(()=>!document.querySelector('#browser').classList.contains('browser-empty'),null,{timeout:5000});
  assert.equal(await page.locator('#browserPause').isEnabled(),true);
  await page.locator('#browserPause').click();
  assert.equal(await page.locator('#browserPause').innerText(),'Resume live view');
  await page.locator('#browserPause').click();
  assert.equal(await page.locator('#browserPause').innerText(),'Pause live view');
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
  await page.screenshot({path:'/tmp/cc-browser-active-accepted-'+width+'.png',fullPage:true});
  assert.deepEqual(errors,[]);
  console.log('PASS',width,'SESSION_SWITCH_ISOLATED','HANDOFF_PRIVACY','EMPTY_AND_REFRESH','PAUSE_RESUME','NO_OVERFLOW','JS_ERRORS_0','frame_requests='+reads.join(','));
  await page.close();
 }
 await browser.close();await local.close();
})().catch(e=>{console.error('FAIL',e.stack);process.exit(1)});
