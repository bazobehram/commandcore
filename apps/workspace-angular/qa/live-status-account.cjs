const {chromium}=require('playwright-core');
const assert=require('node:assert/strict');
(async()=>{
 const browser=await chromium.launch({executablePath:'/usr/bin/chromium',headless:true,args:['--no-sandbox','--disable-dev-shm-usage','--disable-gpu']});
 let authenticated=true, online=true,active=false,logs=[]; const errors=[];
 const devices=[
  {id:'srv',display_name:'homeserver',hostname:'homeserver',connected:true,platform:'Linux',architecture:'x86_64',permission_profile:'FULL_CONTROL',agent_version:'0.9.0-rc7',capabilities:{services:true,desktop:false,local_max_permission_profile:'FULL_CONTROL'}},
  {id:'desk',display_name:'ascent-gx10',hostname:'ascent-gx10',connected:true,platform:'Linux',architecture:'aarch64',permission_profile:'FULL_CONTROL',agent_version:'0.9.0-rc7',capabilities:{desktop:true,local_max_permission_profile:'FULL_CONTROL'}},
  {id:'lap',display_name:'netti',hostname:'netti',connected:true,platform:'Linux',architecture:'x86_64',permission_profile:'STANDARD',agent_version:'0.9.0-rc7',capabilities:{desktop:false,local_max_permission_profile:'STANDARD'}}];
 const page=await browser.newPage({viewport:{width:1440,height:950},deviceScaleFactor:1});
 page.on('pageerror',e=>errors.push(e.message));page.on('console',m=>{if(m.type()==='error'&&!( !authenticated && m.text().includes('401')))errors.push('console:'+m.text().slice(0,220));});
 await page.route('**/api/**',r=>{
  const u=new URL(r.request().url()),method=r.request().method();logs.push([u.pathname,method]);let status=200,data={};
  if(u.pathname==='/api/session'){
    if(method==='DELETE'){authenticated=false;data={ok:true};}
    else if(!authenticated){status=401;data={detail:'not authenticated'};}
    else data={subject:'qa-operator',auth_kind:'oauth2-panel',scopes:['commandcore:full','commandcore:standard','commandcore:read']};
  }else if(u.pathname==='/api/devices')data={devices:devices.map(x=>({...x,connected:x.id==='srv'?online:true}))};
  else if(u.pathname==='/api/managed-devices')data={devices:devices.map(x=>({...x,connected:x.id==='srv'?online:true,managed_by_me:true,grants:[{subject:'qa-operator',max_permission_profile:x.permission_profile}]}))};
  else if(u.pathname==='/api/enrollment/pending')data={enrollments:[]};
  else if(/^\/api\/devices\/[^/]+$/.test(u.pathname))data={device:{...devices.find(x=>u.pathname.endsWith(x.id)),active_jobs:active?[{id:'job-1',status:'running'}]:[]}};
  else if(u.pathname.endsWith('/inspect'))data={system_info:{cpu_logical:8,memory_total:16663527424,disk_total:240000000000},system_metrics:{cpu_percent:8,memory:{percent:29},disk:{percent:43}}};
  else if(u.pathname.endsWith('/activity'))data={events:[{tool:'shell.exec',status:'ok',summary:'previous command',duration_ms:101}]};
  else if(u.pathname==='/api/browser/sessions')data={sessions:[]};
  r.fulfill({status,contentType:'application/json',body:JSON.stringify(data)});
 });
 await page.goto('http://commandcore-angular22-web:8080/',{waitUntil:'networkidle'});
 await page.getByText('Your devices,').waitFor();
 assert.equal(await page.locator('.device-tile:not(.add-tile)').count(),3);
 assert.equal(await page.locator('.tile-hardware-glyph[data-role=server]').count(),1);
 assert.equal(await page.locator('.tile-hardware-glyph[data-role=workstation]').count(),1);
 assert.equal(await page.locator('.fleet-hub').count(),1);
 await page.getByRole('button',{name:'Account menu'}).click();
 await page.getByText('SIGNED IN').waitFor();
 await page.getByRole('menuitem',{name:/Sign out/}).waitFor();
 assert.equal(await page.locator('.account-popover').isVisible(),true);
 await page.screenshot({path:'/qa/live-account-desktop.png',fullPage:false});
 await page.locator('.account-dismiss').click({position:{x:15,y:350}});
 await page.locator('.account-popover').waitFor({state:'detached'});
 console.log('PASS account menu + close outside, sign out visible');
 await page.locator('.workspace-tabs button').filter({hasText:'Hardware'}).click();
 await page.getByRole('combobox',{name:'Device card appearance'}).selectOption('laptop');
 await page.waitForFunction(()=>document.querySelector('.device-tile.active .tile-hardware-glyph')?.getAttribute('data-role')==='laptop');
 await page.reload({waitUntil:'networkidle'});
 await page.getByText('Your devices,').waitFor();
 assert.equal(await page.locator('.device-tile.active .tile-hardware-glyph').getAttribute('data-role'),'laptop');
 console.log('PASS explicit laptop card role persists across reload');
 await page.locator('.workspace-tabs button').filter({hasText:'Workspace'}).click();
 active=true;
 await page.waitForFunction(()=>document.querySelector('.device-tile.active .device-status')?.textContent?.includes('Working'),null,{timeout:12500});
 console.log('PASS active-job backend state animates active device, not fabricated');
 active=false;online=false;
 await page.waitForFunction(()=>document.querySelector('.device-tile.active .device-status')?.textContent?.includes('Offline'),null,{timeout:12000});
 console.log('PASS device connection change reflected automatically without refresh');
 online=true;await page.waitForFunction(()=>document.querySelector('.device-tile.active .device-status')?.textContent?.includes('Connected'),null,{timeout:12000});
 assert.equal(await page.locator('.top-actions .quiet-icon').count(),1,'only command palette, no manual refresh');
 console.log('PASS automatic status recovery, no refresh control');
 const mobile=await browser.newPage({viewport:{width:390,height:844},deviceScaleFactor:1,isMobile:true,hasTouch:true});
 await mobile.route('**/api/**',r=>{
  const p=new URL(r.request().url()).pathname;let data={};
  if(p==='/api/session')data={subject:'qa-operator',auth_kind:'oauth2-panel',scopes:['commandcore:full']};
  else if(p==='/api/devices')data={devices};else if(p==='/api/managed-devices')data={devices:devices.map(x=>({...x,managed_by_me:true}))};
  else if(p==='/api/enrollment/pending')data={enrollments:[]};else if(p.endsWith('/inspect'))data={system_info:{cpu_logical:6},system_metrics:{cpu_percent:8,memory:{percent:29},disk:{percent:43}}};
  else if(p.endsWith('/activity'))data={events:[]};else if(p==='/api/browser/sessions')data={sessions:[]};
  else data={device:{...devices[0],active_jobs:[]}};
  r.fulfill({status:200,contentType:'application/json',body:JSON.stringify(data)});
 });
 await mobile.goto('http://commandcore-angular22-web:8080/',{waitUntil:'networkidle'});
 await mobile.getByText('Your devices,').waitFor();
 await mobile.screenshot({path:'/qa/live-roles-mobile.png',fullPage:false});
 assert.equal(await mobile.evaluate(()=>document.documentElement.scrollWidth>innerWidth+2),false);
 console.log('PASS mobile device-role rail no horizontal document overflow');
 await page.getByRole('button',{name:'Account menu'}).click();
 await page.getByRole('menuitem',{name:/Sign out/}).click();
 await page.getByRole('link',{name:/Sign in to CommandCore/}).waitFor({timeout:10000});
 assert(logs.some(x=>x[0]==='/api/session'&&x[1]==='DELETE'));
 console.log('PASS sign out endpoint called and login screen restored');
 console.log('PAGE_ERRORS',JSON.stringify(errors));
 await browser.close();
 if(errors.length)process.exitCode=2;
})().catch(e=>{console.error(e.stack);process.exit(1)});
