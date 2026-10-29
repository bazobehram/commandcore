const { chromium } = require('playwright-core');
const assert = require('node:assert/strict');
(async () => {
 const browser=await chromium.launch({executablePath:'/usr/bin/chromium',headless:true,args:['--no-sandbox','--disable-dev-shm-usage','--disable-gpu']});
 const errors=[];const out=[];
 const devices=[
  {id:'h',display_name:'homeserver',hostname:'homeserver',platform:'Linux',architecture:'x86_64',connected:true,permission_profile:'FULL_CONTROL',agent_version:'0.9.0-rc7',capabilities:{desktop:false,local_max_permission_profile:'FULL_CONTROL',privileged_helper:true}},
  {id:'g',display_name:'ascent-gx10',hostname:'ascent-gx10',platform:'Linux',architecture:'aarch64',connected:true,permission_profile:'FULL_CONTROL',agent_version:'0.9.0-rc9',capabilities:{desktop:true,local_max_permission_profile:'FULL_CONTROL',privileged_helper:true}},
  {id:'n',display_name:'netti',hostname:'netti',platform:'Linux',architecture:'x86_64',connected:true,permission_profile:'STANDARD',agent_version:'0.9.0-rc7',capabilities:{desktop:false,local_max_permission_profile:'STANDARD',privileged_helper:false}}
 ];
 const setup=async(page)=>{
 page.on('pageerror',e=>errors.push('PAGE: '+e.message));page.on('console',msg=>{if(msg.type()==='error')errors.push('CONSOLE: '+msg.text().slice(0,260));});
 await page.route('**/api/**',route=>{
 const url=new URL(route.request().url());const p=url.pathname;
 let payload={};
 if(p==='/api/session')payload={subject:'qa-operator',scopes:['commandcore:full']};
 else if(p==='/api/devices')payload={devices};
 else if(p==='/api/managed-devices')payload={devices:devices.map(x=>({...x,managed_by_me:true}))};
 else if(p==='/api/enrollment/pending')payload={enrollments:[]};
 else if(p.includes('/inspect'))payload={system_info:{cpu_logical:12,memory_total:16663527424,disk_total:243232677888,processor:'Intel Core i7'},system_metrics:{cpu_percent:8.4,memory:{percent:27.2,total:16663527424},disk:{percent:68.9,total:243232677888}}};
 else if(p.includes('/activity'))payload={events:[{tool:'shell.exec',status:'ok',summary:'Command completed'}]};
 else if(p==='/api/browser/sessions')payload={enabled:true,sessions:[{client_id:'c1',session_id:'session-test'}]};
 else if(p==='/api/browser/frame')payload={state:'running',changed:false,action:'Navigate to page',sequence:1,title:'Example',url:'https://example.com'};
 else if(p==='/api/browser/handoff')payload={handoff_path:'/browser/console/mocktoken'};
 route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(payload)});
 });
 await page.route('**/install/linux-ready',route=>route.fulfill({status:200,body:''}));
 };
 const d=await browser.newPage({viewport:{width:1440,height:930},deviceScaleFactor:1});
 await setup(d);await d.goto('http://commandcore-angular22-web:8080/',{waitUntil:'networkidle'});
 await d.getByText('Your devices,').waitFor();
 assert.equal(await d.locator('.device-tile:not(.add-tile)').count(),3);
 out.push('DESKTOP: device carousel + API session + live inspection OK');
 await d.screenshot({path:'/qa/screenshot-desktop.png',fullPage:true});
 await d.getByRole('button',{name:'ascent-gx10'}).first().click();
 await d.waitForFunction(()=>document.querySelector('.frame-device-name')?.textContent.includes('ascent-gx10'),null,{timeout:6500});
 await d.getByRole('button',{name:/Browser/}).first().click();
 await d.getByText('Browser control').waitFor();out.push('BROWSER: workspace tab and authenticated session selector OK');
 await d.getByRole('button',{name:/Human control/}).first().click();
 await d.getByText('Private human control').waitFor();out.push('HANDOFF: private-control state OK');
 await d.getByRole('button',{name:/Activity/}).first().click();
 await d.getByText('Activity stream').waitFor();out.push('ACTIVITY: audit section OK');
 await d.locator('.workspace-tabs button').filter({hasText:'Access'}).click();
 await d.getByText('Device permissions').waitFor();out.push('ACCESS: permissions screen OK');
 await d.getByRole('button',{name:/Add device/}).first().click();
 await d.getByText('Install the Agent').waitFor();out.push('ONBOARDING: signed installer gate OK');
 const m=await browser.newPage({viewport:{width:390,height:844},deviceScaleFactor:1,isMobile:true,hasTouch:true});
 await setup(m);await m.goto('http://commandcore-angular22-web:8080/',{waitUntil:'networkidle'});
 await m.getByText('Your devices,').waitFor();
 await m.screenshot({path:'/qa/screenshot-mobile.png',fullPage:true});
 const overflow=await m.evaluate(()=>document.documentElement.scrollWidth>innerWidth+2);
 assert.equal(overflow,false,'mobile horizontal overflow');
 out.push('MOBILE: 390px layout and overflow OK');
 console.log(out.join('\n'));
 console.log('PAGE_ERRORS:',JSON.stringify(errors.slice(0,10)));
 await browser.close();
 if(errors.length)process.exitCode=2;
})().catch(err=>{console.error(err.stack);process.exit(1);});
