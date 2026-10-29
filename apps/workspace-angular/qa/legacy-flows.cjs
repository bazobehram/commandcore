const { chromium }=require('playwright-core');
const assert=require('node:assert/strict');
(async()=>{
const b=await chromium.launch({executablePath:'/usr/bin/chromium',headless:true,args:['--no-sandbox','--disable-dev-shm-usage']});
const results=[],errors=[],writes=[];
const state={devices:[{id:'h',display_name:'homeserver',hostname:'homeserver',architecture:'x86_64',platform:'Linux',connected:true,managed_by_me:true,permission_profile:'STANDARD',capabilities:{local_max_permission_profile:'FULL_CONTROL',privileged_helper:true},grants:[]}]};
async function setup(page,scope){
 page.on('pageerror',e=>errors.push(e.message));page.on('console',m=>{if(m.type()==='error')errors.push(m.text().slice(0,170));});
 await page.route('**/api/**',route=>{
 const req=route.request(),p=new URL(req.url()).pathname,method=req.method(),body=(()=>{try{return req.postDataJSON()}catch{return {}}})();
 if(['POST','PUT','PATCH','DELETE'].includes(method)&&!p.endsWith('/inspect'))writes.push({p,method,body});
 let data={},code=200;
 if(p==='/api/session')data={subject:'qa-operator',scopes:scope,auth_kind:'oauth2-panel'};
 else if(p==='/api/devices')data={devices:state.devices.map(d=>({...d,managed_by_me:undefined,grants:undefined}))};
 else if(p==='/api/managed-devices')data={devices:state.devices.map(d=>({...d,managed_by_me:true}))};
 else if(p==='/api/enrollment/pending')data={enrollments:[{id:'e1',metadata:{display_name:'qa-new-node',hostname:'new-node',platform:'Linux'},verification_code:'ABCD-1234'}]};
 else if(p.endsWith('/inspect'))data={system_info:{cpu_physical:6,cpu_logical:12},system_metrics:{cpu_percent:7,memory:{percent:30},disk:{percent:40}}};
 else if(p.includes('/activity'))data={events:[]};
 else if(p==='/api/browser/sessions')data={enabled:true,sessions:[{client_id:'browser-owner',session_id:'session1'}]};
 else if(p==='/api/browser/frame')data={state:'awaiting_human',changed:false};
 else if(p==='/api/browser/handoff')data={handoff_path:'/browser/console/testsession'};
 else if(p.endsWith('/my-permission')){const d=state.devices[0];d.permission_profile=body.profile;data={ok:true};}
 else if(p.endsWith('/grants')&&method==='PUT'){state.devices[0].grants.push({subject:body.subject,max_permission_profile:body.profile});data={ok:true};}
 else if(p.endsWith('/grants')&&method==='DELETE'){state.devices[0].grants=[];data={ok:true};}
 else if(p.includes('/decision')&&method==='POST'){data={ok:true};}
 else if(p.endsWith('/revoke')){state.devices[0].revoked_at='2026-10-29T16:10:00Z';data={ok:true};}
 else if(p.endsWith('/h')&&method==='PATCH'){state.devices[0].display_name=body.display_name;data={ok:true};}
 else data={ok:true};
 route.fulfill({status:code,contentType:'application/json',body:JSON.stringify(data)});
 });
 await page.route('**/install/linux-ready',r=>r.fulfill({status:200}));
}
const p=await b.newPage({viewport:{width:1280,height:900}});
await setup(p,['commandcore:standard']);
await p.goto('http://commandcore-angular22-web:8080/',{waitUntil:'networkidle'});
await p.locator('.workspace-tabs button').filter({hasText:'Access'}).click();
await p.getByRole('link',{name:/Reconnect with Full Control/}).waitFor();
assert.equal(await p.locator('.permission-editor-row option[value=FULL_CONTROL]').isDisabled(),false);
await p.locator('.permission-editor-row select').selectOption('FULL_CONTROL');
await p.getByRole('button',{name:/Review permission change/}).click();
await p.getByText('One more authorization').waitFor();
assert.equal(writes.length,0);
await p.locator('.sheet .x-close').click();
results.push('PASS OAuth limited scope and guided Full Control upgrade');
await p.getByRole('button',{name:/Restore my access/}).click();
await p.getByRole('button',{name:'Restore access'}).click();
await p.waitForTimeout(250);
assert(writes.some(w=>w.p.endsWith('/grants')&&w.method==='PUT'&&w.body.subject==='qa-operator'));
results.push('PASS restore account grant');
await p.locator('.rename-row input').fill('server-renamed');
await p.locator('.rename-row button').click();
await p.waitForFunction(()=>document.querySelector('.frame-device-name')?.textContent.includes('server-renamed'),null,{timeout:5000});
assert(writes.some(w=>w.method==='PATCH'&&w.body.display_name==='server-renamed'));
results.push('PASS rename device');
await p.getByRole('button',{name:'Revoke device…'}).click();
await p.getByRole('button',{name:'Revoke this device'}).waitFor();
assert.equal(await p.getByRole('button',{name:'Revoke this device'}).isDisabled(),true);
await p.locator('.confirm-input').fill('incorrect');
assert.equal(await p.getByRole('button',{name:'Revoke this device'}).isDisabled(),true);
await p.locator('.confirm-input').fill('server-renamed');
assert.equal(await p.getByRole('button',{name:'Revoke this device'}).isEnabled(),true);
await p.getByRole('button',{name:'×'}).last().click();
assert.equal(writes.filter(w=>w.p.endsWith('/revoke')).length,0);
results.push('PASS no accidental revoke; exact name required');
await p.getByRole('button',{name:/Review pending/}).count().catch(()=>0);
await p.getByRole('button',{name:/Add device/}).first().click();
await p.getByRole('button',{name:/Review pending requests/}).click();
await p.getByText('qa-new-node').waitFor();
await p.locator('.pending-item input:not([type=checkbox])').fill('ABCD-1234');
await p.getByRole('button',{name:'Approve device'}).click();
await p.waitForTimeout(250);
assert(writes.some(w=>w.p.includes('/decision')&&w.body.approve===true&&w.body.code==='ABCD-1234'));
results.push('PASS new-device enrollment approval');
await p.locator('.workspace-tabs button').filter({hasText:'Browser'}).click();
await p.getByText('Browser control').waitFor();
assert.equal(await p.getByRole('button',{name:/Human control/}).isDisabled(),true); // already awaiting human: no extra handoff
results.push('PASS human handoff state blocks duplicate takeover');
console.log(results.join('\n'));console.log('PAGE_ERRORS',JSON.stringify(errors));await b.close();if(errors.length)process.exitCode=2;
})().catch(e=>{console.error(e.stack);process.exit(1)});
