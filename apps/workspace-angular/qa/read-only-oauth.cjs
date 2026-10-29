const {chromium}=require('playwright-core');const assert=require('node:assert/strict');
(async()=>{
const b=await chromium.launch({executablePath:'/usr/bin/chromium',headless:true,args:['--no-sandbox','--disable-dev-shm-usage']});
const p=await b.newPage({viewport:{width:390,height:844},isMobile:true,hasTouch:true});
let scope='READ_ONLY',server='READ_ONLY',grant='READ_ONLY',mutated=0;
p.route('**/auth/login?access=standard',async r=>{scope='STANDARD';await r.fulfill({status:302,headers:{location:'/'}});});
p.route('**/api/**',r=>{
const req=r.request(),path=new URL(req.url()).pathname;const d={id:'read-test',display_name:'small-node',platform:'Linux',architecture:'x86_64',connected:true,permission_profile:server,access_max_permission_profile:grant,capabilities:{local_max_permission_profile:'STANDARD',privileged_helper:false},grants:[{subject:'qa',max_permission_profile:grant}]};
let data={ok:true};
if(path==='/api/session')data={subject:'qa',auth_kind:'oauth2-panel',scopes:scope==='STANDARD'?['commandcore:standard','commandcore:read']:['commandcore:read']};
else if(path==='/api/devices')data={devices:[d]};
else if(path==='/api/managed-devices')data={devices:[{...d,managed_by_me:true}]};
else if(path==='/api/enrollment/pending')data={enrollments:[]};
else if(path.includes('inspect'))data={system_info:{cpu_logical:4},system_metrics:{cpu_percent:2,memory:{percent:12},disk:{percent:21}}};
else if(path.includes('activity'))data={events:[]};
else if(path.includes('/my-permission')){const x=req.postDataJSON();assert.equal(x.profile,'STANDARD');assert.equal(x.expected_profile,'READ_ONLY');assert.equal(x.expected_grant,'READ_ONLY');mutated++;server=grant='STANDARD';}
r.fulfill({status:200,contentType:'application/json',body:JSON.stringify(data)});
});
await p.goto('http://commandcore-angular22-web:8080/',{waitUntil:'networkidle'});
await p.locator('.workspace-tabs button').filter({hasText:'Access'}).click();
await p.locator('.permission-editor-row select').selectOption('STANDARD');
await p.getByRole('button',{name:/Review permission change/}).click();
await p.getByText('One more authorization').waitFor();assert.equal(mutated,0);
await p.getByRole('button',{name:/Continue to authorization/}).click();
await p.waitForFunction(()=>document.querySelector('.permission-editor-row select')?.value==='STANDARD'&&document.querySelector('.workspace-tabs button.current')?.textContent.includes('Access'),null,{timeout:12000});
assert.equal(scope,'STANDARD');await p.getByRole('button',{name:/Review permission change/}).click();await p.getByRole('button',{name:'Confirm and apply'}).click();
await p.waitForFunction(()=>document.querySelector('.effective-banner')?.textContent.includes('Standard'),null,{timeout:7000});
assert.equal(mutated,1);assert.equal(await p.evaluate(()=>document.documentElement.scrollWidth>innerWidth+2),false);
console.log('PASS Read Only OAuth -> Standard OAuth -> same device -> explicit permission change');
console.log('PASS mobile viewport no horizontal overflow');
await b.close();
})().catch(e=>{console.error(e.stack);process.exit(1)});
