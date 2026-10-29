const {chromium}=require('playwright-core');
const assert=require('node:assert/strict');
(async()=>{
const b=await chromium.launch({executablePath:'/usr/bin/chromium',headless:true,args:['--no-sandbox','--disable-dev-shm-usage','--disable-gpu']});
const p=await b.newPage({viewport:{width:1250,height:850}}), errors=[];
p.on('pageerror',e=>errors.push(e.message));
const list=[{id:'one',display_name:'homeserver',hostname:'homeserver',connected:true,platform:'Linux',architecture:'x86_64',permission_profile:'FULL_CONTROL',capabilities:{services:true}},
{id:'two',display_name:'ascent-gx10',hostname:'ascent-gx10',connected:true,platform:'Linux',architecture:'aarch64',permission_profile:'FULL_CONTROL',capabilities:{desktop:true}}];
p.route('**/api/**',r=>{
 const x=new URL(r.request().url()).pathname;let o={};
 if(x==='/api/session')o={subject:'qa',scopes:['commandcore:full']};
 else if(x==='/api/devices')o={devices:list};
 else if(x==='/api/managed-devices')o={devices:list.map(d=>({...d,managed_by_me:true}))};
 else if(x==='/api/enrollment/pending')o={enrollments:[]};
 else if(x.endsWith('/inspect'))o={system_info:{cpu_logical:8},system_metrics:{cpu_percent:8,memory:{percent:26},disk:{percent:33}}};
 else if(x.endsWith('/activity'))o={events:[]};
 else if(x.startsWith('/api/devices/'))o={device:{...list.find(d=>x.endsWith('/'+d.id)),active_jobs:x.endsWith('/two')?[{id:'active-only-on-workstation'}]:[]}};
 else if(x==='/api/browser/sessions')o={sessions:[]};
 r.fulfill({status:200,contentType:'application/json',body:JSON.stringify(o)});
});
await p.goto('http://commandcore-angular22-web:8080/',{waitUntil:'networkidle'});
const one=p.locator('.device-tile').filter({hasText:'homeserver'}),two=p.locator('.device-tile').filter({hasText:'ascent-gx10'});
await p.waitForFunction(()=>[...document.querySelectorAll('.device-tile')].some(e=>e.textContent?.includes('ascent-gx10')&&e.textContent.includes('Working')),{timeout:15000});
assert((await one.innerText()).includes('Connected'));
assert((await two.innerText()).includes('Working'));
assert.equal(await p.locator('.fleet-hub.hub-working').count(),1);
console.log('PASS non-selected workstation Working, selected homeserver Connected');
console.log('PASS hub signals active work; all results from /api/devices/{id}.active_jobs');
console.log('PAGE_ERRORS',JSON.stringify(errors));
await b.close();if(errors.length)process.exit(2);
})().catch(e=>{console.error(e.stack);process.exit(1)});
