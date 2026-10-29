const { chromium }=require('playwright-core');
const assert=require('node:assert/strict');
(async()=>{
 const browser=await chromium.launch({executablePath:'/usr/bin/chromium',headless:true,args:['--no-sandbox','--disable-dev-shm-usage','--disable-gpu']});
 const output=[],errors=[],mutations=[];
 const seed=[
 {id:'h',display_name:'homeserver',hostname:'homeserver',platform:'Linux',architecture:'x86_64',connected:true,permission_profile:'STANDARD',agent_version:'0.9.0-rc7',capabilities:{local_max_permission_profile:'FULL_CONTROL',privileged_helper:true,filesystem:true,shell:true},grants:[{subject:'qa-operator',max_permission_profile:'STANDARD'},{subject:'teammate',max_permission_profile:'READ_ONLY'}]},
 {id:'g',display_name:'ascent-gx10',hostname:'ascent-gx10',platform:'Linux',architecture:'aarch64',connected:true,permission_profile:'FULL_CONTROL',agent_version:'0.9.0-rc9',capabilities:{desktop:true,local_max_permission_profile:'FULL_CONTROL',privileged_helper:true},grants:[{subject:'qa-operator',max_permission_profile:'FULL_CONTROL'}]},
 {id:'n',display_name:'netti',hostname:'netti',platform:'Linux',architecture:'x86_64',connected:true,permission_profile:'STANDARD',agent_version:'0.9.0-rc7',capabilities:{local_max_permission_profile:'STANDARD',privileged_helper:false},grants:[{subject:'qa-operator',max_permission_profile:'STANDARD'}]}
 ];
 const setup=async(page,scopes=['commandcore:full'])=>{
  page.on('pageerror',e=>errors.push('PAGE '+e.message));page.on('console',m=>{if(m.type()==='error')errors.push('CONSOLE '+m.text().slice(0,200));});
  await page.route('**/api/**',route=>{
   const request=route.request(),url=new URL(request.url()),p=url.pathname,method=request.method(),body=(()=>{try{return request.postDataJSON()??{}}catch{return {}}})();
   if(['PUT','POST','PATCH','DELETE'].includes(method)&&!p.endsWith('/inspect'))mutations.push({method,path:p,body,search:url.searchParams.toString()});
   let res={},status=200;
   if(p==='/api/session')res={subject:'qa-operator',scopes,auth_kind:'oauth2-panel'};
   else if(p==='/api/devices')res={devices:seed.map(d=>({...d,grants:undefined}))};
   else if(p==='/api/managed-devices')res={devices:seed.map(d=>({...d,managed_by_me:true}))};
   else if(p==='/api/enrollment/pending')res={enrollments:[]};
   else if(p.endsWith('/inspect'))res={system_info:{cpu_physical:6,cpu_logical:12,memory_total:16663527424,disk_total:243232677888,processor:'x86_64',platform_release:'6.18.2'},system_metrics:{cpu_percent:5,memory:{total:16663527424,percent:22},disk:{total:243232677888,percent:70},swap:{percent:1}}};
   else if(p.includes('/activity'))res={events:[{tool:'shell.exec',status:'ok',duration_ms:300,args_summary:'ls -la'}]};
   else if(p==='/api/browser/sessions')res={enabled:true,sessions:[{client_id:'client-1',session_id:'session-1'}]};
   else if(p==='/api/browser/frame')res={state:'running',changed:false};
   else if(p==='/api/browser/handoff')res={handoff_path:'/browser/console/qa-token'};
   else if(p.includes('/audit'))res={events:[{timestamp:'2026-10-29T16:00:00Z',tool:'enrollment.device.self_permission',status:'ok',duration_ms:15}]};
   else if(p.includes('/my-permission')&&method==='PUT'){
    const d=seed.find(d=>p.includes(d.id));assert(d);
    assert.equal(body.expected_profile,d.permission_profile);assert.equal(body.expected_grant,d.grants.find(g=>g.subject==='qa-operator')?.max_permission_profile);
    d.permission_profile=body.profile;d.grants.find(g=>g.subject==='qa-operator').max_permission_profile=body.profile;res={ok:true};
   } else if(p.endsWith('/grants')&&method==='PUT'){
    const d=seed.find(d=>p.includes(d.id));assert(d); const prev=d.grants.find(x=>x.subject===body.subject);
    if(prev)prev.max_permission_profile=body.profile;else d.grants.push({subject:body.subject,max_permission_profile:body.profile});res={ok:true};
   } else if(p.endsWith('/grants')&&method==='DELETE'){
    const d=seed.find(d=>p.includes(d.id));assert(d);d.grants=d.grants.filter(g=>g.subject!==url.searchParams.get('subject'));res={ok:true};
   }else if(method==='PATCH'){const d=seed.find(d=>p.includes(d.id));d.display_name=body.display_name;res={ok:true};}
   else res={ok:true};
   route.fulfill({status,contentType:'application/json',body:JSON.stringify(res)});
  });
  await page.route('**/install/linux-ready',route=>route.fulfill({status:200,body:''}));
 };
 const desktop=await browser.newPage({viewport:{width:1440,height:1000}});
 await setup(desktop);
 await desktop.goto('http://commandcore-angular22-web:8080/',{waitUntil:'networkidle'});
 await desktop.locator('.device-tile:not(.add-tile)').first().waitFor();
 await desktop.locator('.workspace-tabs button').filter({hasText:'Access'}).click();
 await desktop.getByText('Device permissions').waitFor();
 assert.equal(await desktop.locator('.layer-card').count(),4);
 await desktop.getByText('Full Control',{exact:true}).first().waitFor();
 output.push('PASS four-layer permission breakdown');
 const save=desktop.getByRole('button',{name:/Review permission change/});
 const choice=desktop.locator('.permission-editor-row select');
 await choice.selectOption('FULL_CONTROL');
 await save.click();
 assert.equal(mutations.filter(m=>m.path.endsWith('/my-permission')).length,0,'must not mutate before confirmation');
 await desktop.getByRole('button',{name:'Cancel'}).click();
 assert.equal(mutations.filter(m=>m.path.endsWith('/my-permission')).length,0,'cancel must be safe');
 await save.click();
 await desktop.getByRole('button',{name:'Confirm and apply'}).click();
 await desktop.waitForTimeout(600);
 const own=mutations.find(m=>m.path.endsWith('/my-permission'));
 assert.deepEqual(own.body,{profile:'FULL_CONTROL',expected_profile:'STANDARD',expected_grant:'STANDARD'});
 output.push('PASS confirmed permission switch + atomic API payload');
 await desktop.getByRole('button',{name:/View device audit trail/}).click();
 await desktop.getByText('enrollment.device.self_permission').waitFor();
 await desktop.locator('.sheet .x-close').click();
 output.push('PASS device audit');
 await desktop.locator('.grant-create input').fill('new-teammate');
 await desktop.locator('.grant-create select').selectOption('STANDARD');
 await desktop.getByRole('button',{name:/Review grant/}).click();
 await desktop.getByRole('button',{name:'Confirm',exact:true}).click();
 await desktop.getByText('new-teammate').waitFor();
 assert(mutations.some(m=>m.path.endsWith('/grants')&&m.method==='PUT'&&m.body.subject==='new-teammate'));
 output.push('PASS adding account grant');
 await desktop.locator('.grant-account').filter({hasText:'new-teammate'}).getByRole('button',{name:'Remove'}).click();
 await desktop.getByRole('button',{name:'Confirm',exact:true}).click();
 await desktop.waitForTimeout(350);
 assert(mutations.some(m=>m.method==='DELETE'&&m.search.includes('new-teammate')));
 output.push('PASS removing account grant with confirmation');
 await desktop.locator('.workspace-tabs button').filter({hasText:'Hardware'}).click();
 await desktop.getByText('Machine details').waitFor();
 assert(await desktop.locator('.capability-grid').count()===1);
 await desktop.locator('.workspace-tabs button').filter({hasText:'Activity'}).click();
 await desktop.getByText('shell.exec').first().click();
 assert(await desktop.getByText('ls -la').count()>0);
 output.push('PASS hardware capability detail + expanded activity');
 await desktop.locator('.device-tile').filter({hasText:'netti'}).click();
 await desktop.locator('.workspace-tabs button').filter({hasText:'Access'}).click();
 await desktop.waitForTimeout(350);
 assert(await desktop.locator('.permission-editor-row option[value=FULL_CONTROL]').isDisabled());
 output.push('PASS local Full Control lockout');
 const mobile=await browser.newPage({viewport:{width:390,height:844},isMobile:true,hasTouch:true});
 await setup(mobile);
 await mobile.goto('http://commandcore-angular22-web:8080/',{waitUntil:'networkidle'});
 await mobile.locator('.workspace-tabs button').filter({hasText:'Access'}).click();
 await mobile.screenshot({path:'/qa/access-mobile.png',fullPage:true});
 assert.equal(await mobile.evaluate(()=>document.documentElement.scrollWidth>innerWidth+2),false);
 output.push('PASS mobile permissions no overflow');
 console.log(output.join('\n'));console.log('PAGE_ERRORS',JSON.stringify(errors));await browser.close();
 if(errors.length)process.exitCode=2;
})().catch(e=>{console.error(e.stack);process.exit(1);});
