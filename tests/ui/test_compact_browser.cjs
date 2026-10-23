const {chromium}=require('playwright'),assert=require('node:assert/strict'),fs=require('fs'),path=require('path');
(async()=>{
 const browser=await chromium.launch({headless:true,...(process.env.CHROMIUM_PATH?{executablePath:process.env.CHROMIUM_PATH}:{}),args:['--no-sandbox']});let results=[];
 for(const width of [320,390,940]){
  const p=await browser.newPage({viewport:{width,height:850}});let errors=[];p.on('pageerror',e=>errors.push(e.message));
  await p.addInitScript(()=>{
   const id='12345678-1234-4234-8234-123456789abc',canvas=document.createElement('canvas');canvas.width=1280;canvas.height=720;const context=canvas.getContext('2d');context.fillStyle='#f1f5f9';context.fillRect(0,0,1280,720);context.fillStyle='#172033';context.font='48px sans-serif';context.fillText('Public browser preview',60,100);const png=canvas.toDataURL().split(',')[1];
   window.phase='missing';window.frameRequests=[];window.ended=false;
   window.openai={toolOutput:{task_id:id,task:{id,total:1,ended:null,running:0,failed:0,last_tool:'browser.search'},session_available:true,session_ref:'viewer-A'},notifyIntrinsicHeight:()=>{},requestDisplayMode:async()=>{},callTool:async(n,a)=>{
    if(n==='activity.feed')return {structuredContent:{task:{id,total:window.phase==='other'?2:1,ended:window.ended?1:null,running:0,failed:0,last_tool:window.phase==='other'?'system.metrics':'browser.search'},events:[{tool:'browser.search',status:'ok'}]}};
    if(n==='browser.frame'){
     window.frameRequests.push(a.after_sequence);
     if(window.phase==='private')return {structuredContent:{state:'awaiting_human',sequence:4,changed:false}};
     // Metadata arrives before the host supplies its image. Same server sequence
     // must remain eligible for the next read-only frame request.
     if(window.phase==='missing')return {structuredContent:{state:'agent',session_id:'browser-A',sequence:4,changed:true},content:[]};
     return {structuredContent:{state:'agent',session_id:'browser-A',sequence:4,changed:a.after_sequence!==4},content:a.after_sequence!==4?[{type:'image',mimeType:'image/png',data:png}]:[]};
    }
    if(n==='devices.list')return {structuredContent:{devices:[]}};
    throw Error('unexpected '+n);
   }};
  });
  await p.goto('file://'+path.join(process.env.COMMANDCORE_UI_FIXTURES,'task-rendered.html'));await p.waitForFunction(()=>window.frameRequests.length>0);
  await p.evaluate(()=>window.phase='public');await p.locator('#cc-task-preview').waitFor({state:'visible',timeout:5000});
  assert.equal(await p.locator('body').getAttribute('data-cc-task-compact'),'true','preview requires no expansion');
  assert.match(await p.locator('#cc-task-caption').innerText(),/Live preview/);
  await p.evaluate(()=>window.phase='other');await p.waitForFunction(()=>document.getElementById('cc-task-title').textContent==='Device resources');
  assert(await p.locator('#cc-task-preview').isVisible(),'other task steps must not hide an active browser');
  const before=await p.evaluate(()=>window.frameRequests.length);await p.evaluate(()=>window.phase='private');
  await p.locator('#cc-task-preview').waitFor({state:'hidden',timeout:5000});assert.equal(await p.locator('#cc-task-preview').getAttribute('src'),null);assert.match(await p.locator('#cc-task-caption').innerText(),/Private human/);
  await p.evaluate(()=>window.phase='public');await p.locator('#cc-task-preview').waitFor({state:'visible',timeout:5000});
  assert((await p.locator('#cc-task-preview').boundingBox()).height>=170,'useful inline preview size');
  assert(await p.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
  if(width===390)await p.screenshot({path:path.join(process.env.COMMANDCORE_UI_FIXTURES,'inline-browser-preview.png'),clip:{x:0,y:0,width,height:Math.ceil((await p.locator('body').boundingBox()).height)}});
  await p.evaluate(()=>window.ended=true);await p.locator('#cc-task-preview').waitFor({state:'hidden',timeout:5000});
  assert.equal(await p.locator('#cc-task-preview').getAttribute('src'),null,'ended cards must not retain private-sensitive stale screens');
  const count=await p.evaluate(()=>window.frameRequests.length);await p.waitForTimeout(1700);assert.equal(await p.evaluate(()=>window.frameRequests.length),count,'ended cards do not poll a later browser');
  assert.deepEqual(errors,[]);await p.close();results.push({width,status:'PASS',cases:'first-image retry, no expansion, later nonbrowser step, private hide/resume, useful size, end clears/stops'});
 }
 await browser.close();fs.writeFileSync(path.join(process.env.COMMANDCORE_UI_FIXTURES,'compact-browser-results.json'),JSON.stringify(results,null,2));console.log(results);
})().catch(e=>{console.error(e);process.exit(1)});
