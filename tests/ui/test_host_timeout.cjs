const {fixtureURL}=require('./fixtures.cjs');
const {chromium}=require('playwright'),assert=require('node:assert/strict');
(async()=>{
 const browser=await chromium.launch({headless:true,...(process.env.CHROMIUM_PATH?{executablePath:process.env.CHROMIUM_PATH}:{}),args:['--no-sandbox']});
 const p=await browser.newPage(),errors=[];
 p.on('pageerror',e=>errors.push(e.message));
 await p.addInitScript(()=>{
  const id='12345678-1234-4234-8234-123456789abc';
  const task={id,total:1,ended:null,running:0,failed:0,last_tool:'browser.open'};
  window.stalled=true;window.pendingFrames=[];window.calls=[];
  window.openai={toolOutput:{task_id:id,task,session_available:true,session_ref:'viewer-A'},requestDisplayMode:async()=>{},callTool:async(name,args)=>{
   window.calls.push({name,args});
   if(name==='devices.list')return {structuredContent:{devices:[]}};
   if(window.stalled)return new Promise(resolve=>{if(name==='browser.frame')window.pendingFrames.push(resolve)});
   if(name==='activity.feed')return {structuredContent:{task,events:[]}};
   if(name==='browser.frame')return {isError:true,content:[{type:'text',text:JSON.stringify({message:'No browser session belongs to this conversation'})}]};
   throw Error(name);
  }};
 });
 await p.goto(await fixtureURL());
 await p.locator('#cc-task-expand').press('Enter');
 await p.waitForFunction(()=>document.getElementById('browser-host').textContent==='Browser status unavailable'&&!document.getElementById('browser-refresh').disabled,null,{timeout:22000});
 assert(await p.locator('#browser-refresh').isEnabled(),'stalled Browser unlocks refresh');
 assert.equal(await p.locator('#browser-screen').getAttribute('src'),null,'no stale image after timeout');
 await p.locator('#activity-tab').press('Enter');
 await p.waitForFunction(()=>document.getElementById('metric-running').textContent==='Unavailable',null,{timeout:22000});
 assert(await p.locator('#activity-reconnect').isVisible(),'stalled Activity offers recovery');
 assert.match(await p.locator('#feed').innerText(),/connection unavailable/i);
 await p.evaluate(()=>{window.stalled=false;for(const resolve of window.pendingFrames)resolve({structuredContent:{changed:false,state:'agent',title:'Late stale page',url:'https://stale.example/'}})});
 assert.notEqual(await p.locator('#browser-host').innerText(),'Late stale page','late host response cannot overwrite recovery');
 await p.locator('#browser-tab').press('Enter');
 await p.locator('#browser-refresh').press('Enter');
 await p.waitForFunction(()=>document.getElementById('browser-host').textContent==='No active browser session'&&!document.getElementById('browser-refresh').disabled,null,{timeout:15000});
 assert(await p.locator('#browser-refresh').isEnabled(),'explicit retry recovers');
 assert(await p.evaluate(()=>window.calls.every(x=>['devices.list','activity.feed','browser.frame'].includes(x.name))),'recovery performs no mutation or scope broadening');
 assert.equal(errors.length,0,errors.join('\n'));
 await browser.close();
 console.log('PASS host timeout: stalled Activity and Browser recover, controls unlock, late response ignored, explicit retry, read-only calls');
})().catch(e=>{console.error(e);process.exit(1)});
