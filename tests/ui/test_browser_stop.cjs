const {fixtureURL}=require('./fixtures.cjs');
const {chromium}=require('playwright'),assert=require('node:assert/strict');
(async()=>{
 const browser=await chromium.launch({headless:true,...(process.env.CHROMIUM_PATH?{executablePath:process.env.CHROMIUM_PATH}:{}),args:['--no-sandbox']});
 for(const width of [320,390,940]){
  const p=await browser.newPage({viewport:{width,height:850}}),errors=[];p.on('pageerror',e=>errors.push(e.message));
  await p.addInitScript(()=>{
   const id='12345678-1234-4234-8234-123456789abc',canvas=document.createElement('canvas');canvas.width=1280;canvas.height=720;
   const png=canvas.toDataURL().split(',')[1],task={id,total:1,ended:null,running:0,failed:0,last_tool:'browser.open'};
   window.privateMode=false;window.closed=false;window.closeCalls=[];window.delayClose=false;window.stallFrame=false;window.handoffCalls=0;
   window.openai={toolOutput:{task_id:id,task,session_available:true,session_ref:'viewer-A'},requestDisplayMode:async()=>{},callTool:async(name,args)=>{
    if(name==='devices.list')return {structuredContent:{devices:[]}};
    if(name==='activity.feed')return {structuredContent:{task,events:[]}};
    if(name==='browser.handoff'){window.handoffCalls++;throw Error('Unexpected handoff')}
    if(name==='browser.frame'){
     if(window.stallFrame)return new Promise(resolve=>{window.resolveFrame=resolve});
     if(window.closed)return {isError:true,content:[{type:'text',text:'{"message":"No browser session belongs to this conversation"}'}]};
     return {structuredContent:{session_id:'session-A',state:window.privateMode?'awaiting_human':'agent',sequence:1,changed:!window.privateMode,title:'Example',url:'https://example.com/',action:'Page opened'},content:window.privateMode?[]:[{type:'image',mimeType:'image/png',data:png}]};
    }
    if(name==='browser.close'){
     window.closeCalls.push(args);
     if(window.delayClose)return new Promise(resolve=>{window.resolveClose=resolve});
     window.closed=true;return {structuredContent:{closed:true}};
    }
    throw Error(name);
   }};
  });
  await p.goto(await fixtureURL());await p.locator('#cc-task-expand').click();await p.locator('#browser-screen').waitFor({state:'visible'});
  assert(await p.locator('#browser-stop').isEnabled());
  await p.evaluate(()=>{window.privateMode=true});await p.locator('#browser-refresh').click();await p.locator('#browser-screen').waitFor({state:'hidden'});
  assert(await p.locator('#browser-stop').isDisabled(),'private control cannot be terminated');
  assert.match(await p.locator('#browser-stop').getAttribute('title'),/Resume AI control/);
  await p.evaluate(()=>{window.privateMode=false});await p.locator('#browser-refresh').click();await p.locator('#browser-screen').waitFor({state:'visible'});
  await p.evaluate(()=>{window.delayClose=true});
  if(width===940){
   await p.evaluate(()=>{window.stallFrame=true});await p.locator('#browser-refresh').click();
   await p.locator('#browser-take').click();
  }
  await p.locator('#browser-stop').click();
  if(width===940)await p.evaluate(()=>{window.stallFrame=false;window.resolveFrame({structuredContent:{state:'agent',session_id:'session-A',changed:false}})});
  assert.match(await p.locator('#browser-state').innerText(),/waiting for server confirmation/);
  await p.waitForFunction(()=>document.getElementById('state').textContent.includes('Stopping'));
  assert(await p.locator('#browser-stop').isDisabled());assert(await p.locator('#browser-take').isDisabled());
  assert(await p.locator('#browser-screen').isHidden());
  assert.deepEqual(await p.evaluate(()=>window.closeCalls),[{session_ref:'viewer-A',expected_session_id:'session-A'}]);
  await p.evaluate(()=>{window.closed=true;window.resolveClose({structuredContent:{closed:true}})});
  await p.waitForFunction(()=>document.getElementById('browser-control').textContent==='Stopped');
  assert.match(await p.locator('#browser-state').innerText(),/server confirmed closure/);
  await p.waitForFunction(()=>document.getElementById('state').textContent==='○ Stopped');
  await p.waitForTimeout(4300);assert.equal(await p.locator('#state').innerText(),'○ Stopped','background Activity cannot overwrite Browser status');
  assert(await p.locator('#browser-stop').isDisabled());
  assert(await p.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'Stop toolbar fits viewport');
  assert.equal(await p.evaluate(()=>window.closeCalls.length),1,'closure sent once');
  assert.equal(await p.evaluate(()=>window.handoffCalls),0,'Stop cancels queued takeover instead of starting private control');
  if(width===320){
   await p.evaluate(()=>{window.closed=false});await p.locator('#browser-refresh').click();await p.locator('#browser-screen').waitFor({state:'visible'});
   await p.locator('#browser-stop').click();
   await p.waitForFunction(()=>document.getElementById('browser-host').textContent==='Browser stop unconfirmed',null,{timeout:22000});
   assert.match(await p.locator('#browser-state').innerText(),/No automatic retry/);
   await p.waitForFunction(()=>document.getElementById('state').textContent==='○ Unavailable');
   assert.equal(await p.evaluate(()=>window.closeCalls.length),2);
   await p.evaluate(()=>window.resolveClose({structuredContent:{closed:true}}));
   assert.equal(await p.locator('#browser-host').innerText(),'Browser stop unconfirmed','late success cannot claim confirmed closure');
  }
  assert.equal(errors.length,0,errors.join('\n'));await p.close();
 }
 await browser.close();console.log('PASS Stop Browser: verified session args, private disabled, pending/confirmed states, no duplicate closure, responsive toolbar');
})().catch(e=>{console.error(e);process.exit(1)});
