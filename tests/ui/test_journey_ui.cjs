const {chromium}=require('playwright'),assert=require('node:assert/strict'),path=require('path');
(async()=>{
 const browser=await chromium.launch({headless:true,...(process.env.CHROMIUM_PATH?{executablePath:process.env.CHROMIUM_PATH}:{}),args:['--no-sandbox']});
 for(const width of [320,390,940]){
  const p=await browser.newPage({viewport:{width,height:850}}),errors=[];p.on('pageerror',e=>errors.push(e.message));
  await p.addInitScript(()=>{
   const id='12345678-1234-4234-8234-123456789abc',canvas=document.createElement('canvas');canvas.width=1280;canvas.height=800;const png=canvas.toDataURL().split(',')[1];
   window.index=1;window.sequence=1;window.privateMode=false;window.navigationCalls=[];window.frames=0;window.neverReply=false;window.delayReply=false;window.failNavigation=false;window.lastAction='Link opened';
   window.openai={toolOutput:{task_id:id,task:{id,total:2,ended:null,running:0,failed:0,last_tool:'browser.follow'},session_available:true,session_ref:'viewer-A'},requestDisplayMode:async()=>{},callTool:async(name,args)=>{
    if(name==='activity.feed')return {structuredContent:{task:{id,total:2,ended:null,running:0,failed:0,last_tool:'browser.follow'},events:[]}};
    if(name==='devices.list')return {structuredContent:{devices:[]}};
    if(name==='browser.frame'){
     window.frames++;
     if(window.viewerReplaced)return new Promise(()=>{});
     if(window.privateMode)return {structuredContent:{state:'awaiting_human',sequence:window.sequence,changed:false,action:'Waiting for your manual action'}};
     const changed=args.after_sequence!==window.sequence;
     return {structuredContent:{state:'agent',session_id:'fixture',sequence:window.sequence,changed,action:window.lastAction,busy:false,title:'Public page',url:'https://example.com/page',can_go_back:window.index>0,can_go_forward:window.index<1,recent_pages:[{title:'<img src=x onerror=alert(1)>',url:'https://example.com/one?token=not-for-viewer',current:window.index===0},{title:'Second page',url:'https://example.com/two',current:window.index===1}]},content:changed?[{type:'image',mimeType:'image/png',data:png}]:[]};
    }
    if(name==='browser.back'||name==='browser.forward'){
     window.navigationCalls.push({name,args});
     if(window.neverReply)return new Promise(()=>{});
     if(window.delayReply)return new Promise(resolve=>{window.resolveNavigation=resolve;});
     if(window.failNavigation)return {isError:true,content:[{type:'text',text:'error'}]};
     window.index+=name==='browser.back'?-1:1;window.lastAction=name==='browser.back'?'Previous page opened':'Next page opened';window.sequence++;return {structuredContent:{status:'ok'}};
    }
    throw Error(name);
   }};
  });
  await p.goto('file://'+path.join(process.env.COMMANDCORE_UI_FIXTURES,'task-rendered.html'));await p.locator('#cc-task-expand').click();await p.locator('#browser-screen').waitFor({state:'visible'});
  await p.waitForFunction(()=>!document.getElementById('cc-browser-back').disabled);
  assert.equal(await p.locator('#cc-task-title').innerText(),'Opening a page link');
  assert.equal(await p.locator('#cc-browser-forward').isDisabled(),true);
  await p.locator('#cc-browser-pages').locator('summary').click();
  assert.equal(await p.locator('#cc-browser-pages img').count(),0);assert(!(await p.locator('#cc-browser-pages').innerText()).includes('token='));
  await p.locator('#cc-browser-back').click();await p.waitForFunction(()=>!document.getElementById('cc-browser-forward').disabled);
  assert.equal(await p.locator('#cc-browser-navigation-message').innerText(),'Previous page opened.');
  assert.deepEqual(await p.evaluate(()=>window.navigationCalls),[{name:'browser.back',args:{session_ref:'viewer-A'}}]);
  assert.equal(await p.locator('#cc-browser-back').isDisabled(),true);
  await p.locator('#cc-browser-forward').click();await p.waitForFunction(()=>!document.getElementById('cc-browser-back').disabled);
  assert.equal(await p.evaluate(()=>window.navigationCalls.length),2);
  assert.equal(await p.locator('#cc-browser-navigation-message').innerText(),'Next page opened.');
  assert(await p.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'page must fit narrow viewport');
  await p.evaluate(()=>{window.privateMode=true});await p.locator('#browser-refresh').click();await p.locator('#browser-screen').waitFor({state:'hidden'});
  assert(await p.locator('#cc-browser-back').isDisabled());assert(await p.locator('#cc-browser-forward').isDisabled());assert(await p.locator('#cc-browser-pages').isHidden());
  await p.evaluate(()=>{window.privateMode=false;window.sequence++;window.failNavigation=true});await p.locator('#browser-refresh').click();await p.waitForFunction(()=>!document.getElementById('cc-browser-back').disabled);
  await p.locator('#cc-browser-back').click();await p.waitForFunction(()=>document.getElementById('cc-browser-navigation-message').textContent.includes('could not be confirmed'));
  await p.waitForTimeout(1500);assert.equal(await p.evaluate(()=>window.navigationCalls.length),3,'failed navigation must not be replayed');
  if(width===320){
   await p.evaluate(()=>{window.failNavigation=false;window.neverReply=true});await p.locator('#cc-browser-back').click();await p.waitForTimeout(15500);
   assert.match(await p.locator('#cc-browser-navigation-message').innerText(),/response delayed/);assert.equal(await p.evaluate(()=>window.navigationCalls.length),4);
   await p.evaluate(()=>{window.neverReply=false});
  }
  await p.evaluate(()=>{window.failNavigation=false;window.delayReply=true});await p.waitForFunction(()=>!document.getElementById('cc-browser-back').disabled);await p.locator('#cc-browser-back').click();
  await p.waitForFunction(()=>typeof window.resolveNavigation==='function');
  await p.evaluate(()=>{window.viewerReplaced=true;window.dispatchEvent(new Event('commandcore:viewer-changed'));window.resolveNavigation({structuredContent:{status:'ok'}});});
  await p.waitForTimeout(80);assert(await p.locator('#cc-browser-navigation-message').isHidden());assert(await p.locator('#cc-browser-back').isDisabled());
  assert.equal(errors.length,0,errors.join('\n'));await p.close();
 }
 await browser.close();console.log('PASS journey UI: Back/Forward, page labels, query removal, responsive layout, private shield, no action replay after failure/timeout, stale-viewer response ignored');
})().catch(e=>{console.error(e);process.exit(1)});
