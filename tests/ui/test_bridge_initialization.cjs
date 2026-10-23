const {fixtureURL}=require('./fixtures.cjs');
const {chromium}=require('playwright'),assert=require('node:assert/strict');
(async()=>{
 const browser=await chromium.launch({headless:true,...(process.env.CHROMIUM_PATH?{executablePath:process.env.CHROMIUM_PATH}:{}),args:['--no-sandbox']});
 for(const mode of ['mcp','unsupported','denied','timeout']){
  const p=await browser.newPage(),errors=[];p.on('pageerror',e=>errors.push(e.message));
  await p.addInitScript(mode=>{
   window.__fixtureOwnHost=true;window.initializes=[];window.mcpCalls=[];window.nativeCalls=[];window.initialized=false;
   const id='12345678-1234-4234-8234-123456789abc',task={id,total:1,running:0,failed:0,ended:null,last_tool:'shell.exec'};
   const result=name=>name==='activity.feed'?{structuredContent:{task,events:[]}}:{structuredContent:{devices:[]}};
   window.openai={toolOutput:{task_id:id,task,session_available:true,session_ref:'viewer-A'},requestDisplayMode:async()=>{},callTool:async(name,args)=>{window.nativeCalls.push({name,args});return result(name)}};
   window.addEventListener('message',e=>{
    if(e.source!==window||e.data?.jsonrpc!=='2.0')return;const m=e.data;
    if(m.method==='ui/initialize'){
     window.initializes.push(m);
     window.completeInitialization=()=>window.postMessage({jsonrpc:'2.0',id:m.id,...(mode==='unsupported'?{error:{code:-32601,message:'Unsupported method'}}:mode==='denied'?{error:{code:-32000,message:'Host denied initialization'}}:{result:{protocolVersion:'2026-01-26'}})},'*');
    }
    if(m.method==='ui/notifications/initialized')window.initialized=true;
    if(m.method==='tools/call'){
     window.mcpCalls.push({name:m.params.name,args:m.params.arguments,ready:window.initialized});
     window.postMessage({jsonrpc:'2.0',id:m.id,result:result(m.params.name)},'*');
    }
   });
  },mode);
  await p.goto(await fixtureURL());await p.waitForFunction(()=>window.initializes.length===1);
  assert.equal(await p.evaluate(()=>window.mcpCalls.length+window.nativeCalls.length),0,JSON.stringify(await p.evaluate(()=>({native:window.nativeCalls,mcp:window.mcpCalls}))));
  await p.evaluate(()=>window.dispatchEvent(new MessageEvent('message',{source:null,data:{jsonrpc:'2.0',id:window.initializes[0].id,result:{}}})));
  await p.waitForTimeout(50);assert.equal(await p.evaluate(()=>window.mcpCalls.length+window.nativeCalls.length),0,'foreign initialization response ignored');
  if(mode!=='timeout')await p.evaluate(()=>window.completeInitialization());
  if(mode==='mcp'||mode==='unsupported'){
   await p.waitForFunction(()=>window.mcpCalls.length+window.nativeCalls.length>0);
   if(mode==='mcp'){
    assert.equal(await p.evaluate(()=>window.nativeCalls.length),0,'standard host uses standard tools/call');
    assert(await p.evaluate(()=>window.mcpCalls.every(x=>x.ready)),'initialized notification precedes tool calls');
   }else assert.equal(await p.evaluate(()=>window.mcpCalls.length),0,'explicit unsupported method selects legacy native alias');
  }else{
   await p.waitForFunction(()=>document.getElementById('cc-task-summary').textContent==='Live updates paused',null,{timeout:20000});
   assert.equal(await p.evaluate(()=>window.mcpCalls.length+window.nativeCalls.length),0,'denial/timeout never changes transport or sends an action');
   if(mode==='timeout'){await p.evaluate(()=>window.completeInitialization());await p.waitForTimeout(50);assert.equal(await p.evaluate(()=>window.mcpCalls.length+window.nativeCalls.length),0,'late initialization cannot dispatch expired work');}
  }
  assert.equal(await p.evaluate(()=>window.initializes.length),1,'Activity and Browser share one handshake');
  assert.equal(errors.length,0,errors.join('\n'));await p.close();
 }
 await browser.close();console.log('PASS bridge initialization: MCP handshake with native alias present, readiness ordering, explicit legacy fallback, foreign reply rejection, denial/timeout fail closed, no late action');
})().catch(e=>{console.error(e);process.exit(1)});
