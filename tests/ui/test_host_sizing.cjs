const {chromium}=require('playwright'),assert=require('node:assert/strict'),fs=require('fs'),path=require('path');
// Reproduce the installed Codex inline-height calculation, without modifying it.
const inlineHeight=(intrinsic,hint,min)=>Math.max(intrinsic??hint??480,min??200);
(async()=>{
 const browser=await chromium.launch({headless:true,...(process.env.CHROMIUM_PATH?{executablePath:process.env.CHROMIUM_PATH}:{}),args:['--no-sandbox']});const results=[];
 const metadata=JSON.parse(fs.readFileSync(path.join(process.env.COMMANDCORE_UI_FIXTURES,'sizing-meta.json')));
 for(const width of [320,390,940])for(const channel of ['openai','mcp','throwing-openai']){
  const p=await browser.newPage({viewport:{width,height:850}});const errors=[];p.on('pageerror',e=>errors.push(e.message));
  // This parent owns iframe height, as Codex does. Content cannot resize its parent directly.
  await p.setContent('<style>body{margin:0}iframe{border:0;display:block;width:100%}</style><iframe title="CommandCore test"></iframe>');
  await p.evaluate(({metadata})=>{const frame=document.querySelector('iframe');frame.height=String(Math.max(metadata['openai/widgetHeightHint']??480,metadata['openai/widgetMinFrameHeight']??200));window.acceptHeight=h=>{frame.height=String(Math.max(h,metadata['openai/widgetMinFrameHeight']??200))};window.addEventListener('message',e=>{if(e.source===frame.contentWindow&&e.data?.method==='ui/notifications/size-changed')window.acceptHeight(e.data.params.height)});},{metadata});
  const boot=`<script>(()=>{const id='12345678-1234-4234-8234-123456789abc';window.task={id,total:8,ended:null,running:0,failed:0,last_tool:'shell.exec',device:'test-device'};window.openai={toolOutput:{task_id:id,task:window.task,session_available:true,session_ref:'fixture'},callTool:async n=>n==='activity.feed'?{structuredContent:{task:window.task,events:[{tool:'shell.exec',status:'ok',device:'test-device',detail:{path:'/tmp/fixture'}}]}}:{structuredContent:{devices:[]}},requestDisplayMode:async()=>{}};if('${channel}'==='openai')window.openai.notifyIntrinsicHeight=h=>parent.acceptHeight(h);if('${channel}'==='throwing-openai')window.openai.notifyIntrinsicHeight=()=>{throw Error('Unsupported host channel')};})();<\/script>`;
  const html=fs.readFileSync(path.join(process.env.COMMANDCORE_UI_FIXTURES,'task-rendered.html'),'utf8').replace('<head>','<head>'+boot);
  await p.locator('iframe').evaluate((e,html)=>{e.srcdoc=html},html);const f=p.frameLocator('iframe');
  await f.locator('#cc-task-title').waitFor({state:'visible'});
  await p.waitForFunction(()=>{const f=document.querySelector('iframe'),b=f.contentDocument?.body;return b&&Math.abs(f.clientHeight-b.getBoundingClientRect().height)<=2});
  const compact=await f.locator('body').evaluate(e=>e.getBoundingClientRect().height);assert(compact<150);
  assert.equal(await f.locator('#cc-task').count(),1);
  await f.locator('#cc-task-steps summary').click();
  await p.waitForFunction(()=>{const f=document.querySelector('iframe');return Math.abs(f.clientHeight-f.contentDocument.body.getBoundingClientRect().height)<=2});
  assert((await f.locator('body').evaluate(e=>e.getBoundingClientRect().height))>compact);
  await f.locator('#cc-task-steps summary').click();
  await f.locator('#cc-task-expand').click();await f.locator('#cc-task-back').click();
  await p.waitForFunction(()=>{const f=document.querySelector('iframe');return Math.abs(f.clientHeight-f.contentDocument.body.getBoundingClientRect().height)<=2&&f.clientHeight<150});
  // A host viewport change must not reinstate the old oversized frame.
  await p.setViewportSize({width,height:550});
  await p.waitForFunction(()=>{const f=document.querySelector('iframe');return Math.abs(f.clientHeight-f.contentDocument.body.getBoundingClientRect().height)<=2});
  assert(await f.locator('body').evaluate(e=>e.scrollWidth<=window.innerWidth));
  assert.deepEqual(errors,[]);results.push({width,channel,compactHeight:compact,status:'PASS'});
  if(width===940&&channel==='openai')await p.screenshot({path:path.join(process.env.COMMANDCORE_UI_FIXTURES,'compact-preview.png'),clip:{x:0,y:0,width,height:Math.ceil(compact)}});
  await p.close();
 }
 assert.equal(inlineHeight(112,112,undefined),200,'old host minimum reproduces spare space');assert.equal(inlineHeight(112,112,1),112);
 await browser.close();fs.writeFileSync(path.join(process.env.COMMANDCORE_UI_FIXTURES,'sizing-results.json'),JSON.stringify(results,null,2));console.log(results);
})().catch(e=>{console.error(e);process.exit(1)});
