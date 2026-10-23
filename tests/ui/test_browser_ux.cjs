const {fixtureURL}=require('./fixtures.cjs');
const {chromium}=require('playwright'),assert=require('node:assert/strict'),path=require('path');
(async()=>{
 const browser=await chromium.launch({headless:true,...(process.env.CHROMIUM_PATH?{executablePath:process.env.CHROMIUM_PATH}:{}),args:['--no-sandbox']});
 for(const width of [320,390,940]){
 const p=await browser.newPage({viewport:{width,height:850}}),errors=[];p.on('pageerror',e=>errors.push(e.message));
 await p.addInitScript(()=>{
  const id='12345678-1234-4234-8234-123456789abc',canvas=document.createElement('canvas');canvas.width=1280;canvas.height=720;canvas.getContext('2d').fillRect(0,0,1280,720);const png=canvas.toDataURL().split(',')[1];
  window.human=false;window.empty=false;window.frameCalls=0;
  const task={id,total:1,ended:null,running:0,failed:0,last_tool:'browser.open',device:'Control plane'};
  window.openai={toolOutput:{task_id:id,task,session_available:true,session_ref:'viewer-A'},requestDisplayMode:async()=>{},callTool:async(n,a)=>{
   if(n==='activity.feed')return {structuredContent:{task,events:[]}};
   if(n==='devices.list')return {structuredContent:{devices:[]}};
   if(n==='browser.frame'){
    window.frameCalls++;
    if(window.empty)return {isError:true,content:[{type:'text',text:JSON.stringify({message:'No browser session belongs to this conversation'})}]};
    const changed=a.after_sequence!==1;
    return {structuredContent:{session_id:'fixture',sequence:1,state:window.human?'awaiting_human':'agent',url:window.human?undefined:'https://example.com/',title:'Example Domain',cursor:{x:200,y:150},action:'Observing',changed:!window.human&&changed,recent_actions:[]},content:!window.human&&changed?[{type:'image',mimeType:'image/png',data:png}]:[]};
   }
   throw Error(n);
  }};
 });
 await p.goto(await fixtureURL());
 await p.locator('#cc-task-expand').press('Enter');await p.locator('#browser-screen').waitFor({state:'visible'});await p.waitForFunction(()=>document.getElementById('browser-screen').naturalWidth===1280);
 assert(await p.evaluate(()=>document.getElementById('browser-refresh').parentElement.compareDocumentPosition(document.getElementById('browser-stage'))&Node.DOCUMENT_POSITION_FOLLOWING));
 assert.match(await p.locator('#browser-help').innerText(),/Ask ChatGPT to search or browse/);
 assert.equal(await p.locator('#browser-take').innerText(),'Use privately');
 assert.match(await p.locator('#browser-freshness').innerText(),/Live preview · updated/);
 await p.locator('#browser-zoom').press('Enter');assert.equal(await p.locator('#browser-zoom').getAttribute('aria-pressed'),'true');
 assert(await p.locator('#browser-stage').evaluate(e=>e.scrollWidth>e.clientWidth));
 assert(await p.evaluate(()=>{const a=document.getElementById('browser-stage').getBoundingClientRect(),b=document.getElementById('browser-screen').getBoundingClientRect();return b.left>=a.left&&b.top>=a.top}),'zoom starts at reachable top-left edge');
 await p.locator('#browser-stage').evaluate(e=>{e.scrollLeft=60;e.scrollTop=20});await p.evaluate(()=>window.dispatchEvent(new Event('resize')));
 const alignment=await p.evaluate(()=>{const im=document.getElementById('browser-screen'),b=im.getBoundingClientRect(),q=document.getElementById('browser-pointer').getBoundingClientRect(),scale=b.width/im.naturalWidth;return Math.abs(q.left+q.width/2-(b.left+200*scale))<3&&Math.abs(q.top+q.height/2-(b.top+150*scale))<3});
 assert(alignment,'pointer remains aligned while zoomed and panned');
 assert(await p.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth),'no page overflow');
 await p.locator('#browser-zoom').press('Enter');assert.equal(await p.locator('#browser-zoom').innerText(),'Zoom in');
 await p.locator('#browser-auto').press('Enter');assert.match(await p.locator('#browser-freshness').innerText(),/Preview paused/);
 const calls=await p.evaluate(()=>window.frameCalls);await p.waitForTimeout(1400);assert.equal(await p.evaluate(()=>window.frameCalls),calls,'pause stops automatic frame requests');
 await p.locator('#browser-refresh').press('Enter');await p.waitForFunction(n=>window.frameCalls>n,calls);assert(await p.evaluate(n=>window.frameCalls>n,calls),'manual refresh works while paused');
 await p.evaluate(()=>{window.human=true});await p.locator('#browser-refresh').press('Enter');await p.locator('#browser-screen').waitFor({state:'hidden'});
 assert(await p.locator('#browser-zoom').isDisabled());assert.equal(await p.locator('#browser-screen').getAttribute('src'),null);assert.match(await p.locator('#browser-freshness').innerText(),/Private control · preview hidden/);
 await p.evaluate(()=>{window.human=false;window.empty=true});await p.locator('#browser-refresh').press('Enter');await p.waitForFunction(()=>document.getElementById('browser-host').textContent==='No active browser session');
 assert(await p.locator('#browser-zoom').isDisabled());assert.equal(await p.locator('#browser-screen').getAttribute('src'),null);
 await p.waitForTimeout(4300);assert.equal(await p.locator('#state').innerText(),'○ No session','Activity polling cannot label an absent Browser live');
 assert.equal(errors.length,0,errors.join('\n'));await p.close();
 }
 await browser.close();console.log('PASS Browser UX: toolbar placement, helper, freshness, zoom/pan pointer, no page overflow, pause/manual refresh, private shield and absent-session cleanup at 320/390/940');
})().catch(e=>{console.error(e);process.exit(1)});
