const {fixtureURL}=require('./fixtures.cjs');
const {chromium}=require('playwright'),assert=require('node:assert/strict');
(async()=>{
 const browser=await chromium.launch({headless:true,...(process.env.CHROMIUM_PATH?{executablePath:process.env.CHROMIUM_PATH}:{}),args:['--no-sandbox']});
 const page=await browser.newPage();const errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.addInitScript(()=>{
  const id='12345678-1234-4234-8234-123456789abc';window.openai={widgetState:{},setWidgetState:s=>{window.openai.widgetState=s},toolOutput:{task_id:id,task:{id,total:8,running:0,failed:0,ended:null,last_tool:'shell.exec'},session_available:true,session_ref:'viewer'},callTool:async()=>({structuredContent:{task:{id,total:8,running:0,failed:0,ended:null,last_tool:'shell.exec'},events:[
   {tool:'shell.exec',status:'ok',device:'fixture',duration_ms:1250,detail:{command_visibility:'validated',command_display:'pwd && git status --short'}},
   {tool:'browser.open',status:'ok',device:'fixture',detail:{public_url:'https://example.com/'}},
   {tool:'shell.exec',status:'ok',device:'fixture',detail:{command_visibility:'withheld',command_display:'HIDDEN_PRIVATE_VALUE'}},
   ...Array.from({length:5},()=>({tool:'system.info',status:'ok',device:'fixture'}))
  ]}})};
 });
 await page.goto(await fixtureURL());await page.waitForFunction(()=>document.querySelectorAll('#cc-task-list li').length===8);
 await page.locator('#cc-task-steps summary').click();
 const rows=page.locator('#cc-task-list li');assert.match(await rows.nth(0).innerText(),/1\.3s/);assert.match(await rows.nth(0).innerText(),/pwd && git status --short/);
 assert.match(await rows.nth(1).innerText(),/https:\/\/example.com\//);assert(!/HIDDEN_PRIVATE_VALUE/.test(await page.locator('#cc-task').textContent()));
 assert(!/pwd|example\.com|HIDDEN_PRIVATE_VALUE/.test(JSON.stringify(await page.evaluate(()=>window.openai.widgetState))),'operation detail must not be persisted');
 assert.equal(errors.length,0,errors.join('\n'));await browser.close();console.log('PASS bounded aggregate details and private summary persistence');
})().catch(e=>{console.error(e);process.exit(1)});
