const {chromium}=require('playwright'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
(async()=>{
 const browser=await chromium.launch({headless:true,...(process.env.CHROMIUM_PATH?{executablePath:process.env.CHROMIUM_PATH}:{}),args:['--no-sandbox']});
 for(const view of ['browser','activity']){
  const page=await browser.newPage(),errors=[];page.on('pageerror',e=>errors.push(e.message));
  await page.evaluate(()=>{
   window.calls=[];window.privateHandoff=false;
   const canvas=document.createElement('canvas');canvas.width=320;canvas.height=180;
   const png=canvas.toDataURL('image/png').split(',')[1];
   window.openai={toolOutput:{session_available:true,session_ref:'fixture'},callTool:async(name)=>{
    window.calls.push(name);
    if(name==='browser.frame')return {structuredContent:{session_id:'fixture',sequence:1,state:window.privateHandoff?'awaiting_human':'agent',url:window.privateHandoff?undefined:'https://example.com/',title:'Example',changed:!window.privateHandoff,recent_actions:[]},content:window.privateHandoff?[]:[{type:'image',mimeType:'image/png',data:png}]};
    return {structuredContent:{events:[],devices:[]}};
   }};
  });
  const html=fs.readFileSync(path.join(process.env.COMMANDCORE_UI_FIXTURES,view+'-standalone.html'),'utf8');
  await page.setContent(html,{waitUntil:'domcontentloaded'});
  assert.equal(await page.locator('nav[aria-label="Workspace tabs"]').isVisible(),false);
  assert.equal(await page.locator('#'+view+'-pane').isVisible(),true);
  assert.equal(await page.locator('#'+(view==='browser'?'activity':'browser')+'-pane').isVisible(),false);
  await page.evaluate(v=>document.getElementById((v==='browser'?'activity':'browser')+'-tab').click(),view);
  assert.equal(await page.locator('#'+view+'-pane').isVisible(),true,'view remains independent');
  await page.waitForFunction(v=>window.calls.includes(v==='browser'?'browser.frame':'activity.feed'),view,{timeout:5000});
  if(view==='browser'){
   await page.locator('#browser-screen').waitFor({state:'visible'});
   await page.waitForFunction(()=>document.getElementById('browser-screen').naturalWidth===320);
   await page.evaluate(()=>{window.privateHandoff=true});
   await page.locator('#browser-refresh').click();
   await page.locator('#browser-screen').waitFor({state:'hidden'});
   assert.equal(await page.locator('#browser-screen').getAttribute('src'),null,'private handoff clears the frame');
  }
  assert.equal(errors.length,0,errors.join('\n'));
  await page.close();
 }
 await browser.close();console.log('PASS standalone Browser and Activity resources remain independent');
})().catch(e=>{console.error(e);process.exit(1)});
