const {chromium}=require('playwright'),assert=require('node:assert/strict'),path=require('path');
(async()=>{
 const browser=await chromium.launch({headless:true,...(process.env.CHROMIUM_PATH?{executablePath:process.env.CHROMIUM_PATH}:{}),args:['--no-sandbox']});const p=await browser.newPage();
 await p.addInitScript(()=>{const id='12345678-1234-4234-8234-123456789abc';window.expired=true;window.foreign=false;window.renewals=0;window.feeds=0;window.ref='initial';const task={id,total:4,ended:null,running:0,failed:0,last_tool:'system.metrics'};window.openai={toolOutput:{task_id:id,task,session_available:true,session_ref:'initial'},requestDisplayMode:async()=>{},notifyIntrinsicHeight:()=>{},callTool:async(n,a)=>{
  if(n==='activity.feed'){window.feeds++;if(window.foreign)return {isError:true,structuredContent:{error:'invalid_task_view'}};if(window.expired||a.session_ref!==window.ref)return {isError:true,content:[{type:'text',text:JSON.stringify({error:'invalid_session_view'})}]};return {structuredContent:{task,events:[]}};}
  if(n==='commandcore.viewer'){window.renewals++;window.expired=false;window.ref='renewed-'+window.renewals;return {structuredContent:{session_available:true,session_ref:window.ref}};}
  if(n==='devices.list')return {structuredContent:{devices:[]}};throw Error(n);
 }}});
 await p.goto('file://'+path.join(process.env.COMMANDCORE_UI_FIXTURES,'task-rendered.html'));await p.waitForFunction(()=>window.renewals===1&&document.getElementById('cc-task-summary').textContent.includes('4 calls'));
 await p.evaluate(()=>window.expired=true);await p.waitForFunction(()=>window.renewals===2);await p.waitForTimeout(100);assert(!/expired|unavailable/.test(await p.locator('#cc-task-summary').innerText()),'second expiry also recovers');
 await p.evaluate(()=>window.foreign=true);await p.waitForFunction(()=>document.getElementById('cc-task-summary').textContent.includes('Saved task'));
 assert(await p.locator('#cc-task-retry').isHidden());assert.equal(await p.evaluate(()=>window.renewals),2,'foreign/legacy task must not renew into another task');
 const count=await p.evaluate(()=>window.feeds);await p.waitForTimeout(1800);assert.equal(await p.evaluate(()=>window.feeds),count,'known stale task stops requests');
 await browser.close();console.log('PASS repeated expired viewer renewal including text-only error; foreign/legacy saved card stops without rebinding or action replay');
})().catch(e=>{console.error(e);process.exit(1)});
