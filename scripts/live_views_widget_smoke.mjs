import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import vm from "node:vm";
const html=readFileSync("apps/web/commandcore-widget.html","utf8");
const script=html.match(/<script>([\s\S]*?)<\/script>/)?.[1];
assert.ok(script,"combined widget script is present");
const tick=()=>new Promise(resolve=>setImmediate(resolve));
const png={type:"image",mimeType:"image/png",data:"iVBORw0KGgo="};
class Node {
  constructor(id){this.id=id;this.hidden=id==="browser-tab"||id==="browser-view";
    this.disabled=false;this.textContent="";this.src="";this.events={};this.children=[];this.attrs={};}
  addEventListener(event,fn){this.events[event]=fn;}
  setAttribute(name,value){this.attrs[name]=value;}
  removeAttribute(name){delete this.attrs[name];if(name==="src")this.src="";}
  replaceChildren(...children){this.children=[...children];}
  append(...children){this.children.push(...children);}
  click(){return this.events.click?.();}
}
const nodes=new Map();
const get=id=>{if(!nodes.has(id))nodes.set(id,new Node(id));return nodes.get(id);};
let handler;
const calls=[];
let activeHuman=false;
let visibleActivity=[{tool:"fs.read",status:"ok",device:"test-node-a",duration_ms:240,started_at:"2026-10-09T05:00:00+00:00"}];
const parent={postMessage(msg){
  calls.push(msg);
  if(msg.id===undefined)return;
  let result={};
  if(msg.method==="ui/initialize")result={hostCapabilities:{serverTools:{},openLinks:{}}};
  if(msg.method==="tools/call"){
    const name=msg.params.name;
    if(name==="commandcore.watch")result={structuredContent:{state:"dashboard_ready",browser_available:true}};
    if(name==="activity.feed")result={structuredContent:{events:visibleActivity}};
    if(name==="browser.observe"){
      result=activeHuman
        ?{isError:true,structuredContent:{message:"browser paused for human"}}
        :{structuredContent:{title:"Example Domain",url:"https://example.com"},content:[png]};
    }
    if(name==="browser.handoff"){
      activeHuman=true;
      result={structuredContent:{handoff_url:"https://example.com/browser/console/demo"}};
    }
  }
  queueMicrotask(()=>handler({source:parent,data:{jsonrpc:"2.0",id:msg.id,result}}));
}};
const window={parent,addEventListener(name,fn){if(name==="message")handler=fn;}};
const document={hidden:false,getElementById:get,createElement:tag=>new Node(tag)};
const intervals=[];
vm.runInNewContext(script,{window,document,Promise,Map,Date,Error,Number,
  setTimeout:()=>1,clearTimeout:()=>{},
  setInterval:fn=>{intervals.push(fn);return intervals.length;},
},{timeout:3000});
await tick();await tick();await tick();
assert.equal(calls[0].method,"ui/initialize");
assert.ok(calls.some(c=>c.method==="ui/notifications/initialized"));
assert.ok(calls.some(c=>c.method==="tools/call"&&c.params.name==="commandcore.watch"));
assert.equal(get("browser-tab").hidden,false,"browser tab available when enabled");
assert.equal(get("status").textContent,"Live");
assert.equal(get("activity-list").children[0].children[1].children[0].textContent,"fs.read");
await get("browser-tab").click();await tick();
assert.equal(get("activity-view").hidden,true);
assert.equal(get("browser-view").hidden,false);
assert.equal(get("browser-screen").src,"data:image/png;base64,iVBORw0KGgo=");
assert.equal(get("browser-host").textContent,"Example Domain");
await get("handoff").click();await tick();
assert.ok(calls.some(c=>c.method==="tools/call"&&c.params.name==="browser.handoff"));
assert.ok(calls.some(c=>c.method==="ui/open-link"));
assert.equal(get("browser-screen").hidden,true,"handoff hides screenshot");
activeHuman=false;
await get("browser-refresh").click();await tick();
assert.equal(get("browser-screen").hidden,false,"human resume permits manual refresh");
await get("activity-tab").click();await tick();
assert.equal(get("activity-view").hidden,false);
await get("activity-pause").click();
assert.equal(get("activity-pause").textContent,"Resume");
document.hidden=true;
const before=calls.length;
for(const poll of intervals)poll();
await tick();
assert.equal(calls.length,before,"hidden widget never polls");
console.log("Unified Live Views smoke: PASS (MCP Apps, Activity/Browser tabs, PNG, handoff, mobile-style visibility)");
