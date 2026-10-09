import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import vm from "node:vm";

const html=readFileSync("apps/web/browser-widget.html","utf8");
const script=html.match(/<script>([\s\S]*?)<\/script>/)?.[1];
assert.ok(script,"widget script must exist");
const tick=()=>new Promise(resolve=>setImmediate(resolve));
const png={type:"image",mimeType:"image/png",data:"iVBORw0KGgo="};
const observed={structuredContent:{title:"Example Domain",url:"https://example.com/"},
                content:[{type:"text",text:"{}"},png]};
function harness({native=false}={}){
  class Element {
    constructor(id) {this.id=id;this.hidden=false;this.disabled=false;this.textContent="";
      this.src="";this.attrs={};this.events={};}
    addEventListener(kind,fn){this.events[kind]=fn;}
    setAttribute(k,v){this.attrs[k]=v;}
    removeAttribute(k){delete this.attrs[k];if(k==="src")this.src="";}
    click(){return this.events.click?.();}
  }
  const elements=new Map();
  const get=id=>{if(!elements.has(id))elements.set(id,new Element(id));return elements.get(id);};
  const calls=[];
  let handler;
  let interval;
  let handoff=false;
  let response=observed;
  const parent={postMessage(req) {
    calls.push(req);
    if(req.id===undefined)return;
    let result;
    if(req.method==="tools/call"){
      if(req.params.name==="browser.handoff"){
        handoff=true;
        result={structuredContent:{handoff_url:"https://example.com/browser/console/fake"}};
      }else if(handoff) result={isError:true,content:[{type:"text",text:'{"message":"browser paused for human"}'}]};
      else result=response;
    }else if(req.method==="ui/initialize")result={hostCapabilities:{serverTools:{},openLinks:{}}};
    else if(req.method==="ui/open-link")result={};
    queueMicrotask(()=>handler({source:parent,data:{jsonrpc:"2.0",id:req.id,result}}));
  }};
  const window={parent,addEventListener(kind,fn){if(kind==="message")handler=fn;}};
  if(native)window.openai={
    callTool:async (name)=>{
      calls.push({method:"native-call",name});
      if(name==="browser.handoff"){handoff=true;return {structuredContent:{handoff_url:"https://example.com/browser/console/fake"}};}
      return handoff?{isError:true,content:[{type:"text",text:'{"message":"browser paused for human"}'}]}:response;
    },
    openExternal:({href})=>{calls.push({method:"native-open",href});}
  };
  const document={hidden:false,getElementById:get};
  vm.runInNewContext(script,{window,document,Promise,Map,Error,Number,
    setTimeout:()=>1,clearTimeout:()=>{},
    setInterval:fn=>{interval=fn;return 2;},clearInterval:()=>{}},{timeout:2500});
  return {calls,get,document,click:id=>get(id).click(),setHandoff:v=>{handoff=v;},
    interval:()=>interval?.(),setResponse:v=>{response=v;}};
}

const app=harness();
await tick();await tick();
assert.equal(app.calls[0].method,"ui/initialize");
assert.ok(app.calls.some(x=>x.method==="ui/notifications/initialized"));
assert.ok(app.calls.some(x=>x.method==="tools/call"&&x.params.name==="browser.observe"));
assert.equal(app.get("screen").src,"data:image/png;base64,iVBORw0KGgo=");
assert.equal(app.get("screen").hidden,false);
assert.equal(app.get("host").textContent,"Example Domain");
await app.click("auto");await tick();
assert.equal(app.get("auto").attrs["aria-pressed"],"true");
app.document.hidden=true;
const before=app.calls.length;
app.interval();
await tick();
assert.equal(app.calls.length,before,"hidden iframe must not poll");
app.document.hidden=false;
await app.click("take");await tick();
assert.ok(app.calls.some(x=>x.method==="tools/call"&&x.params.name==="browser.handoff"));
assert.ok(app.calls.some(x=>x.method==="ui/open-link"));
assert.equal(app.get("screen").hidden,true,"handoff must hide model screenshot");
app.setHandoff(false);
await app.click("refresh");await tick();
assert.equal(app.get("screen").hidden,false,"refresh must recover after explicit human resume");
const native=harness({native:true});
await tick();await tick();
assert.ok(native.calls.some(x=>x.method==="native-call"&&x.name==="browser.observe"));
assert.ok(!native.calls.some(x=>x.method==="ui/initialize"));
console.log("Browser widget smoke: PASS (MCP Apps handshake, PNG, polling, secure handoff, manual recovery, native bridge)");
