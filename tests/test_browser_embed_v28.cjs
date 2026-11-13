"use strict";
const fs=require("fs"),vm=require("vm"),assert=require("assert");
const html=fs.readFileSync(__dirname+"/../apps/web/browser-live-v28.html","utf8");
const source=html.match(/<script>([\s\S]*?)<\/script>/)?.[1]||"";
const nodes=new Map(),sent=[],timers=new Map(),called=[],listeners={};
let nextTimer=0;
function node(id){
 if(!nodes.has(id)){
  const handlers={};
  nodes.set(id,{
   id,textContent:"",hidden:id==="frame"||id==="control-panel",disabled:false,
   value:"",naturalWidth:1280,naturalHeight:713,src:"",style:{},
   children:[],handlers,attributes:{},
   classList:{toggle(){}},appendChild(v){this.children.push(v)},
   replaceChildren(){this.children=[]},
   setAttribute(n,v){this.attributes[n]=v},
   removeAttribute(n){delete this.attributes[n]},
   addEventListener(n,fn){handlers[n]=fn},
   getBoundingClientRect(){return {left:0,top:0,width:1280,height:713}}
  });
 }
 return nodes.get(id);
}
const document={
 hidden:false,getElementById:node,addEventListener(k,fn){listeners["document:"+k]=fn},
 createElement:()=>({textContent:""}),
};
const window={
 parent:{postMessage(m){sent.push(m)}},
 openai:{
  async callTool(name,args){
   called.push({name,args});
   if(name==="commandcore.viewer")return {structuredContent:{session_available:true,session_ref:"verified-conversation-ref-1234"}};
   if(name==="browser.frame")return {structuredContent:{session_id:"session-1",state:"running",url:"https://www.google.com/",sequence:4,busy:false},content:"MCP frame metadata",content_items:[{type:"text",text:"frame"},{type:"image",mimeType:"image/png",data:"A".repeat(200)}]};
   if(name==="browser.click"||name==="browser.scroll"||name==="browser.keypress"||name==="browser.type")return {structuredContent:{status:"ok"}};
   throw Error("unexpected tool "+name);
  }
 },
 addEventListener(k,fn){listeners[k]=fn}
};
const sandbox={window,document,URL,setTimeout:(cb,ms)=>{const id=++nextTimer;timers.set(id,{cb,ms});return id},clearTimeout:id=>timers.delete(id),console};
vm.runInNewContext(source,sandbox,{timeout:800});
const init=sent.find(m=>m.method==="ui/initialize");
assert(init,"must initialize even when native callTool exists");
listeners.message({source:window.parent,data:{jsonrpc:"2.0",id:init.id,result:{protocolVersion:"2026-01-26"}}});

async function flush(){for(let i=0;i<45;i++)await Promise.resolve();}
async function tick(){
 await flush();
 const tasks=[...timers.entries()].filter(([,value])=>value.ms<5000);
 for(const [id,value] of tasks){timers.delete(id);value.cb();}
 await flush();
}
(async()=>{
 await flush();
 assert(sent.some(m=>m.method==="ui/notifications/initialized"),"host-ready notification must be sent");
 await tick();
 assert(called.some(x=>x.name==="browser.frame"),"live browser frame requested");
 assert.strictEqual(node("frame").hidden,false,"live screenshot visible");
 assert.strictEqual(node("inline").disabled,false);
 node("inline").handlers.click();
 assert.strictEqual(node("control-panel").hidden,false,"in-chat controls visible");
 node("frame").handlers.click({clientX:640,clientY:356});
 await flush();
 const click=called.find(x=>x.name==="browser.click");
 assert(click,"click must reach actual browser.click MCP tool");
 assert(Math.abs(click.args.x-640)<3&&Math.abs(click.args.y-356)<3,"actual page coordinates");
 node("down").handlers.click();
 await flush();
 assert(called.some(x=>x.name==="browser.scroll"),"scroll must reach actual browser.scroll tool");
 node("typed").value="public search";
 node("send").handlers.click();
 await flush();
 assert(called.some(x=>x.name==="browser.type"&&x.args.text==="public search"),"normal text input forwarded");
 assert.strictEqual(node("typed").value,"","text input cleared after sending");
 console.log("PASS native MCP Apps initialization + loaded screenshot + click/scroll/text controls");
 const handshake=sent.filter(x=>x.method==="ui/initialize").length;
 assert.strictEqual(handshake,1,"no repeated handshake");
})().catch(e=>{console.error(e);process.exitCode=1});
