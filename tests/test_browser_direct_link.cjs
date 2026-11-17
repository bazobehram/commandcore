"use strict";
const vm=require("vm"),fs=require("fs"),assert=require("assert");
const source=fs.readFileSync(__dirname+"/../apps/web/browser-live.js","utf8");
const called=[],elems=new Map(),assignments=[],callbacks=new Map();
function el(id){
 if(!elems.has(id)){
  const handlers={};
  elems.set(id,{id,textContent:"",value:"",src:"",hidden:id==="frame"||id==="auth",disabled:false,
   children:[],handlers,classList:{toggle(){}},
   addEventListener(k,fn){handlers[k]=fn},
   replaceChildren(){this.children=[]},
   appendChild(child){this.children.push(child)},
  });
 }
 return elems.get(id);
}
let frameResponses=0;
const fetch=async (url,opt)=>{
 called.push({url,options:opt||{}});
 if(url==="/api/browser/sessions")
  return {ok:true,status:200,json:async()=>({sessions:[{client_id:"authorized-client-id",label:"Owner session"}]})};
 if(url.startsWith("/api/browser/frame?")){
  frameResponses++;
  return {ok:true,status:200,json:async()=>({
   changed:true,screenshot_base64:"A".repeat(160),sequence:frameResponses,
   state:"ready",url:"https://www.google.com/search?q=private"
  })};
 }
 if(url==="/api/browser/handoff"){
  return {ok:true,status:200,json:async()=>({
   state:"paused_for_human",handoff_path:"/browser/console/"+"A".repeat(43)
  })};
 }
 throw Error("Unexpected route "+url);
};
const location={href:"https://control.example.invalid/browser/live",assign(path){assignments.push(path)}};
const document={hidden:false,getElementById:el,createElement:()=>({value:"",textContent:""}),addEventListener:(k,fn)=>callbacks.set(k,fn)};
const timers=[];const sandbox={fetch,document,location,URL,setTimeout:fn=>{timers.push(fn);return timers.length},clearTimeout:()=>{}};
vm.runInNewContext(source,sandbox,{timeout:800});
async function settle(){for(let i=0;i<100;i++)await Promise.resolve();}
(async()=>{
 await settle();
 assert(called.some(x=>x.url==="/api/browser/sessions"),"auth session list fetched");
 assert(called.some(x=>x.url.startsWith("/api/browser/frame?")),"real frame requested");
 assert.strictEqual(el("frame").hidden,false,"live image visible");
 assert.strictEqual(el("take").disabled,false);
 assert(!called.some(x=>x.url==="/api/browser/handoff"),"GET does NOT grant takeover");
 assert.strictEqual(assignments.length,0);
 el("take").handlers.click();
 await settle();
 const handoff=called.find(x=>x.url==="/api/browser/handoff");
 assert(handoff,"explicit user button invokes handoff");
 assert.strictEqual(handoff.options.method,"POST");
 assert.strictEqual(JSON.parse(handoff.options.body).client_id,"authorized-client-id");
 assert.strictEqual(assignments[0],"/browser/console/"+"A".repeat(43));
 console.log("PASS: one-click Browser live view, no implicit control, explicit authenticated handoff");
})().catch(err=>{console.error(err);process.exitCode=1});
