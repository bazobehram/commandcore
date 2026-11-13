"use strict";
const fs=require("fs"),vm=require("vm"),assert=require("assert");
const source=fs.readFileSync(__dirname+"/../apps/web/browser-console.js","utf8");
const nodes=new Map(),calls=[],timers=[],events={},constructed=[];
let focused=false;
function node(id){
 if(!nodes.has(id)){
  const handlers={};
  nodes.set(id,{id,handlers,hidden:id==="viewport",naturalWidth:id==="viewport"?1280:0,naturalHeight:id==="viewport"?713:0,
   disabled:false,textContent:"",value:"",className:"",classList:{toggle(){}},
   getAttribute(){return null},removeAttribute(){},getBoundingClientRect(){return {left:0,top:0,width:1280,height:713}},
   setAttribute(){},addEventListener(n,f){handlers[n]=f},focus(){focused=true},after(){},append(){},
   querySelector(){return {textContent:""}},decode:async()=>{},appendChild(){},
   set innerHTML(v){this._innerHTML=v},get innerHTML(){return this._innerHTML||""}
  });
 }
 return nodes.get(id);
}
const document={hidden:false,getElementById:node,
 querySelectorAll(){return ["refresh","scroll-up","scroll-down","send-text","enter","tab","escape","text","resume"].map(node)},
 querySelector(){return null},
 createElement(){return node("reload-page")},
 addEventListener(n,fn){events["document:"+n]=fn}};
const fetch=async (url,options={})=>{
 calls.push({url,options});
 if(url.includes("/screenshot")){
  return {ok:true,status:200,headers:{get:()=> "https://www.google.com/"},blob:async()=>({type:"image/png"})};
 }
 if(url.includes("/action")){
  return {ok:true,status:200,headers:{get:()=>null},blob:async()=>({type:"image/png"}),json:async()=>({pending:null})};
 }
 if(url.includes("/resume"))return {ok:true,status:200};
 throw Error("unexpected route");
};
class FileReader{
 readAsDataURL(){this.result="data:image/png;base64,"+"A".repeat(100);this.onload();}
}
class EventSource{
 constructor(url){constructed.push(url);this.listeners={};}
 addEventListener(n,f){this.listeners[n]=f}
 close(){}
}
const context={document,location:{pathname:"/browser/console/example-valid-token"},fetch,
 setTimeout(cb,ms){timers.push({cb,ms});return timers.length},clearTimeout(){},
 setInterval(){},clearInterval(){},EventSource,FileReader,
 Date,Math,JSON,AbortController,URL,console};
vm.runInNewContext(source,context,{timeout:800});
async function settle(){for(let i=0;i<80;i++)await Promise.resolve();}
(async()=>{
 await settle();
 assert(calls.some(x=>x.url.includes("/screenshot")),"must retrieve real authenticated frame on startup");
 assert.strictEqual(node("viewport").hidden,false,"frame must be visible after PNG");
 assert.strictEqual(node("scroll-up").disabled,false,"controls activate after real screenshot");
 assert(constructed.length>=1,"SSE should start after initial frame");
 assert.strictEqual(node("viewport").tabIndex,0,"image must accept keyboard focus");
 const click=node("viewport").handlers.click;
 assert(click);
 node("viewport").handlers.pointerdown();
 click({clientX:510,clientY:340});
 await settle();
 assert(focused,"click should focus remote keyboard");
 assert(calls.some(x=>x.url.includes("/action")&&JSON.parse(x.options.body).name==="browser.click"),"click sends authenticated browser.click");
 console.log("PASS private console first-frame load, SSE after screenshot, live click API and keyboard focus");
})().catch(e=>{console.error(e);process.exitCode=1});
