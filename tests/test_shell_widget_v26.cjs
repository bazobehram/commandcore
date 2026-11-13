const fs=require("fs"),vm=require("vm"),assert=require("assert");
const html=fs.readFileSync(__dirname+"/../apps/web/shell-compact-v26.html","utf8");
const source=html.match(/<script>([\s\S]*?)<\/script>/)?.[1]||"";
const ID="bda4d9b2-4c8e-4483-ab71-cb18d9b3d74a";
function env(){
 const nodes=new Map(),listeners={},sent=[],timers=[];
 function get(id){
  if(!nodes.has(id))nodes.set(id,{textContent:"",hidden:false,open:false});
  return nodes.get(id);
 }
 const document={getElementById:get,documentElement:{scrollHeight:240}};
 const win={parent:{postMessage:(message,origin)=>sent.push({message,origin})},addEventListener:(type,fn)=>listeners[type]=fn,openai:{}};
 vm.runInNewContext(source,{window:win,document,console,
    setTimeout:cb=>{timers.push(cb);return timers.length},
    clearTimeout:()=>{},
    Math,Number});
 const receive=data=>listeners["message"]({source:win.parent,data:{jsonrpc:"2.0",method:"ui/notifications/tool-result",params:data}});
 return {get,sent,timers,receive,listeners,win};
}
function payload(card,step={tool:"shell.exec",operation_id:ID,device:"test-node",duration_ms:18,status:"ok",exit_code:0}){
 return {structuredContent:{activity_step:step,exit_code:0,...card?{shell_card:card}: {}}};
}
const base={operation_id:ID,device:"test-node",exit_code:0,duration_ms:18,status:"completed"};
{
 const t=env();
 assert.strictEqual(t.sent[0].message.method,"ui/initialize");
 t.receive(payload(null));
 
 assert(t.get("preview-note").textContent.includes("Loading"));
 assert(!t.get("preview-note").textContent.includes("credential"));
 assert(t.get("terminal").hidden===false);
 const full=payload({...base,command:"ls -la /home/homeserver/commandcore-private",stdout:"files ok",stderr:"",command_visibility:"visible"});
 t.receive(full);
 assert.strictEqual(t.get("prompt").textContent,"$ ls -la /home/homeserver/commandcore-private");
 assert.strictEqual(t.get("out").textContent,"files ok");
 assert(t.get("preview-note").hidden);
 t.receive(payload(null));
 assert.strictEqual(t.get("out").textContent,"files ok");
 console.log("PASS: partial metadata -> full command without false credential warning");
}
{
 const t=env();
 t.receive(payload({...base,command:"export API_KEY=[REDACTED]",stdout:"SECRET_TEXT",command_visibility:"redacted"}));
 assert(t.get("prompt").textContent.includes("[REDACTED]"));
 assert.strictEqual(t.get("output-block").hidden,true);
 assert(t.get("preview-note").textContent.includes("masked"));
 console.log("PASS: masked command, no stdout leak");
}
{
 const t=env();
 t.receive(payload({...base,command:"",stdout:"SECRET_TEXT",command_visibility:"withheld"}));
 assert.strictEqual(t.get("terminal").hidden,true);
 assert(t.get("preview-note").textContent.includes("withheld"));
 console.log("PASS: explicit server withholding state");
}
{
 const t=env();
 t.receive(payload(null));
 for(const f of t.timers)f();
 assert(t.get("preview-note").textContent.includes("unavailable"));
 assert(!t.get("preview-note").textContent.includes("credential"));
 console.log("PASS: missing full result is unavailable, not fake credential detection");
}

{
 const t=env();
 t.receive(payload({...base,command:"python3 - <<'PY'\nprint('hello')\n... [preview shortened]",
   stdout:"do not disclose",command_visibility:"shortened",preview_reason:"command_preview_limit"}));
 assert(t.get("prompt").textContent.includes("preview shortened"));
 assert(t.get("preview-note").textContent.includes("Long command"));
 assert.strictEqual(t.get("output-block").hidden,true);
 console.log("PASS: long scripts display safe excerpt without misleading credential claim");
}
{
 const t=env();
 t.receive(payload({...base,command:"",stdout:"hidden",
   command_visibility:"withheld",preview_reason:"protected_file_reference"}));
 assert(t.get("preview-note").textContent.includes("protected file"));
 assert(!t.get("preview-note").textContent.includes("server security policy"));
 console.log("PASS: protected file has specific reason");
}
