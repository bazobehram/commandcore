"use strict";
(()=>{
 const $=id=>document.getElementById(id);
 const ui={session:$("session"),status:$("status"),frame:$("frame"),empty:$("empty"),take:$("take"),refresh:$("refresh"),auth:$("auth"),updated:$("updated"),address:$("address")};
 let sessions=[],client="",sequence=-1,pending=false,stopped=false,epoch=0,lastFrame=null,poll=null;
 const setStatus=(msg,error=false)=>{ui.status.textContent=msg;ui.status.classList.toggle("error",error)};
 const linkSafe=path=>/^\/browser\/console\/[A-Za-z0-9_-]{43}$/.test(path);
 const frameAddress=url=>{try{const u=new URL(url);return u.protocol==="https:"?u.origin:"Remote page"}catch{return "Remote page"}};
 async function request(path,opts={}){
  const response=await fetch(path,{credentials:"same-origin",cache:"no-store",...opts});
  if(response.status===401||response.status===403){
   stopped=true;ui.auth.hidden=false;
   setStatus("Sign in to your CommandCore account to see your authorized Browser sessions.",true);
   throw new Error("unauthorized");
  }
  if(!response.ok)throw new Error("Browser service returned "+response.status);
  return response.json();
 }
 function schedule(delay=1250){
  if(poll)clearTimeout(poll);
  if(!stopped)poll=setTimeout(refreshFrame,delay);
 }
 function fillSessions(items){
  sessions=items;ui.session.replaceChildren();
  for(const entry of sessions){
   const option=document.createElement("option");
   option.value=entry.client_id;
   option.textContent=entry.label||entry.client_name||entry.client_id.slice(0,12);
   ui.session.appendChild(option);
  }
  const preferred=new URL(location.href).searchParams.get("client_id");
  const chosen=sessions.find(x=>x.client_id===client)||sessions.find(x=>x.client_id===preferred)||sessions[0];
  client=chosen?chosen.client_id:"";
  if(client)ui.session.value=client;
  ui.session.disabled=!client;
  ui.take.disabled=!client;
  ui.refresh.disabled=!client;
  if(!client){ui.frame.hidden=true;ui.empty.hidden=false;ui.empty.textContent="No active Browser sessions. Open a page in CommandCore Browser through ChatGPT.";setStatus("No active browser session.");}
 }
 async function loadSessions(){
  try{
   const data=await request("/api/browser/sessions");
   if(stopped)return;
   fillSessions(Array.isArray(data.sessions)?data.sessions:[]);
   if(client){sequence=-1;await refreshFrame();}
  }catch(error){if(error.message!=="unauthorized")setStatus("Unable to load Browser sessions. Refresh to retry.",true);}
 }
 async function refreshFrame(){
  if(stopped||!client||pending||document.hidden){schedule(1500);return}
  pending=true;
  const snapshot=epoch,owner=client;
  try{
   const data=await request("/api/browser/frame?client_id="+encodeURIComponent(owner)+"&after_sequence="+sequence);
   if(stopped||snapshot!==epoch||owner!==client)return;
   if(data.state==="awaiting_human"){
    ui.frame.hidden=true;ui.empty.hidden=false;
    ui.empty.textContent="Private control is active. Continue in your private Browser tab or request private control again.";
    setStatus("AI paused for private human control.");
    ui.take.disabled=false;schedule(2500);return;
   }
   if(data.changed&&typeof data.screenshot_base64==="string"&&/^[A-Za-z0-9+/=]+$/.test(data.screenshot_base64)&&data.screenshot_base64.length>50){
    ui.frame.src="data:image/png;base64,"+data.screenshot_base64;
    ui.frame.hidden=false;ui.empty.hidden=true;sequence=Number.isInteger(data.sequence)?data.sequence:sequence;
    ui.address.textContent=frameAddress(data.url);
    ui.updated.textContent="Live · frame "+sequence;
   }
   if(ui.frame.hidden){ui.empty.hidden=false;ui.empty.textContent="Connected; waiting for the next live frame…"}
   setStatus("Browser connected · Live view. Take private control to click or type.");
  }catch(error){
   if(error.message!=="unauthorized")setStatus("Live Browser frame unavailable. You can refresh or reopen Browser in ChatGPT.",true);
  }finally{
   pending=false;
   if(!stopped)schedule(1500);
  }
 }
 ui.session.addEventListener("change",()=>{client=ui.session.value;epoch++;sequence=-1;ui.frame.hidden=true;refreshFrame()});
 ui.refresh.addEventListener("click",()=>{sequence=-1;epoch++;refreshFrame()});
 ui.take.addEventListener("click",async()=>{
  if(!client||ui.take.disabled)return;
  ui.take.disabled=true;
  setStatus("Requesting authenticated private control…");
  try{
   const result=await request("/api/browser/handoff",{
    method:"POST",headers:{"Content-Type":"application/json"},
    body:JSON.stringify({client_id:client})
   });
   if(!linkSafe(result.handoff_path))throw new Error("invalid_control_path");
   location.assign(result.handoff_path);
  }catch(error){
   if(error.message!=="unauthorized")setStatus("Private control request failed. The AI session was not confirmed paused.",true);
   ui.take.disabled=false;
  }
 });
 document.addEventListener("visibilitychange",()=>{if(!document.hidden&&client)refreshFrame()});
 loadSessions();
})();
