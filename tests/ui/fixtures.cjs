// A real loopback origin gives host-state fixtures stable storage semantics.
// Never serve arbitrary local paths or contact an external service.
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
// In top-level fixture pages, emulate the MCP host around existing data stubs.
// Dedicated bridge tests disable this adapter and implement their own host.
const HOST_ADAPTER=`<script>(()=>{window.addEventListener('message',async e=>{
 if(window.__fixtureOwnHost||window.parent!==window||e.source!==window||e.data?.jsonrpc!=='2.0'||typeof window.openai?.callTool!=='function')return;
 const m=e.data;if(!m.method||m.id===undefined)return;
 if(m.method==='ui/initialize'){window.postMessage({jsonrpc:'2.0',id:m.id,result:{protocolVersion:'2026-01-26',hostCapabilities:{}}},'*');return;}
 if(m.method==='tools/call'){
  try{const result=await window.openai.callTool(m.params.name,m.params.arguments);window.postMessage({jsonrpc:'2.0',id:m.id,result},'*');}
  catch(error){window.postMessage({jsonrpc:'2.0',id:m.id,error:{code:-32000,message:error.message}},'*');}
 }
});})();</script>`;
let listening;
async function fixtureURL(name = 'task-rendered.html') {
  if (name !== 'task-rendered.html') throw Error('Unknown fixture');
  if (!listening) listening = new Promise(resolve => {
    const server = http.createServer((request, response) => {
      if (request.url !== '/task-rendered.html') {
        response.writeHead(404); response.end(); return;
      }
      response.writeHead(200, {'Content-Type':'text/html; charset=utf-8', 'Cache-Control':'no-store'});
      response.end(fs.readFileSync(path.join(process.env.COMMANDCORE_UI_FIXTURES, name),'utf8').replace('<head>','<head>'+HOST_ADAPTER));
    });
    server.listen(0, '127.0.0.1', () => {
      server.unref();
      resolve(`http://127.0.0.1:${server.address().port}/task-rendered.html`);
    });
  });
  return listening;
}
module.exports = {fixtureURL};
