// A real loopback origin gives host-state fixtures stable storage semantics.
// Never serve arbitrary local paths or contact an external service.
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
let listening;
async function fixtureURL(name = 'task-rendered.html') {
  if (name !== 'task-rendered.html') throw Error('Unknown fixture');
  if (!listening) listening = new Promise(resolve => {
    const server = http.createServer((request, response) => {
      if (request.url !== '/task-rendered.html') {
        response.writeHead(404); response.end(); return;
      }
      response.writeHead(200, {'Content-Type':'text/html; charset=utf-8', 'Cache-Control':'no-store'});
      // Offline-only fixture host: explicitly answer unsupported MCP Apps init.
      // The real widget requires an actual host response before using a legacy
      // native alias. Never relax that production requirement.
      const shim = `<script>(() => {
        window.addEventListener('message', event => {
          if (window.parent !== window || event.source !== window) return;
          if (event.data?.jsonrpc !== '2.0' || event.data?.method !== 'ui/initialize') return;
          if (typeof window.openai?.callTool !== 'function') return;
          window.postMessage({
            jsonrpc:'2.0',id:event.data.id,
            error:{code:-32601,message:'Offline fixture: native host has no ui/initialize'}
          },'*');
        });
      })();</script>`;
      const html=fs.readFileSync(path.join(process.env.COMMANDCORE_UI_FIXTURES,name),'utf8');
      response.end(html.replace('<head>','<head>'+shim));
    });
    server.listen(0, '127.0.0.1', () => {
      server.unref();
      resolve(`http://127.0.0.1:${server.address().port}/task-rendered.html`);
    });
  });
  return listening;
}
module.exports = {fixtureURL};
