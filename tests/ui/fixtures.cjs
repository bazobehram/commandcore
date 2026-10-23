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
      response.end(fs.readFileSync(path.join(process.env.COMMANDCORE_UI_FIXTURES, name)));
    });
    server.listen(0, '127.0.0.1', () => {
      server.unref();
      resolve(`http://127.0.0.1:${server.address().port}/task-rendered.html`);
    });
  });
  return listening;
}
module.exports = {fixtureURL};
