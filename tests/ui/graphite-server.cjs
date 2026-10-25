
const http=require('node:http');
const fs=require('node:fs');
const path=require('node:path');
const root=path.resolve(__dirname,'../../apps/web');
const exposed={'/':'index.html','/commandcore.webmanifest':'commandcore.webmanifest','/panel.css':'panel.css','/panel.js':'panel.js','/commandcore-icon.png':'commandcore-icon.png','/commandcore-wordmark.png':'commandcore-wordmark.png','/commandcore-logo.webp':'commandcore-logo.webp'};
const types={'.html':'text/html','.webmanifest':'application/manifest+json','.js':'text/javascript','.css':'text/css','.png':'image/png','.webp':'image/webp'};
async function startServer(){
 const server=http.createServer((req,res)=>{
  const filename=exposed[req.url.split('?')[0]];
  if(!filename){res.writeHead(404);res.end();return;}
  const file=path.join(root,filename);
  fs.readFile(file,(err,data)=>{
   if(err){res.writeHead(404);res.end();return;}
   res.writeHead(200,{'Content-Type':types[path.extname(filename)]||'application/octet-stream','Cache-Control':'no-store'});res.end(data);
  });
 });
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 return {url:'http://127.0.0.1:'+server.address().port+'/',close:()=>new Promise(resolve=>server.close(resolve))};
}
module.exports={startServer};
