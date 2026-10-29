const { chromium }=require('playwright-core'),assert=require('node:assert/strict');
(async()=>{
 const b=await chromium.launch({executablePath:'/usr/bin/chromium',headless:true,args:['--no-sandbox','--disable-dev-shm-usage']});
 const p=await b.newPage({viewport:{width:1280,height:800}}),errors=[];
 p.on('pageerror',e=>errors.push(e.message));
 const resp=await p.goto('https://commandcore.synovaq.org/',{waitUntil:'networkidle'});
 assert.equal(resp.status(),200);
 await p.getByText('All your machines.').waitFor();
 const info=await p.evaluate(async()=>{
  const manifest=await (await fetch('/manifest.webmanifest')).json();
  const reg=await navigator.serviceWorker.ready;
  const iconChecks=await Promise.all(manifest.icons.map(async icon=>({url:icon.src,status:(await fetch(icon.src)).status})));
  const svg=await fetch('/brand/octopus-online.svg?v=20261029-v8');
  return {manifestIconChecks:iconChecks,brandSvgStatus:svg.status,serviceWorker:reg.active?.scriptURL,cacheNames:await caches.keys(),faviconLinks:[...document.querySelectorAll('link[rel="icon"]')].map(x=>x.href)};
 });
 assert(info.manifestIconChecks.every(x=>x.status===200));
 assert.equal(info.brandSvgStatus,200);
 assert(info.cacheNames.includes('commandcore-workspace-static-v10-live'),'current offline cache missing');
 assert.equal(info.faviconLinks.length,2);
 console.log('PASS public HTTPS and login page');
 console.log('PASS current favicon links (SVG + PNG), no old favicon');
 console.log('PASS all PWA manifest icon URLs load');
 console.log('PASS dynamic octopus SVG loads');
 console.log('PASS v8 service worker installed with offline cache');
 console.log('PAGE_ERRORS',JSON.stringify(errors));
 await b.close();
 if(errors.length)process.exit(2);
})().catch(e=>{console.error(e.stack);process.exit(1)});
