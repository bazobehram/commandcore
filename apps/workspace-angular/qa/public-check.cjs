const {chromium}=require('playwright-core');
(async()=>{
const b=await chromium.launch({executablePath:'/usr/bin/chromium',headless:true,args:['--no-sandbox','--disable-dev-shm-usage']});
const p=await b.newPage({viewport:{width:1280,height:800}});
const errors=[];p.on('pageerror',e=>errors.push(e.message));p.on('console',m=>{if(m.type()==='error')errors.push(m.text());});
const response=await p.goto('https://commandcore.synovaq.org/',{waitUntil:'networkidle'});
await p.getByText('All your machines.').waitFor();
console.log('HTTPS_STATUS:',response.status());
console.log('LOGIN_UI:',await p.getByRole('link',{name:/Sign in to CommandCore/}).count());
console.log('PWA_MANIFEST:',await p.locator('link[rel="manifest"]').getAttribute('href'));
console.log('SERVICE_WORKER:',await p.evaluate(async()=>{await new Promise(r=>setTimeout(r,1500));const x=await navigator.serviceWorker.getRegistration('/');return x?.active?.scriptURL||'not active';}));
console.log('CSP_JS_ERRORS:',JSON.stringify(errors));
await b.close();
if(errors.length)process.exitCode=2;
})().catch(e=>{console.error(e);process.exit(1)});
