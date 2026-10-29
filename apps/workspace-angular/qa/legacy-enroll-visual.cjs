const {chromium}=require('playwright-core');
(async()=>{
const b=await chromium.launch({executablePath:'/usr/bin/chromium',headless:true,args:['--no-sandbox','--disable-dev-shm-usage']});
const p=await b.newPage({viewport:{width:1366,height:900}}),errs=[];
p.on('pageerror',e=>errs.push(e.message));p.on('console',m=>{if(m.type()==='error')errs.push(m.text().slice(0,100))});
const resp=await p.goto('https://commandcore.synovaq.org/enroll/',{waitUntil:'networkidle'});
console.log('ENROLL_HTTP',resp.status());
console.log('LOGO_SRC',await p.locator('.brand img').getAttribute('src'));
console.log('BG',await p.evaluate(()=>getComputedStyle(document.body).backgroundColor));
console.log('LIGHT_CARD',await p.locator('main').evaluate(e=>getComputedStyle(e).backgroundColor));
console.log('REVIEW_PRESENT',await p.locator('#review').count());
console.log('PAGE_ERRORS',JSON.stringify(errs));
await p.screenshot({path:'/qa/octopus-enroll-desktop.png',fullPage:false});
const m=await b.newPage({viewport:{width:390,height:844},isMobile:true,hasTouch:true});
await m.goto('https://commandcore.synovaq.org/enroll/',{waitUntil:'networkidle'});
console.log('MOBILE_OVERFLOW',await m.evaluate(()=>document.documentElement.scrollWidth>innerWidth+2));
await m.screenshot({path:'/qa/octopus-enroll-mobile.png',fullPage:false});
await b.close();
})().catch(e=>{console.error(e.stack);process.exit(1)});
