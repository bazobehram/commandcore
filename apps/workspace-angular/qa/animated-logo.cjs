const {chromium}=require('playwright-core');
(async()=>{
const b=await chromium.launch({executablePath:'/usr/bin/chromium',headless:true,args:['--no-sandbox','--disable-dev-shm-usage','--disable-gpu']});
const p=await b.newPage();
for(const mode of ['loading','working','online','attention']){
 await p.goto('https://commandcore.synovaq.org/brand/octopus-'+mode+'.svg?v=20261029-v8',{waitUntil:'load'});
 const v=await p.evaluate(()=>{
  const cores=[...document.querySelectorAll('.core')];
  return {count:cores.length,animations:cores.map(x=>getComputedStyle(x).animationName),running:document.getAnimations().length};
 });
 console.log(mode,v);
 if(!v.running&&mode!=='offline')process.exitCode=2;
}
await b.close();
})().catch(e=>{console.error(e);process.exit(1)});
