const {chromium}=require('playwright');
(async()=>{
const b=await chromium.launch({headless:true,executablePath:'/usr/bin/google-chrome',args:['--no-sandbox']});
try{
const context=await b.newContext({ignoreHTTPSErrors:true});const page=await context.newPage();
await page.route('https://panel.example.test/**',r=>r.fulfill({status:200,contentType:'text/html',body:'<html>test</html>'}));
await page.goto('https://panel.example.test/');
const cdp=await context.newCDPSession(page);await cdp.send('WebAuthn.enable');
await cdp.send('WebAuthn.addVirtualAuthenticator',{options:{protocol:'ctap2',transport:'usb',hasResidentKey:true,hasUserVerification:true,isUserVerified:true}});
for(const alg of [-8]){
const out=await page.evaluate(async alg=>{try{
const challenge=crypto.getRandomValues(new Uint8Array(32));
const c=await navigator.credentials.create({publicKey:{challenge,rp:{name:'CommandCore',id:'panel.example.test'},user:{id:new TextEncoder().encode('owner'),name:'owner',displayName:'owner'},pubKeyCredParams:[{type:'public-key',alg}],authenticatorSelection:{residentKey:'required',userVerification:'required'},timeout:10000,attestation:'none'}});
return {ok:!!c,alg,rawIdLength:c.rawId.byteLength};}catch(e){return {ok:false,alg,error:e.name,message:e.message}}},alg);
if(!out.ok) throw Error(JSON.stringify(out)); console.log('BROWSER_NATIVE_WEBAUTHN_ED25519_PASS '+JSON.stringify(out));
}
}finally{await b.close()}
})().catch(e=>{console.error(e);process.exitCode=1})
