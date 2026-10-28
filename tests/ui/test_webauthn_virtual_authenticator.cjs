const {chromium}=require('playwright');
const fs=require('fs');
(async()=>{
const b=await chromium.launch({headless:true,...(process.env.CHROMIUM_PATH?{executablePath:process.env.CHROMIUM_PATH}:process.arch==='arm64'?{executablePath:chromium.executablePath()}:{}),args:['--no-sandbox']});
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
const assertionChallenge=crypto.getRandomValues(new Uint8Array(32));
const assertion=await navigator.credentials.get({publicKey:{
 challenge:assertionChallenge,
 rpId:'panel.example.test',userVerification:'required',timeout:10000
}});
const authData=new Uint8Array(assertion.response.authenticatorData);
return {ok:!!c&&!!assertion,alg,rawIdLength:c.rawId.byteLength,
 fixture:{publicKey: Array.from(new Uint8Array(c.response.getPublicKey())),challenge:Array.from(assertionChallenge),authenticatorData:Array.from(new Uint8Array(assertion.response.authenticatorData)),clientDataJSON:Array.from(new Uint8Array(assertion.response.clientDataJSON)),signature:Array.from(new Uint8Array(assertion.response.signature))},
 discoverableAssertion:assertion.rawId.byteLength===c.rawId.byteLength &&
 Array.from(new Uint8Array(assertion.rawId)).every((v,i)=>v===new Uint8Array(c.rawId)[i]),
 userVerified:!!(authData[32]&4),signatureBytes:assertion.response.signature.byteLength};}catch(e){return {ok:false,alg,error:e.name,message:e.message}}},alg);
if(!out.ok || !out.discoverableAssertion || !out.userVerified || !out.signatureBytes) throw Error(JSON.stringify(out));
if(!process.env.COMMANDCORE_NATIVE_ASSERTION_FIXTURE)throw Error('missing isolated fixture path');
fs.writeFileSync(process.env.COMMANDCORE_NATIVE_ASSERTION_FIXTURE,JSON.stringify(out.fixture),{flag:'wx',mode:0o600});
const {fixture,...summary}=out;console.log('BROWSER_NATIVE_WEBAUTHN_ED25519_ASSERTION_PASS '+JSON.stringify(summary));
}
}finally{await b.close()}
})().catch(e=>{console.error(e);process.exitCode=1})
