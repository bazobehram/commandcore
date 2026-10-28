const {chromium}=require('playwright'),fs=require('fs'),assert=require('assert');
const src=fs.readFileSync('/tmp/commandcore-release-work/apps/server/commandcore_server/collaboration_review_routes.py','utf8');
const script=src.match(/async def review_verification_script[\s\S]*?source = r"""([\s\S]*?)"""/)?.[1];
assert(script,'review script missing');
(async()=>{
 const browser=await chromium.launch({headless:true,executablePath:'/usr/bin/google-chrome',args:['--no-sandbox']});
 try{
  for(const shouldPass of [true,false]){
   const page=await browser.newPage(),calls=[];
   await page.route('https://panel.example.test/**',route=>{
    const path=new URL(route.request().url()).pathname;
    if(path.endsWith('/review-challenge')){
     calls.push('challenge');return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({challenge:'token-123'})});
    }
    if(path.endsWith('/verify-webauthn')){
     calls.push('verify');const data=route.request().postDataJSON();
     assert.equal(data.challenge,'token-123');assert.equal(data.credentialId,'AQID');
     assert.equal(data.authenticatorData,'BAUG');assert.equal(data.clientDataJSON,'Bwg');
     assert.equal(data.signature,'CQo');
     return route.fulfill({status:shouldPass?200:409,contentType:'application/json',body:JSON.stringify({credential_verified:true,delivery_authorized:false})});
    }
    return route.fulfill({status:200,contentType:'text/html',body:'<button id="verify-review-passkey" data-request-id="req-A">Verify</button><p id="review-verification-status"></p>'});
   });
   await page.goto('https://panel.example.test/');
   await page.evaluate(()=>{
    Object.defineProperty(window,'PublicKeyCredential',{value:function(){}});
    Object.defineProperty(navigator,'credentials',{configurable:true,value:{get:async ({publicKey})=>{
     if(new TextDecoder().decode(publicKey.challenge)!=='token-123'||publicKey.userVerification!=='required')throw Error('challenge');
     return {type:'public-key',rawId:Uint8Array.from([1,2,3]).buffer,response:{
      authenticatorData:Uint8Array.from([4,5,6]).buffer,
      clientDataJSON:Uint8Array.from([7,8]).buffer,
      signature:Uint8Array.from([9,10]).buffer}};
    }}});
   });
   await page.evaluate(js=>new Function(js)(),script);
   await page.getByRole('button').click();
   await page.waitForFunction(()=>document.querySelector('#review-verification-status').textContent.includes('verified')||document.querySelector('#review-verification-status').textContent.includes('failed'));
   const status=await page.locator('#review-verification-status').innerText();
   assert(shouldPass?status.includes('Identity verified'):status.includes('Verification failed'),status);
   assert.deepEqual(calls,['challenge','verify']);
   assert.equal(await page.getByRole('button').isDisabled(),false);
   await page.close();
  }
  console.log('BROWSER_REVIEW_SIGNING_SUCCESS_AND_FAILURE_PASS');
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exit(1)});
