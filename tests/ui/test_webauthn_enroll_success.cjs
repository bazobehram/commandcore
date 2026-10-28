const {chromium}=require('playwright'),fs=require('fs'),assert=require('assert');
const src=fs.readFileSync('/tmp/commandcore-release-work/apps/server/commandcore_server/collaboration_review_routes.py','utf8').match(/        source = r"""([\s\S]*?)"""/)[1];
(async()=>{
 const browser=await chromium.launch({headless:true,executablePath:'/usr/bin/google-chrome',args:['--no-sandbox']});
 try {
  const page=await browser.newPage(),calls=[];
  const b64=b=>Buffer.from(b).toString('base64url');
  const challenge=b64(Buffer.alloc(32,7)),uid=b64(Buffer.from('owner'));
  await page.route('https://panel.example.test/**', async route=>{
   const req=route.request(),path=new URL(req.url()).pathname;
   if(path.endsWith('/begin')) {
    calls.push('begin');
    return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({challenge,options:{publicKey:{challenge,user:{id:uid,name:'owner',displayName:'owner'},rp:{id:'panel.example.test',name:'CommandCore'},pubKeyCredParams:[{type:'public-key',alg:-8}]}}})});
   }
   if(path.endsWith('/finish')){
    calls.push('finish');const body=req.postDataJSON();
    assert.equal(body.challenge,challenge);
    assert.equal(body.response.rawId,b64(Buffer.from([1,2,3])));
    assert.equal(body.response.response.clientDataJSON,b64(Buffer.from([4,5])));
    assert.equal(body.response.response.attestationObject,b64(Buffer.from([6,7])));
    return route.fulfill({status:200,contentType:'application/json',body:'{"enrolled":true}'});
   }
   return route.fulfill({status:200,contentType:'text/html',body:'<button id="enroll-passkey">Enroll</button><p id="enrollment-status"></p>'});
  });
  await page.goto('https://panel.example.test/');
  await page.evaluate(()=>{
   Object.defineProperty(window,'PublicKeyCredential',{value:function(){}});
   Object.defineProperty(navigator,'credentials',{configurable:true,value:{create:async ({publicKey})=>{
    if(!(publicKey.challenge instanceof Uint8Array)||publicKey.challenge.length!==32)throw Error('challenge decode');
    if(!(publicKey.user.id instanceof Uint8Array))throw Error('user decode');
    return {id:'AQID',rawId:Uint8Array.from([1,2,3]).buffer,type:'public-key',response:{clientDataJSON:Uint8Array.from([4,5]).buffer,attestationObject:Uint8Array.from([6,7]).buffer}};
   }}});
  });
  await page.evaluate(js=>{new Function(js)()},src);
  await page.getByRole('button').click();
  await page.waitForFunction(()=>document.querySelector('#enrollment-status').textContent.startsWith('Passkey enrolled'));
  assert.deepEqual(calls,['begin','finish']);
  assert.equal(await page.getByRole('button').isDisabled(),false);
  console.log('BROWSER_SIMULATED_ENROLLMENT_SUCCESS_PASS');
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exit(1)});
