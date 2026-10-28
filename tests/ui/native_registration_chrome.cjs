const {chromium}=require('playwright'),fs=require('fs');
(async()=>{
 const options=JSON.parse(fs.readFileSync(process.env.CC_NATIVE_REG_OPTIONS,'utf8'));
 const b=await chromium.launch({headless:true,...(process.env.CHROMIUM_PATH?{executablePath:process.env.CHROMIUM_PATH}:{}),args:['--no-sandbox']});
 try {
  const ctx=await b.newContext(),page=await ctx.newPage();
  await page.route('https://panel.example.test/**',r=>r.fulfill({status:200,contentType:'text/html',body:'test'}));
  await page.goto('https://panel.example.test/');
  const cdp=await ctx.newCDPSession(page);await cdp.send('WebAuthn.enable');
  await cdp.send('WebAuthn.addVirtualAuthenticator',{options:{protocol:'ctap2',transport:'usb',hasResidentKey:true,hasUserVerification:true,isUserVerified:true}});
  const resp=await page.evaluate(async v=>{
    const dec=x=>Uint8Array.from(atob(x.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0));
    const enc=x=>btoa(String.fromCharCode(...new Uint8Array(x))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
    const pk=v.options.publicKey;pk.challenge=dec(pk.challenge);pk.user.id=dec(pk.user.id);
    const cred=await navigator.credentials.create({publicKey:pk});
    return {challenge:v.challenge,response:{id:cred.id,rawId:enc(cred.rawId),type:cred.type,response:{clientDataJSON:enc(cred.response.clientDataJSON),attestationObject:enc(cred.response.attestationObject)}}};
  },options);
  fs.writeFileSync(process.env.CC_NATIVE_REG_RESULT,JSON.stringify(resp),{flag:'wx',mode:0o600});
  console.log('NATIVE_REGISTRATION_BROWSER_PASS');
 }finally{await b.close()}
})().catch(e=>{console.error(e);process.exitCode=1});
