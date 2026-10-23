const {chromium}=require('playwright'),assert=require('node:assert/strict'),fs=require('fs');
(async()=>{
 const b=await chromium.launch({headless:true,...(process.env.CHROMIUM_PATH?{executablePath:process.env.CHROMIUM_PATH}:{}),args:['--no-sandbox']}),p=await b.newPage({viewport:{width:390,height:844}});
 const scripts=JSON.parse(fs.readFileSync(process.env.COMMANDCORE_UI_FIXTURES+'/link-scripts.json'));
 await p.setContent(`<a href="https://example.com/product"> Product\n details </a><br>
 <form><a href="https://example.com/submit">Form control</a></form>
 <a download href="https://example.com/file">Download</a><br>
 <a style="display:none" href="https://example.com/hidden">Hidden</a>
 <a onmousedown="window.trackerFired=true" onclick="window.trackerFired=true;return false" href="https://example.com/script">Scripted</a><br>
 <a role="button" href="https://example.com/button">Button</a><br>
 <div aria-hidden="true"><a href="https://example.com/invisible">Invisible</a></div>
 <a id="covered" href="https://example.com/covered">Covered</a>
 <input type="password" value="SECRET_PASSWORD"><input value="SECRET_FORM_VALUE">`);
 await p.evaluate(()=>{const r=document.getElementById('covered').getBoundingClientRect(),d=document.createElement('div');Object.assign(d.style,{position:'absolute',left:r.left+'px',top:r.top+'px',width:r.width+'px',height:r.height+'px',zIndex:20});document.body.append(d);});
 const value=await p.evaluate(scripts.links);
 assert.deepEqual(value.links.map(x=>x.label),['Product details','Scripted']);assert(!JSON.stringify(value).includes('SECRET'));
 const follow=await p.evaluate(scripts.follow.replace('POSITION','0'));assert(follow.valid);assert.equal(follow.label,'Product details');
 const covered=await p.evaluate(scripts.follow.replace('POSITION','7'));assert.equal(covered.valid,false);
 const tracked=await p.evaluate(scripts.follow.replace('POSITION','4'));assert(tracked.valid,'tracking handlers must not hide ordinary address navigation');
 assert.equal(await p.evaluate(()=>window.trackerFired),undefined,'inspection and address validation do not dispatch page handlers');
 await p.setContent(`<a id="partial" href="https://example.com/result" style="display:block;width:200px;height:80px"><span style="display:block;padding-top:55px">Result heading</span></a><a style="display:contents" href="https://example.com/contents"><h3>Contents result</h3></a>`);
 await p.evaluate(()=>{const a=document.getElementById('partial'),r=a.getBoundingClientRect(),cover=document.createElement('div');Object.assign(cover.style,{position:'absolute',left:r.left+'px',top:r.top+'px',width:r.width+'px',height:'50px',zIndex:20});document.body.append(cover);const top=document.elementFromPoint((r.left+r.right)/2,(r.top+r.bottom)/2);if(a.contains(top))throw Error('Fixture must cover bounding-box centre');});
 const pieces=await p.evaluate(scripts.links);assert.deepEqual(pieces.links.map(x=>x.label),['Result heading','Contents result']);
 assert((await p.evaluate(scripts.follow.replace('POSITION','0'))).valid,'partly visible result revalidates');
 assert((await p.evaluate(scripts.follow.replace('POSITION','1'))).valid,'display:contents link revalidates');
 await b.close();console.log('PASS actual DOM link extraction/revalidation: whitespace, visibility, occlusion, form/button/download filtering; tracked links allowed without executing handlers; no input values');
})().catch(e=>{console.error(e);process.exit(1)});
