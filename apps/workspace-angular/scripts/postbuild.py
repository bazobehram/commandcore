#!/usr/bin/env python3
"""Generate public-only PWA assets for the CommandCore Angular build."""
from pathlib import Path
import json,re
root=Path(__file__).resolve().parents[1]
pub=root/'public'
pub.mkdir(exist_ok=True)
out=root/'dist/commandcore-workspace/browser'
out.mkdir(parents=True,exist_ok=True)
manifest={
 'id':'/','name':'CommandCore Workspace','short_name':'CommandCore',
 'description':'Private MCP workspace for connected devices and AI agents.',
 'start_url':'/','scope':'/','display':'standalone',
 'background_color':'#f6f8fd','theme_color':'#f6f8fd',
 'icons':[{'src':f'/icon-{n}.png?v=octopus-v7','sizes':f'{n}x{n}','type':'image/png','purpose':'any'} for n in (192,512)]+[{'src':'/icon-maskable-512.png?v=octopus-v7','sizes':'512x512','type':'image/png','purpose':'maskable'}]
}
(out/'manifest.webmanifest').write_text(json.dumps(manifest,indent=2))
source=(out/'index.html').read_text()
source=re.sub(r'<title>[^<]*</title>','<title>CommandCore Workspace</title>',source)
source=re.sub(r'<base href="/"\s*/?>','',source)
source=re.sub(r'<link rel="icon" type="image/x-icon" href="favicon.ico"\s*/?>','',source)
if '<link rel="manifest" href="/manifest.webmanifest">' not in source:
    source=source.replace('</head>', '<meta name="theme-color" content="#f6f8fd"><meta name="apple-mobile-web-app-capable" content="yes"><meta name="apple-mobile-web-app-status-bar-style" content="default"><link rel="apple-touch-icon" href="/apple-touch-icon.png?v=octopus-v7"><link rel="icon" type="image/svg+xml" href="/brand/octopus-idle.svg?v=20261029-v8"><link rel="icon" type="image/png" href="/favicon.png?v=octopus-v7" sizes="64x64"><link rel="manifest" href="/manifest.webmanifest"></head>')
(out/'index.html').write_text(source)
assets=['/','/index.html','/brand/octopus-head.svg?v=octopus-v10','/manifest.webmanifest','/icon-192.png?v=octopus-v7','/icon-512.png?v=octopus-v7','/icon-maskable-512.png?v=octopus-v7','/apple-touch-icon.png?v=octopus-v7','/favicon.png?v=octopus-v7']+[f'/brand/octopus-{s}.svg?v=20261029-v8' for s in ('idle','online','offline','loading','working','attention','completed')]+['/'+x.name for x in out.glob('*.js')]+['/'+x.name for x in out.glob('*.css')]
sw='''const CACHE = 'commandcore-workspace-static-v11-live';
const STATIC = '''+json.dumps(assets)+''';
self.addEventListener('install',event=>event.waitUntil(caches.open(CACHE).then(cache=>cache.addAll(STATIC))));
self.addEventListener('activate',event=>event.waitUntil(caches.keys().then(keys=>Promise.all(keys.filter(k=>k.startsWith('commandcore-workspace-static-')&&k!==CACHE).map(k=>caches.delete(k))))));
self.addEventListener('fetch',event=>{
  const request=event.request;
  if(request.method!=='GET'||new URL(request.url).origin!==location.origin)return;
  const path=new URL(request.url).pathname;
  // Never intercept API/MCP/auth/session/onboarding, browser private routes, or credentials.
  if(path!=='/'&&!STATIC.includes(path)&&!STATIC.includes(path+new URL(request.url).search))return;
  event.respondWith(fetch(request).then(response=>{
    if(response.ok && !request.headers.has('Authorization') && response.type==='basic'){
      const snapshot=response.clone();
      caches.open(CACHE).then(cache=>cache.put(request,snapshot));
    }
    return response;
  }).catch(()=>caches.match(request).then(hit=>hit||caches.match('/index.html'))));
});
'''
(out/'sw.js').write_text(sw)
from subprocess import run
import sys
run([sys.executable,str(root/'scripts/brand_icons.py')],check=True)
print('PWA static assets:',len(assets))
