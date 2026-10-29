#!/usr/bin/env python3
"""Render the approved CommandCore octopus vector geometry as PWA / site icons.
Derived from brand_identity/vector/mark-dark-on-light.svg; no external dependencies.
"""
from pathlib import Path
from PIL import Image, ImageDraw
import math, re, io
ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'dist/commandcore-workspace/browser'
OUT.mkdir(parents=True,exist_ok=True)
segments=[
"M119 111 C91 129 62 126 53 109 L53 86",
"M114 125 C78 152 39 160 26 134 L25 120",
"M119 137 C95 177 54 199 43 190",
"M126 141 C114 190 92 216 78 218",
"M147 144 C153 190 171 216 180 218",
"M158 136 C186 182 210 197 220 191",
"M160 126 C199 152 226 158 234 137 L234 120",
"M163 113 C191 128 216 123 219 104 L220 87"]
nodes=[(53,86),(25,120),(43,190),(78,218),(180,218),(220,191),(234,120),(220,87)]
def path_pts(source):
    tokens=re.findall(r'[MCL]|-?\d+(?:\.\d+)?',source)
    i=0; points=[]; cur=(0.,0.)
    while i<len(tokens):
        op=tokens[i];i+=1
        if op=='M':
            cur=(float(tokens[i]),float(tokens[i+1]));i+=2;points.append(cur)
        elif op=='L':
            cur=(float(tokens[i]),float(tokens[i+1]));i+=2;points.append(cur)
        elif op=='C':
            p0=cur;p1=(float(tokens[i]),float(tokens[i+1]));p2=(float(tokens[i+2]),float(tokens[i+3]));p3=(float(tokens[i+4]),float(tokens[i+5]));i+=6
            for n in range(1,45):
                t=n/44;u=1-t
                points.append((u*u*u*p0[0]+3*u*u*t*p1[0]+3*u*t*t*p2[0]+t*t*t*p3[0],u*u*u*p0[1]+3*u*u*t*p1[1]+3*u*t*t*p2[1]+t*t*t*p3[1]))
            cur=p3
    return points
def render(size=512,dark=False,transparent=False,maskable=False):
    big=1024
    if transparent: bg=(0,0,0,0)
    else: bg=(25,35,51,255) if dark else (248,250,253,255)
    im=Image.new('RGBA',(big,big),bg);d=ImageDraw.Draw(im)
    if not transparent:
        # Keep tile quiet; white/light and dark icon variants.
        d.rounded_rectangle((14,14,big-14,big-14),radius=240,fill=bg)
    pct=.57 if maskable else .69
    scale=big*pct/256
    off=(big-256*scale)/2
    def P(pt):return (off+pt[0]*scale,off+pt[1]*scale)
    line=(245,248,252,255) if dark else (29,42,52,255)
    ring=line
    for source in segments:
        pts=[P(x) for x in path_pts(source)]
        width=int(16*scale)
        d.line(pts,fill=line,width=width,joint='curve')
        for x,y in (pts[0],pts[-1]):
            rr=width/2
            d.ellipse((x-rr,y-rr,x+rr,y+rr),fill=line)
    head=path_pts('M136 39 C102 39 88 63 92 94 C93 112 110 129 111 148 L161 148 C163 125 180 114 180 91 C180 63 163 39 136 39')
    d.polygon([P(x) for x in head],fill=line)
    eyes=(29,42,52,255) if dark else (255,255,255,255)
    if dark: eyes=(25,35,51,255)
    for x in (120,153):
        px,py=P((x,101));rx=5.8*scale;ry=9*scale;d.ellipse((px-rx,py-ry,px+rx,py+ry),fill=eyes)
    for i,(x,y) in enumerate(nodes):
        px,py=P((x,y));rr=11.5*scale;core=5.4*scale
        d.ellipse((px-rr,py-rr,px+rr,py+rr),fill=ring)
        accent=(185,133,95,255) if i in (2,5,7) else ((29,42,52,255) if dark else (248,250,253,255))
        d.ellipse((px-core,py-core,px+core,py+core),fill=accent)
    return im.resize((size,size),Image.Resampling.LANCZOS)
for size in (16,24,32,48,64,180,192,256,512):
    render(size).save(OUT/f'brand-icon-{size}.png')
for sz in (192,512):render(sz).save(OUT/f'icon-{sz}.png')
render(192).save(OUT/'apple-touch-icon.png')
render(512,maskable=True).save(OUT/'icon-maskable-512.png')
render(64).save(OUT/'commandcore-icon.png')
render(512,dark=True).save(OUT/'brand-icon-dark-512.png')
render(512,transparent=True).save(OUT/'brand-icon-transparent-512.png')
render(64).save(OUT/'favicon.png')
render(64).save(OUT/'favicon.ico',format='ICO',sizes=[(16,16),(32,32),(48,48)])
print('Branded octopus icons created.')
