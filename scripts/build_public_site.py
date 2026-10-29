#!/usr/bin/env python3
"""Build static CommandCore product website, Angular workspace and hosted docs."""

from pathlib import Path
import html
import re
import shutil

import markdown

ROOT = Path(__file__).resolve().parent.parent
ANGULAR = ROOT / "apps/workspace-angular/dist/commandcore-workspace/browser"
SITE = ROOT / "deploy/public/site"
DOCS = ROOT / "docs"
OUT = ROOT / "dist/public-site"

if not (ANGULAR / "index.html").is_file():
    raise SystemExit(
        "Angular bundle missing; run npm ci && npm run build in apps/workspace-angular"
    )
if OUT.exists():
    shutil.rmtree(OUT)
shutil.copytree(SITE, OUT)
shutil.copytree(ANGULAR, OUT / "app")
# Angular's current base href may be '/' in some builds; retain same-origin root assets.
for item in ANGULAR.iterdir():
    if item.is_dir():
        if item.name == "brand":
            shutil.copytree(item, OUT / "brand", dirs_exist_ok=True)
        continue
    if item.name != "index.html" and not item.name.startswith("."):
        shutil.copy2(item, OUT / item.name)

style = (
    "body{background:#0b1420;color:#e8f2f4;font:16px/1.75 system-ui,sans-serif;margin:0}"
    "nav{padding:18px 6%;border-bottom:1px solid #2b4050;display:flex;gap:24px;flex-wrap:wrap}"
    "a{color:#55e4cb}main{max-width:920px;margin:35px auto;padding:0 22px 60px}"
    "h1,h2{line-height:1.3}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#132734;"
    "border:1px solid #2e4350;padding:18px;border-radius:9px}"
    "code{overflow-wrap:anywhere}p,li{color:#bfccd3}table{border-collapse:collapse;width:100%}"
    "th,td{padding:7px 11px;text-align:left;border:1px solid #38515f}"
    "blockquote{border-left:3px solid #55e4cb;margin-left:0;padding-left:16px;color:#9cb2c0}"
    "img{max-width:100%}"
)
docs_target = OUT / "docs"
docs_target.mkdir(parents=True, exist_ok=True)
rendered = 0
for source in sorted(DOCS.rglob("*")):
    if not source.is_file():
        continue
    relative = source.relative_to(DOCS)
    target = docs_target / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    if source.suffix.lower() != ".md":
        shutil.copy2(source, target)
        continue
    raw = source.read_text(encoding="utf-8")
    raw = re.sub(
        r"\]\(([^)\s]+)\.md((?:[#?][^)]*)?)\)",
        lambda match: "](" + match.group(1) + ".html" + match.group(2) + ")",
        raw,
    )
    body = markdown.markdown(raw, extensions=["fenced_code", "tables", "toc"])
    title = html.escape(source.stem)
    document = (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>{title} · CommandCore Docs</title><style>{style}</style>"
        '</head><body><nav><a href="/">CommandCore</a><a href="/app/">Dashboard</a>'
        '<a href="/docs/">Documentation</a>'
        '<a href="https://github.com/bazobehram/commandcore">GitHub</a>'
        f"</nav><main>{body}</main></body></html>"
    )
    target.with_suffix(".html").write_text(document, encoding="utf-8")
    rendered += 1
shutil.copy2(docs_target / "README.html", docs_target / "index.html")
assert (OUT / "app/index.html").is_file()
assert (OUT / "docs/index.html").is_file()
assert list((OUT / "app").glob("main-*.js"))
assert list((OUT / "app").glob("styles-*.css"))
print(f"Static product bundle ready: {OUT}, docs={rendered}")
