#!/usr/bin/env bash
# Operator-side publication; no signing key or GitHub token in arguments/files.
set -euo pipefail
if [[ $# -ne 2 ]]; then
  echo "Usage: $0 RELEASE_DIRECTORY PUBLIC_KEY_FILE" >&2
  exit 2
fi
DIR="$(realpath "$1")"
PUBLIC_KEY_FILE="$(realpath "$2")"
REPO="bazobehram/commandcore"
VERSION="0.9.0-rc8"
TAG="agent-v${VERSION}"
test -r "$DIR/manifest.signed.json"
test -r "$DIR/commandcore-agent-linux-x86_64"
test -r "$PUBLIC_KEY_FILE"
command -v gh >/dev/null || { echo 'GitHub CLI (gh) required.' >&2; exit 3; }
gh auth status >/dev/null || { echo 'Authenticate gh first: gh auth login' >&2; exit 3; }
python3 - "$DIR" "$PUBLIC_KEY_FILE" "$VERSION" "$REPO" <<'PY'
import base64,hashlib,json,sys
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
d=Path(sys.argv[1]); key=base64.b64decode(Path(sys.argv[2]).read_text().strip(),validate=True)
version,repo=sys.argv[3:]
m=json.loads((d/'manifest.signed.json').read_text())
artifact=d/'commandcore-agent-linux-x86_64'
assert len(key)==32
assert m['schema_version']==1 and m['product']=='commandcore-agent' and m['version']==version
assert len(m['artifacts'])==1
item=m['artifacts'][0]
assert item['url']==f'https://github.com/{repo}/releases/download/agent-v{version}/{artifact.name}'
assert item['sha256']==hashlib.sha256(artifact.read_bytes()).hexdigest() and item['size']==artifact.stat().st_size
assert m['signing_key_id']==hashlib.sha256(key).hexdigest()[:16]
canonical=json.dumps({k:v for k,v in m.items() if k!='signature'},sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
Ed25519PublicKey.from_public_bytes(key).verify(base64.b64decode(m['signature'],validate=True),canonical)
print('SIGNED_RELEASE_VERIFIED')
PY
if gh release view "$TAG" --repo "$REPO" >/dev/null 2>&1; then
  echo 'Release already exists; refusing overwrite.' >&2
  exit 4
fi
gh release create "$TAG" --repo "$REPO" --target main \
  "$DIR/commandcore-agent-linux-x86_64" "$DIR/manifest.signed.json" \
  --title "CommandCore Agent $VERSION" \
  --notes "Verified signed native Linux agent prerelease." --prerelease
echo "SIGNED_RELEASE_PUBLISHED: $TAG"
