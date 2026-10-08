# Verify a Linux installer before executing it

The normal installer command remains supported. Operators who want to inspect
and authenticate the script first can use the procedure below. It requires curl,
Python 3 and OpenSSL with Ed25519 support, and executes no downloaded script
before verification.

Obtain your deployment's release public key and its SHA-256 fingerprint through
an independently trusted channel. Set `COMMANDCORE_RELEASE_PUBLIC_KEY_B64` and
`COMMANDCORE_RELEASE_KEY_SHA256` in your local environment to those verified
values; this repository does not prescribe a shared deployment trust key. A key
and hash delivered by the same compromised website do not independently prove
authenticity; initial HTTPS/DNS/provider/workstation trust remains necessary.

Run these commands in a new empty directory:

```sh
curl --proto '=https' --tlsv1.2 -fsS https://commandcore.example.com/releases/agent/manifest.json -o manifest.json
curl --proto '=https' --tlsv1.2 -fsS https://commandcore.example.com/install/linux -o linux.sh
python3 - <<'PY'
import base64, hashlib, json, os, pathlib
key = base64.b64decode(os.environ['COMMANDCORE_RELEASE_PUBLIC_KEY_B64'], validate=True)
assert len(key) == 32
assert hashlib.sha256(key).hexdigest() == os.environ['COMMANDCORE_RELEASE_KEY_SHA256'].lower()
raw = pathlib.Path('manifest.json').read_bytes()
assert len(raw) <= 1048576
m = json.loads(raw)
pathlib.Path('public.der').write_bytes(bytes.fromhex('302a300506032b6570032100') + key)
pathlib.Path('signature.bin').write_bytes(base64.b64decode(m['signature'], validate=True))
pathlib.Path('canonical.json').write_bytes(json.dumps({k:v for k,v in m.items() if k != 'signature'}, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode())
PY
openssl pkey -pubin -inform DER -in public.der -out public.pem
openssl pkeyutl -verify -rawin -pubin -inkey public.pem -sigfile signature.bin -in canonical.json
```

**Continue only if signature verification succeeds.** Check the script against
the authenticated manifest's `installers.linux` metadata, then inspect it:

```sh
python3 - <<'PY'
import hashlib, json, pathlib
m = json.loads(pathlib.Path('manifest.json').read_bytes())
assert m['schema_version'] == 1 and m['product'] == 'commandcore-agent'
script = pathlib.Path('linux.sh').read_bytes()
expected = m['installers']['linux']
assert expected['url'].startswith('https://commandcore.example.com/releases/agent/')
assert len(script) == expected['size']
assert hashlib.sha256(script).hexdigest() == expected['sha256']
print('Verified installer for release', m['version'])
PY
less linux.sh
sh linux.sh --server https://commandcore.example.com --upgrade
```

Stop if the manifest lacks installer metadata, verification fails, or the script
does not match the release you intended. Current feed and script may be updated
between downloads; retry using the authenticated immutable version URL rather
than relaxing a failed hash check. Removing `--upgrade` performs a fresh install.
The installer separately verifies every Agent artifact's signature, hash and
exact size before activating it. For rollback, use the recorded immutable
known-good manifest and its signed installer; retain the prior identity/state.
