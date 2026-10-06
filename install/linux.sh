#!/bin/sh
# CommandCore user installer. Release key must be pinned out of band.
set -eu
umask 077
server=https://commandcore.example.com
manifest=
enroll=yes
service=yes
test_loopback=no
upgrade=no
device_name=
service_name=${COMMANDCORE_AGENT_SERVICE_NAME:-commandcore-agent.service}
case "$service_name" in commandcore-agent*.service) ;; *) echo 'Invalid Agent service name.' >&2; exit 2;; esac
case "$service_name" in *[!A-Za-z0-9_.-]*) echo 'Invalid Agent service name.' >&2; exit 2;; esac
systemd_config_home=${COMMANDCORE_SYSTEMD_CONFIG_HOME:-${XDG_CONFIG_HOME:-$HOME/.config}}
service_ctl() { XDG_CONFIG_HOME="$systemd_config_home" systemctl --user "$@"; }
while [ "$#" -gt 0 ]; do
  case "$1" in
    --server) server=$2; shift 2;;
    --manifest) manifest=$2; shift 2;;
    --no-enroll) enroll=no; shift;;
    --no-service) service=no; shift;;
    --test-loopback) test_loopback=yes; shift;;
    --upgrade) upgrade=yes; shift;;
    --name) device_name=$2; shift 2;;
    *) printf 'Unknown option: %s\n' "$1" >&2; exit 2;;
  esac
done
: "${COMMANDCORE_RELEASE_PUBLIC_KEY_B64:?Pin the trusted release public key before installation}"
[ "$(uname -s)" = Linux ] || { echo 'This installer supports Linux only.' >&2; exit 2; }
[ "$(id -u)" != 0 ] || { echo 'Run as the normal Agent user; privileged helper setup is separate.' >&2; exit 2; }
for tool in curl openssl python3; do command -v "$tool" >/dev/null || { echo "Required tool: $tool" >&2; exit 2; }; done
case "$(uname -m)" in x86_64|amd64) arch=x86_64;; aarch64|arm64) arch=arm64;; *) echo 'Unsupported architecture.' >&2; exit 2;; esac
python3 - <<'PY'
import ctypes,re,subprocess
try:
    version=ctypes.CDLL(None).gnu_get_libc_version
    version.restype=ctypes.c_char_p
    if tuple(map(int,version().decode().split('.'))) < (2,36): raise ValueError()
except (AttributeError,ValueError): raise SystemExit('Supported Linux release requires glibc 2.36 or newer')
found=re.search(r'^curl (\d+)\.(\d+)\.(\d+)',subprocess.check_output(['curl','--disable','--version'],text=True))
if not found or tuple(map(int,found.groups())) < (8,4,0): raise SystemExit('curl 8.4 or newer is required for bounded release downloads')
PY
manifest=${manifest:-${server%/}/releases/agent/manifest.json}
tmp=$(mktemp -d "${TMPDIR:-/tmp}/commandcore-install.XXXXXXXX")
previous=
switched=no
complete=no
rollback=
cleanup() {
  result=$?
  trap - EXIT HUP INT TERM
  if [ "$switched" = yes ] && [ "$complete" != yes ] && [ -n "$previous" ]; then
    ln -s "$previous" "$install_root/current.rollback"
    mv -Tf "$install_root/current.rollback" "$install_root/current"
    if [ -n "$rollback" ] && [ -f "$rollback/service.unit" ]; then
      cp "$rollback/service.unit" "$unit_root/$service_name"
      service_ctl daemon-reload || true
    fi
    service_ctl restart "$service_name" || true
    echo 'Installation failed; restored previous Agent.' >&2
  elif [ "$switched" = yes ] && [ "$complete" != yes ] && [ "$service" = yes ]; then
    service_ctl stop "$service_name" || true
    echo 'Fresh installation failed; Agent stopped. Existing identity is preserved.' >&2
  fi
  rm -f "$tmp/manifest.json" "$tmp/canonical.json" "$tmp/signature.bin" "$tmp/public.der" "$tmp/public.pem" "$tmp/metadata.json" "$tmp/agent.bin"
  rmdir "$tmp"
  exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' HUP TERM
fetch() {
  python3 - "$1" "$test_loopback" <<'PY'
import sys,urllib.parse
u=urllib.parse.urlsplit(sys.argv[1])
local=sys.argv[2]=='yes' and u.scheme=='http' and u.hostname in {'127.0.0.1','localhost','::1'}
if (u.scheme!='https' and not local) or not u.hostname or u.username or u.password or u.fragment or any(ord(c)<32 for c in sys.argv[1]): raise SystemExit('Download requires HTTPS without embedded credentials')
PY
  case "$1" in
    https://*) protocol='=https';;
    http://127.0.0.1:*|http://localhost:*) [ "$test_loopback" = yes ] || exit 2; protocol='=http';;
    *) echo 'HTTPS download URL required.' >&2; exit 2;;
  esac
  if curl --disable --globoff --proto "$protocol" --tlsv1.2 --happy-eyeballs-timeout-ms 250 --connect-timeout 15 --max-time 60 --max-filesize 134217728 --fail --silent --user-agent CommandCore-release-downloader/1 --url "$1" -o "$2"; then
    return
  else
    code=$?
    case "$code" in 5|6) stage=DNS;; 7) stage=TCP;; 35|51|58|60|77) stage=TLS;; 22) stage=HTTP;; 28) stage=deadline;; 63) stage=HTTP_size;; *) stage=transport;; esac
    printf 'Download failed: stage=%s curl_exit=%s\n' "$stage" "$code" >&2
    return "$code"
  fi
}
fetch "$manifest" "$tmp/manifest.json"
python3 - "$tmp" <<'PY'
import base64,json,os,pathlib,sys
root=pathlib.Path(sys.argv[1])
raw=(root/'manifest.json').read_bytes()
if len(raw)>1048576: raise SystemExit('Manifest too large')
manifest=json.loads(raw)
key=base64.b64decode(os.environ['COMMANDCORE_RELEASE_PUBLIC_KEY_B64'],validate=True)
if len(key)!=32: raise SystemExit('Ed25519 public key must be 32 bytes')
(root/'public.der').write_bytes(bytes.fromhex('302a300506032b6570032100')+key)
(root/'signature.bin').write_bytes(base64.b64decode(manifest['signature'],validate=True))
(root/'canonical.json').write_bytes(json.dumps({k:v for k,v in manifest.items() if k!='signature'},sort_keys=True,separators=(',',':'),ensure_ascii=False).encode())
PY
openssl pkey -pubin -inform DER -in "$tmp/public.der" -out "$tmp/public.pem" >/dev/null 2>&1
if ! openssl pkeyutl -verify -rawin -pubin -inkey "$tmp/public.pem" -sigfile "$tmp/signature.bin" -in "$tmp/canonical.json" >/dev/null 2>&1; then
  echo 'Release validation failed: stage=signature' >&2
  exit 1
fi
python3 - "$tmp" "$arch" <<'PY'
import json,pathlib,re,sys
root=pathlib.Path(sys.argv[1]);m=json.loads((root/'manifest.json').read_bytes())
if m.get('schema_version')!=1 or m.get('product')!='commandcore-agent': raise SystemExit('Wrong release product/schema')
if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,60}',m['version']): raise SystemExit('Invalid release version')
matches=[a for a in m['artifacts'] if a.get('platform')=='linux' and a.get('architecture')==sys.argv[2] and a.get('kind')=='executable']
if len(matches)!=1: raise SystemExit('No unique executable for this architecture')
a=matches[0]
if not re.fullmatch('[a-f0-9]{64}',a['sha256']) or not isinstance(a['size'],int) or not 0<a['size']<=134217728: raise SystemExit('Invalid artifact integrity metadata')
a['version']=m['version'];(root/'metadata.json').write_text(json.dumps(a))
PY
url=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["url"])' "$tmp/metadata.json")
fetch "$url" "$tmp/agent.bin"
python3 - "$tmp" <<'PY'
import hashlib,json,pathlib,sys
root=pathlib.Path(sys.argv[1]);a=json.loads((root/'metadata.json').read_text());binary=(root/'agent.bin').read_bytes()
if len(binary)!=a['size'] or hashlib.sha256(binary).hexdigest()!=a['sha256']: raise SystemExit('Release validation failed: stage=hash/size')
PY
version=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["version"])' "$tmp/metadata.json")
implementation=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("implementation","rust"))' "$tmp/metadata.json")
case "$implementation" in rust) ;; *) echo 'Public Linux installer requires the accepted native release matrix.' >&2; exit 2;; esac
install_root=${XDG_DATA_HOME:-$HOME/.local/share}/commandcore-agent
state_root=${XDG_CONFIG_HOME:-$HOME/.config}/commandcore
bin_root=${COMMANDCORE_AGENT_BIN_DIR:-$HOME/.local/bin}
unit_root=$systemd_config_home/systemd/user
case "$install_root$state_root$unit_root$bin_root" in *'"'*|*'%'*|*'\'*) echo 'Unsupported installation path characters.' >&2; exit 2;; esac
python3 - "$install_root" "$state_root" "$unit_root" "$bin_root" <<'PY'
import sys
if any(any(ord(c)<32 for c in p) for p in sys.argv[1:]): raise SystemExit('Unsupported control characters in installation path')
PY
if [ "$service" = yes ]; then
  command -v systemctl >/dev/null || { echo 'systemd user services unavailable; use --no-service.' >&2; exit 2; }
  service_ctl show-environment >/dev/null || { echo 'No running systemd user manager; use --no-service or start a user session.' >&2; exit 2; }
  command -v loginctl >/dev/null || { echo 'loginctl is required for boot persistence.' >&2; exit 2; }
  if [ "$(loginctl show-user "$(id -un)" -p Linger --value)" != yes ]; then
    echo 'Enabling startup persistence for this normal-user service. The Agent remains unprivileged.'
    if ! loginctl enable-linger "$(id -un)"; then
      command -v sudo >/dev/null || { echo 'Local administrator authentication is required to enable user boot persistence.' >&2; exit 2; }
      echo 'Local authentication enables only this user systemd manager at boot; FULL_CONTROL remains disabled.'
      sudo loginctl enable-linger "$(id -un)"
    fi
    [ "$(loginctl show-user "$(id -un)" -p Linger --value)" = yes ] || { echo 'Could not verify boot persistence.' >&2; exit 2; }
  fi
fi
if [ -e "$install_root" ] && [ ! -f "$install_root/.commandcore-install" ]; then echo 'Refusing to overwrite an unrelated installation.' >&2; exit 2; fi
if [ -e "$bin_root/commandcore-agent" ] || [ -L "$bin_root/commandcore-agent" ]; then
  [ "$(readlink "$bin_root/commandcore-agent")" = "$install_root/current/commandcore-agent" ] || { echo 'An unrelated commandcore-agent already exists.' >&2; exit 2; }
fi
if [ -e "$unit_root/$service_name" ]; then
  [ "$(head -n 1 "$unit_root/$service_name")" = '# Managed by CommandCore' ] || { echo 'An unrelated service already exists.' >&2; exit 2; }
fi
mkdir -p "$install_root/releases" "$state_root" "$bin_root"
chmod 700 "$install_root" "$state_root"
printf '%s\n' 'commandcore-agent' > "$install_root/.commandcore-install"
python3 - "$install_root" "$service_name" "$systemd_config_home" "$bin_root" <<'PY'
import json,pathlib,sys
root=pathlib.Path(sys.argv[1]);meta={'service_name':sys.argv[2],'systemd_config_home':sys.argv[3],'bin_root':sys.argv[4]}
path=root/'installation.json'
if path.exists() and json.loads(path.read_text())!=meta: raise SystemExit('Installation namespace differs; refusing a service/path migration')
path.write_text(json.dumps(meta)+'\n')
PY
release=$install_root/releases/$version
if [ -L "$install_root/current" ]; then
  previous=$(readlink "$install_root/current")
  if [ "$previous" != "releases/$version" ]; then
    [ "$upgrade" = yes ] && [ "$service" = yes ] && [ -f "$state_root/agent.json" ] || { echo 'Existing installation: use --upgrade with a running user service for health-gated replacement.' >&2; exit 2; }
    python3 - "$previous" "$version" <<'PY'
import re,sys
def version(value):
    found=re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*))?',value)
    if not found: raise SystemExit('Unsupported release version comparison')
    prerelease=found.group(4)
    identifiers=[]
    for identifier in prerelease.split('.') if prerelease else []:
        if identifier.isdigit():
            if len(identifier)>1 and identifier.startswith('0'): raise SystemExit('Invalid numeric prerelease identifier')
            identifiers.append((0,int(identifier)))
        else: identifiers.append((1,identifier))
    return tuple(map(int,found.group(1,2,3)))+(prerelease is None,tuple(identifiers))
if not sys.argv[1].startswith('releases/') or version(sys.argv[2])<=version(sys.argv[1][9:]): raise SystemExit('Upgrade must be newer than installed release')
PY
  fi
fi
if [ -e "$release" ]; then
  cmp "$tmp/agent.bin" "$release/commandcore-agent" >/dev/null || { echo 'Existing release differs; refusing overwrite.' >&2; exit 2; }
else
  mkdir "$release"
  cp "$tmp/agent.bin" "$release/commandcore-agent"
  chmod 755 "$release/commandcore-agent"
  cp "$tmp/manifest.json" "$release/manifest.json"
fi
mode=fresh
if [ -n "$previous" ]; then
  mode=update
  rollback=$(mktemp -d "$install_root/rollback.XXXXXXXX")
  printf '%s\n' "$previous" > "$rollback/previous-target"
  if [ -f "$unit_root/$service_name" ]; then cp "$unit_root/$service_name" "$rollback/service.unit"; fi
  if [ -f "$state_root/agent.json" ]; then cp "$state_root/agent.json" "$rollback/agent.json"; chmod 600 "$rollback/agent.json"; fi
fi
if [ -e "$install_root/current" ] && [ ! -L "$install_root/current" ]; then echo 'Refusing to replace an unrelated current path.' >&2; exit 2; fi
ln -s "releases/$version" "$install_root/current.new"
mv -Tf "$install_root/current.new" "$install_root/current"
switched=yes
if [ ! -L "$bin_root/commandcore-agent" ]; then ln -s "$install_root/current/commandcore-agent" "$bin_root/commandcore-agent"; fi
if [ "$enroll" = yes ] && [ ! -f "$state_root/agent.json" ]; then
  set --
  if [ -n "$device_name" ]; then set -- --name "$device_name"; fi
  case "$server" in
    http://127.0.0.1:*|http://localhost:*)
      [ "$test_loopback" = yes ] || exit 2
      "$install_root/current/commandcore-agent" enroll "$server" --state "$state_root/agent.json" --no-connect --insecure "$@";;
    *) "$install_root/current/commandcore-agent" enroll "$server" --state "$state_root/agent.json" --no-connect "$@";;
  esac
fi
if [ "$service" = yes ]; then
  command -v systemctl >/dev/null || { echo 'systemd user services unavailable; rerun with --no-service.' >&2; exit 2; }
  mkdir -p "$unit_root"
  cat > "$unit_root/$service_name" <<EOF
# Managed by CommandCore
[Unit]
Description=CommandCore Agent
After=network-online.target
[Service]
ExecStart="$install_root/current/commandcore-agent" run --state "$state_root/agent.json"
Restart=on-failure
RestartSec=5
KillMode=process
NoNewPrivileges=true
[Install]
WantedBy=default.target
EOF
  service_ctl daemon-reload
  service_ctl enable "$service_name"
  if [ -f "$state_root/agent.json" ]; then
    activated=$(date +%s)
    service_ctl restart "$service_name"
    if [ -f "$state_root/agent.json" ]; then
      if ! python3 - "$state_root/health.json" "$version" "$activated" <<'PY'
import json,pathlib,sys,time
deadline=time.time()+45
while time.time()<deadline:
    try:
        health=json.loads(pathlib.Path(sys.argv[1]).read_text())
        if health.get('connected') is True and health.get('version')==sys.argv[2] and health.get('observed_at_unix',0)>float(sys.argv[3]): raise SystemExit(0)
    except (OSError,ValueError): pass
    time.sleep(.5)
raise SystemExit(1)
PY
      then
        echo 'Candidate failed fresh connection health.' >&2
        exit 1
      fi
    fi
  fi
fi
complete=yes
printf 'Installed signed Agent %s. Identity preserved at %s\n' "$version" "$state_root/agent.json"
printf 'Implementation: %s\nArchitecture: %s\nSigned manifest version: %s\nInstallation mode: %s\n' "$implementation" "$arch" "$version" "$mode"
if [ -n "$rollback" ]; then printf 'Rollback backup: %s\n' "$rollback"; fi
if [ "$service" = yes ] && [ -n "${activated:-}" ]; then
  if python3 - "$state_root/health.json" "$version" "$activated" <<'PY'
import json,pathlib,sys
try:
    health=json.loads(pathlib.Path(sys.argv[1]).read_text())
    connected=health.get('connected') is True and health.get('version')==sys.argv[2] and health.get('observed_at_unix',0)>float(sys.argv[3])
except (OSError,ValueError): connected=False
raise SystemExit(0 if connected else 1)
PY
  then
    printf 'Agent installed and connected.\n'
  else
    printf 'Installation complete. Check status for connection progress.\n'
  fi
fi
printf 'Add %s to PATH if needed.\n' "$bin_root"
printf '\nCheck status:\ncommandcore-agent status\n\nWatch live CommandCore activity:\ncommandcore-agent activity\n'
if [ "$service_name" != commandcore-agent.service ]; then
  printf 'Custom service: use --service %s with status and activity.\n' "$service_name"
fi
