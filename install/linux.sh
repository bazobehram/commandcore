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
prepare_full_control=${COMMANDCORE_PREPARE_FULL_CONTROL:-auto}
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
    --prepare-full-control) prepare_full_control=yes; shift;;
    --no-full-control-preparation) prepare_full_control=no; shift;;
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
  rm -f "$tmp/manifest.json" "$tmp/canonical.json" "$tmp/signature.bin" "$tmp/public.der" "$tmp/public.pem" "$tmp/metadata.json" "$tmp/agent.bin" "$tmp/helper-bootstrap.py"
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
# Preserve the original verified rc7 release during installer-only recovery.
# Its legacy product ID is pinned by SHA-256 to avoid exposing old branding in
# the public source. Manifest signature and artifact hash remain mandatory.
import hashlib
product=m.get('product'); version=m.get('version')
legacy_rc7=version=='0.9.0-rc7' and isinstance(product,str) and hashlib.sha256(product.encode()).hexdigest()=='6c72f9dc3d73777e2e9677ad030fa6f3863b0e98a0c63293b2ad36b16e46ca9d'
if m.get('schema_version')!=1 or not (product=='commandcore-agent' or legacy_rc7): raise SystemExit('Wrong release product/schema')
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
  python3 - "$unit_root/$service_name" "$install_root" "$state_root" <<'PY_UNIT'
import hashlib,pathlib,sys
unit=pathlib.Path(sys.argv[1])
if unit.is_symlink() or not unit.is_file(): raise SystemExit('Refusing an unexpected service path')
lines=unit.read_text().splitlines()
expected=f'ExecStart="{sys.argv[2]}/current/commandcore-agent" run --state "{sys.argv[3]}/agent.json"'
legacy_hash='79ed9052a1390363c3969b7ea374d50df9dbe9cef7807d98c5a1f89752bb70b6'
first=lines[0] if lines else ''
legacy=hashlib.sha256(first.encode()).hexdigest()==legacy_hash
marker=pathlib.Path(sys.argv[2])/'.commandcore-install'
managed=marker.is_file() and not marker.is_symlink() and marker.read_text().strip()=='commandcore-agent'
if first!='# Managed by CommandCore' and not (legacy and expected in lines and managed):
    raise SystemExit('An unrelated service already exists.')
PY_UNIT
fi
# Match the Agent's managed-job trust boundary before enrollment. Do not
# silently chmod an existing HOME, symlink, or shared parent directory.
python3 - "$state_root" <<'PY_CHECK_DIR'
import os, pathlib, stat, sys
path = pathlib.Path(sys.argv[1]).absolute()
uid = os.geteuid()
for ancestor in reversed((path.parent, *path.parent.parents)):
    if not ancestor.exists() and not ancestor.is_symlink():
        # A fresh user may not have ~/.config yet. Create missing parents
        # securely; never repair preexisting shared or foreign-owned parents.
        ancestor.mkdir(mode=0o700)
    info = ancestor.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, uid):
        raise SystemExit(f"Unsafe CommandCore state ancestor: {ancestor} (owner mismatch or symlink)")
    if info.st_mode & 0o022 and not (info.st_uid == 0 and info.st_mode & stat.S_ISVTX):
        # A normal user's ~/.config must not be writable by other users.
        # Repair this one familiar, user-owned location only; never chmod
        # HOME, a shared ancestor, a symlink or a foreign-owned directory.
        if ancestor == pathlib.Path.home() / '.config' and info.st_uid == uid and not ancestor.is_symlink():
            ancestor.chmod(info.st_mode & ~0o022)
        else:
            raise SystemExit(f"Unsafe CommandCore state ancestor: {ancestor} (writable by group/others)")
if path.is_symlink():
    raise SystemExit(f"Unsafe CommandCore state directory symlink: {path}")
if path.exists():
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != uid:
        raise SystemExit(f"Unsafe CommandCore state directory: {path} (not owned by current user)")
    # This is the CommandCore-owned state directory, so tightening is safe.
    path.chmod(0o700)
else:
    path.mkdir(mode=0o700)
# Managed jobs belong to CommandCore. Repair legacy directory modes only
# when ownership and type are verified; never follow symlinks.
for child in (path / 'managed-jobs',):
    if child.is_symlink():
        raise SystemExit(f"Unsafe CommandCore managed-job symlink: {child}")
    if child.exists():
        info = child.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != uid:
            raise SystemExit(f"Unsafe CommandCore managed-job directory: {child}")
        child.chmod(0o700)
        for device_dir in child.iterdir():
            if device_dir.is_symlink():
                raise SystemExit(f"Unsafe CommandCore device-job symlink: {device_dir}")
            info = device_dir.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != uid:
                raise SystemExit(f"Unsafe CommandCore device-job directory: {device_dir}")
            device_dir.chmod(0o700)
PY_CHECK_DIR
mkdir -p "$install_root/releases" "$bin_root"
chmod 700 "$install_root"
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
# A signed same-version reinstall with a connected, healthy user Agent is a
# true no-op: do not restart the Agent or accumulate rollback snapshots. Only
# skip after the immutable release binary was checked above with cmp.
agent_unchanged=no
if [ "$previous" = "releases/$version" ] && [ "$service" = yes ] &&
  [ -f "$state_root/agent.json" ] &&
  service_ctl is-active --quiet "$service_name" 2>/dev/null &&
  python3 - "$state_root/health.json" "$version" <<'PY_AGENT_CURRENT'
import json,pathlib,sys
try:
    current=json.loads(pathlib.Path(sys.argv[1]).read_text())
    good=(current.get('connected') is True and
          current.get('version')==sys.argv[2])
except (OSError,ValueError,TypeError):
    good=False
raise SystemExit(0 if good else 1)
PY_AGENT_CURRENT
then
  agent_unchanged=yes
fi
if [ "$agent_unchanged" = yes ]; then
  mode=unchanged
  echo 'Verified signed Agent release is already installed and connected; no restart or rollback required.'
else
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

# Optional one-time, locally approved helper preparation in the SAME terminal
# invocation. The main Agent installation is already healthy and committed;
# helper failure never reenrolls or removes an existing identity.
if [ "$prepare_full_control" = auto ]; then
  if [ -n "${COMMANDCORE_HELPER_RELEASE_URL:-}" ] && [ -n "${COMMANDCORE_HELPER_RELEASE_PUBLIC_KEY_B64:-}" ]; then
    prepare_full_control=yes
  else
    prepare_full_control=no
  fi
fi
if [ "$prepare_full_control" = yes ]; then
  : "${COMMANDCORE_HELPER_RELEASE_URL:?Set the signed helper release HTTPS URL}"
  : "${COMMANDCORE_HELPER_RELEASE_PUBLIC_KEY_B64:?Pin the independently trusted helper public key}"
  : "${COMMANDCORE_HELPER_RELEASE_VERSION:?Select the independently signed helper release version}"
  : "${COMMANDCORE_HELPER_BOOTSTRAP_SHA256:?Pin the reviewed helper bootstrap script SHA256}"
  : "${COMMANDCORE_HELPER_BOOTSTRAP_URL:?Pin a trusted helper bootstrap source HTTPS URL}"
  # Repeat installs must not attempt to reinstall an already authenticated,
  # matching helper. Query capabilities through the freshly release-verified
  # Agent (not a user-controlled PATH command), and verify the root service is
  # running. A missing, unhealthy or older helper is NEVER called successful.
  if [ "$service" = yes ] && systemctl is-active --quiet commandcore-helper.service 2>/dev/null &&
    "$install_root/current/commandcore-agent" capabilities | python3 -c '
import json,sys
try:
    data=json.load(sys.stdin)
    good=(data.get("privileged_helper") is True and
          data.get("privileged_helper_version")==sys.argv[1] and
          data.get("local_max_permission_profile")=="FULL_CONTROL" and
          data.get("configured_max_permission_profile")=="FULL_CONTROL" and
          data.get("policy_error") is None)
except (ValueError,TypeError):
    good=False
raise SystemExit(0 if good else 1)
' "$COMMANDCORE_HELPER_RELEASE_VERSION"; then
    echo 'Full Control helper already installed and healthy at the requested signed version; no administrator prompt or helper changes needed.'
  else
    # An existing but unhealthy/different helper must be handled by a
    # separately reviewed repair/upgrade path, not by overwriting root files.
    if systemctl list-unit-files commandcore-helper.service --no-legend --no-pager 2>/dev/null | grep -q '^commandcore-helper.service'; then
      echo 'FULL_CONTROL_REPAIR_REQUIRED: existing helper is unhealthy or version differs. Agent remains connected; use a reviewed helper repair/upgrade procedure.' >&2
      exit 6
    fi
    fetch "$COMMANDCORE_HELPER_BOOTSTRAP_URL" "$tmp/helper-bootstrap.py"
    python3 - "$tmp/helper-bootstrap.py" "$COMMANDCORE_HELPER_BOOTSTRAP_SHA256" <<'PY_HELPER_HASH'
import hashlib,pathlib,re,sys
expected=sys.argv[2]
if not re.fullmatch(r'[0-9a-f]{64}',expected): raise SystemExit('Invalid pinned helper bootstrap SHA256')
actual=hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest()
if actual!=expected: raise SystemExit('Helper bootstrap code failed pinned integrity check')
PY_HELPER_HASH
    python_minor=$(python3 -c 'import sys;print(str(sys.version_info.major)+"."+str(sys.version_info.minor))')
    echo 'Requesting one-time LOCAL administrator approval to prepare Full Control capability.'
    if python3 "$tmp/helper-bootstrap.py" \
      --release-url "$COMMANDCORE_HELPER_RELEASE_URL" \
      --trusted-public-key-b64 "$COMMANDCORE_HELPER_RELEASE_PUBLIC_KEY_B64" \
      --version "$COMMANDCORE_HELPER_RELEASE_VERSION" \
      --architecture "$arch" \
      --python-minor "$python_minor" \
      --agent-user "$(id -un)"; then
      echo 'Local Full Control helper preparation completed. Active server/account permission remains unchanged.'
    else
      echo 'FULL_CONTROL_SETUP_INCOMPLETE: existing Agent is installed and remains at its previous safe access.' >&2
      exit 6
    fi
  fi
else
  echo 'Local Full Control helper not prepared by this invocation; Standard operation remains available.'
fi
