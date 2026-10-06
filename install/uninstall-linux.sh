#!/bin/sh
set -eu
install_root=${XDG_DATA_HOME:-$HOME/.local/share}/commandcore-agent
[ -f "$install_root/.commandcore-install" ] || { echo 'No managed CommandCore installation found.' >&2; exit 2; }
[ "$(cat "$install_root/.commandcore-install")" = commandcore-agent ] || exit 2
service_name=$(python3 - "$install_root" <<'PY'
import json,pathlib,re,sys
p=pathlib.Path(sys.argv[1])/'installation.json'
name=json.loads(p.read_text())['service_name'] if p.exists() else 'commandcore-agent.service'
if not re.fullmatch(r'commandcore-agent[A-Za-z0-9_.-]*\.service',name): raise SystemExit('Invalid managed service name')
print(name)
PY
)
systemd_config_home=$(python3 - "$install_root" <<'PY'
import json,os,pathlib,sys
p=pathlib.Path(sys.argv[1])/'installation.json'
print(json.loads(p.read_text())['systemd_config_home'] if p.exists() else os.environ.get('XDG_CONFIG_HOME',str(pathlib.Path.home()/'.config')))
PY
)
bin_root=$(python3 - "$install_root" <<'PY'
import json,pathlib,sys
p=pathlib.Path(sys.argv[1])/'installation.json'
print(json.loads(p.read_text())['bin_root'] if p.exists() else str(pathlib.Path.home()/'.local/bin'))
PY
)
unit=$systemd_config_home/systemd/user/$service_name
bin=$bin_root/commandcore-agent
if [ -e "$unit" ]; then
  [ "$(head -n 1 "$unit")" = '# Managed by CommandCore' ] || { echo 'Refusing to remove an unrelated service.' >&2; exit 2; }
  XDG_CONFIG_HOME="$systemd_config_home" systemctl --user disable --now "$service_name"
  rm -f "$unit"
  XDG_CONFIG_HOME="$systemd_config_home" systemctl --user daemon-reload
fi
if [ -L "$bin" ] && [ "$(readlink "$bin")" = "$install_root/current/commandcore-agent" ]; then rm -f "$bin"; fi
python3 - "$install_root" <<'PY'
import os,pathlib,shutil,sys
target=pathlib.Path(sys.argv[1])
expected=pathlib.Path(os.environ.get('XDG_DATA_HOME',str(pathlib.Path.home()/'.local/share')))/'commandcore-agent'
if target.is_symlink() or target.resolve()!=expected.absolute() or target.name!='commandcore-agent': raise SystemExit('Unsafe uninstall target')
if (target/'.commandcore-install').read_text().strip()!='commandcore-agent': raise SystemExit('Not a managed installation')
shutil.rmtree(target)
PY
echo 'Agent removed. Device identity remains in the CommandCore configuration directory for deliberate recovery. Revoke the device in the panel before deleting its identity.'
