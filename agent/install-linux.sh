#!/usr/bin/env bash
set -euo pipefail

PREFIX="${COMMANDCORE_AGENT_PREFIX:-/opt/commandcore-agent}"
SERVICE_USER="${COMMANDCORE_AGENT_USER:-commandcore}"
MAX_PROFILE="${COMMANDCORE_MAX_PERMISSION_PROFILE:-STANDARD}"
UPDATE_PUBLIC_KEY="${COMMANDCORE_UPDATE_PUBLIC_KEY_B64:-}"
UPDATE_MANIFEST_ORIGIN="${COMMANDCORE_UPDATE_MANIFEST_ORIGIN:-}"
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION="0.9.0-rc7"
PY_RELEASE_ID="${VERSION}-python"
RELEASE_DIR="$PREFIX/releases/$PY_RELEASE_ID"
HELPER_DIR="$PREFIX/helper"
NATIVE_BINARY=""
ACTIVATE_NATIVE="false"
NATIVE_RELEASE_ID="${VERSION}-rust"

usage(){
  cat <<EOF
Usage: sudo ./install-linux.sh [--max-profile READ_ONLY|STANDARD|FULL_CONTROL] [--update-public-key-b64 BASE64] [--update-manifest-origin HTTPS_ORIGIN] [--native-binary PATH] [--activate-native]

Installs the unprivileged network Agent in a versioned release layout. The
stable launcher follows $PREFIX/current so a verified native Agent can be
installed as a versioned release, activated atomically and rolled back. Python
remains the default unless --activate-native is explicitly supplied. The privileged helper/updater runtime is
installed separately and never follows the Agent release symlink.
EOF
}
while [[ $# -gt 0 ]]; do
  case "$1" in
    --max-profile) MAX_PROFILE="${2:-}"; shift 2;;
    --update-public-key-b64) UPDATE_PUBLIC_KEY="${2:-}"; shift 2;;
    --update-manifest-origin) UPDATE_MANIFEST_ORIGIN="${2:-}"; shift 2;;
    --native-binary) NATIVE_BINARY="${2:-}"; shift 2;;
    --activate-native) ACTIVATE_NATIVE="true"; shift;;
    -h|--help) usage; exit 0;;
    *) echo "Unknown argument: $1" >&2; usage; exit 2;;
  esac
done
MAX_PROFILE="${MAX_PROFILE^^}"
case "$MAX_PROFILE" in READ_ONLY|STANDARD|FULL_CONTROL) ;; *) echo "Invalid --max-profile: $MAX_PROFILE" >&2; exit 2;; esac

if [[ $EUID -ne 0 ]]; then echo "Run as root: sudo ./install-linux.sh" >&2; exit 1; fi
for unit in /etc/systemd/system/commandcore-agent.service /etc/systemd/system/commandcore-helper.service; do
  if [[ -e "$unit" || -L "$unit" ]]; then
    [[ ! -L "$unit" ]] && grep -q 'Description=CommandCore' "$unit" || { echo "Refusing unrelated or linked service: $unit" >&2; exit 2; }
  fi
done
if [[ "$MAX_PROFILE" == FULL_CONTROL ]]; then
  echo 'FULL_CONTROL permits root administration through authenticated local IPC. This is an explicit local privileged opt-in; server grants remain separate.' >&2
fi
if ! command -v python3 >/dev/null; then echo "python3 >= 3.11 is required for the reference Agent" >&2; exit 1; fi
if ! id "$SERVICE_USER" >/dev/null 2>&1; then
  useradd --system --create-home --home-dir /var/lib/commandcore --shell /usr/sbin/nologin "$SERVICE_USER"
fi
mkdir -p "$PREFIX/releases" "$RELEASE_DIR" "$HELPER_DIR" /etc/commandcore /var/lib/commandcore /var/lib/commandcore/updates /var/log/commandcore

# Versioned Python reference release.
python3 -m venv "$RELEASE_DIR/venv"
"$RELEASE_DIR/venv/bin/pip" install --upgrade pip
"$RELEASE_DIR/venv/bin/pip" install "$SOURCE_DIR"
cat >"$RELEASE_DIR/release.json" <<EOF
{"schema_version":1,"version":"$VERSION","implementation":"python"}
EOF
chmod 0644 "$RELEASE_DIR/release.json"

# Optional prebuilt Rust candidate. The source ZIP intentionally does not ship
# an unverified binary; CI/release infrastructure must build and verify it.
if [[ -n "$NATIVE_BINARY" ]]; then
  if [[ ! -f "$NATIVE_BINARY" || ! -x "$NATIVE_BINARY" ]]; then
    echo "--native-binary must point to an executable file" >&2; exit 2
  fi
  NATIVE_DIR="$PREFIX/releases/$NATIVE_RELEASE_ID"
  mkdir -p "$NATIVE_DIR"
  install -o root -g root -m 0755 "$NATIVE_BINARY" "$NATIVE_DIR/commandcore-agent"
  "$NATIVE_DIR/commandcore-agent" --version >/dev/null
  "$NATIVE_DIR/commandcore-agent" capabilities >/dev/null
  cat >"$NATIVE_DIR/release.json" <<EOF
{"schema_version":1,"version":"$VERSION","implementation":"rust"}
EOF
  chmod 0644 "$NATIVE_DIR/release.json"
fi

# Stable privileged helper/updater runtime. This does not move when `current`
# switches to a native Agent candidate, preserving a known-good rollback path.
python3 -m venv "$HELPER_DIR/venv"
"$HELPER_DIR/venv/bin/pip" install --upgrade pip
"$HELPER_DIR/venv/bin/pip" install "$SOURCE_DIR"

if [[ "$ACTIVATE_NATIVE" == "true" ]]; then
  if [[ -z "$NATIVE_BINARY" ]]; then echo "--activate-native requires --native-binary" >&2; exit 2; fi
  ln -sfn "releases/$NATIVE_RELEASE_ID" "$PREFIX/current"
else
  ln -sfn "releases/$PY_RELEASE_ID" "$PREFIX/current"
fi

cat >/usr/local/bin/commandcore-agent <<WRAP
#!/usr/bin/env bash
set -e
if [[ -x "$PREFIX/current/commandcore-agent" ]]; then
  exec "$PREFIX/current/commandcore-agent" "\$@"
fi
exec "$PREFIX/current/venv/bin/commandcore-agent" "\$@"
WRAP
cat >/usr/local/bin/commandcore-helper <<WRAP
#!/usr/bin/env bash
exec "$HELPER_DIR/venv/bin/commandcore-helper" "\$@"
WRAP
cat >/usr/local/bin/commandcore-updater <<WRAP
#!/usr/bin/env bash
exec "$HELPER_DIR/venv/bin/commandcore-agent" "\$@"
WRAP
chmod 0755 /usr/local/bin/commandcore-agent /usr/local/bin/commandcore-helper /usr/local/bin/commandcore-updater

"$HELPER_DIR/venv/bin/commandcore-helper" init-policy \
  --agent-user "$SERVICE_USER" \
  --max-profile "$MAX_PROFILE" \
  --policy-file /etc/commandcore/agent-policy.json \
  --secret-file /etc/commandcore/helper.key \
  --update-public-key-b64 "$UPDATE_PUBLIC_KEY" \
  ${UPDATE_MANIFEST_ORIGIN:+--update-manifest-origin "$UPDATE_MANIFEST_ORIGIN"} >/dev/null

cat >/etc/systemd/system/commandcore-helper.service <<UNIT
[Unit]
Description=CommandCore Privileged Helper
After=local-fs.target
Before=commandcore-agent.service

[Service]
Type=simple
User=root
Group=root
Environment=COMMANDCORE_AGENT_POLICY=/etc/commandcore/agent-policy.json
Environment=COMMANDCORE_HELPER_SECRET=/etc/commandcore/helper.key
Environment=COMMANDCORE_HELPER_SOCKET=/run/commandcore/helper.sock
Environment=COMMANDCORE_HELPER_SOCKET_GROUP=$SERVICE_USER
Environment=COMMANDCORE_HELPER_AUDIT=/var/log/commandcore/helper-audit.jsonl
Environment=COMMANDCORE_AGENT_INSTALL_ROOT=$PREFIX
Environment=COMMANDCORE_UPDATE_STAGE_DIR=/var/lib/commandcore/updates
Environment=COMMANDCORE_AGENT_HEALTH_FILE=/run/commandcore-agent/health.json
Environment=COMMANDCORE_AGENT_SERVICE=commandcore-agent
ExecStart=/usr/local/bin/commandcore-helper serve
Restart=on-failure
RestartSec=2
RuntimeDirectory=commandcore
RuntimeDirectoryMode=0755
LogsDirectory=commandcore
LogsDirectoryMode=0750
PrivateTmp=true
ProtectHome=false

[Install]
WantedBy=multi-user.target
UNIT

cat >/etc/systemd/system/commandcore-agent.service <<UNIT
[Unit]
Description=CommandCore Agent
After=network-online.target commandcore-helper.service
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
Environment=COMMANDCORE_AGENT_STATE=/var/lib/commandcore/agent.json
Environment=COMMANDCORE_AGENT_POLICY=/etc/commandcore/agent-policy.json
Environment=COMMANDCORE_HELPER_SECRET=/etc/commandcore/helper.key
Environment=COMMANDCORE_HELPER_SOCKET=/run/commandcore/helper.sock
Environment=COMMANDCORE_AGENT_HEALTH_FILE=/run/commandcore-agent/health.json
ExecStart=/usr/local/bin/commandcore-agent run
Restart=always
RestartSec=3
RuntimeDirectory=commandcore-agent
RuntimeDirectoryMode=0750
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=false
ReadWritePaths=/var/lib/commandcore /run/commandcore-agent

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
chown -R "$SERVICE_USER:$SERVICE_USER" /var/lib/commandcore
chown root:root /etc/commandcore/agent-policy.json
chmod 0644 /etc/commandcore/agent-policy.json
chown root:"$SERVICE_USER" /etc/commandcore/helper.key
chmod 0640 /etc/commandcore/helper.key

if [[ "$MAX_PROFILE" == "FULL_CONTROL" ]]; then
  systemctl enable commandcore-helper
  systemctl restart commandcore-helper
else
  systemctl disable --now commandcore-helper >/dev/null 2>&1 || true
fi

cat <<MSG
Installed CommandCore Agent v$VERSION (Python reference + optional Rust candidate).
Local maximum permission profile: $MAX_PROFILE
Stable release pointer: $PREFIX/current
Python release: releases/$PY_RELEASE_ID
Rust candidate: ${NATIVE_BINARY:+releases/$NATIVE_RELEASE_ID}

Enroll as the service user before enabling the Agent:
  sudo -u $SERVICE_USER COMMANDCORE_AGENT_STATE=/var/lib/commandcore/agent.json \
    commandcore-agent enroll <TOKEN> --control-url <API_URL> --agent-url <WSS_URL>

Then:
  sudo systemctl enable --now commandcore-agent

Safe native rollout commands use the stable updater runtime:
  sudo commandcore-updater update-activate ...
  sudo commandcore-updater update-rollback ...
  commandcore-updater update-status

Check local authority/helper state:
  sudo -u $SERVICE_USER COMMANDCORE_AGENT_STATE=/var/lib/commandcore/agent.json commandcore-agent status
MSG
