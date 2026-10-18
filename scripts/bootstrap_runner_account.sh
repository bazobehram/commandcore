#!/usr/bin/env bash
# Explicit operator-only provisioning; never invoked by PR CI or release jobs.
set -euo pipefail
if [[ "${1:-}" != "--apply" ]]; then
  echo "DRY RUN: this script only provisions a non-privileged local account."
  echo "Requires local root operator: sudo bash scripts/bootstrap_runner_account.sh --apply"
  exit 0
fi
if [[ "${EUID}" -ne 0 ]]; then
  echo "ERROR: run with explicit local root authorization" >&2; exit 1
fi
runner=cc-gh-runner
if ! id "$runner" >/dev/null 2>&1; then
  useradd --create-home --shell /bin/bash --user-group "$runner"
fi
for group in docker sudo wheel lxd adm; do
  if id -nG "$runner" | tr ' ' '\n' | grep -Fxq "$group"; then
    echo "BLOCKED: $runner belongs to privileged group $group" >&2; exit 1
  fi
done
if id -u "$runner" | grep -qx 0; then echo "BLOCKED: root runner" >&2; exit 1; fi
install -d -m 0700 -o "$runner" -g "$runner" "/home/$runner/actions-runner"
echo "ACCOUNT READY: isolated local identity created. No token, service or Docker permissions configured."
