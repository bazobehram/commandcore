#!/bin/sh
# Run complete installer lifecycle in a disposable fixture container.
set -eu
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
image="${COMMANDCORE_INSTALL_TEST_IMAGE:-commandcore-v1-install-test-tools:local}"
exec docker run --rm \
 --network none --read-only --tmpfs /tmp:rw,nosuid,size=256m \
 --security-opt no-new-privileges --cap-drop ALL \
 --cap-add CHOWN --cap-add SETUID --cap-add SETGID \
 --cap-add FOWNER --cap-add DAC_OVERRIDE \
 --entrypoint sh -e PYTHONDONTWRITEBYTECODE=1 \
 -v "$repo:/source:ro" -w /source "$image" \
 -c 'python3 scripts/installer_smoke.py'
