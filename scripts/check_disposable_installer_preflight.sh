#!/bin/sh
# Offline, read-only, non-root installer-preflight regression.
set -eu
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
image="${COMMANDCORE_INSTALL_TEST_IMAGE:-commandcore-v1-install-test-tools:local}"
exec docker run --rm   --network none   --read-only   --tmpfs /tmp:rw,nosuid,size=128m   --security-opt no-new-privileges   --cap-drop ALL   --user 10001:10001   --entrypoint sh   -e PYTHONDONTWRITEBYTECODE=1   -e HOME=/tmp   -v "$repo:/source:ro"   -w /source   "$image" -c 'python3 -m unittest discover -s tests -p test_linux_install_state_preflight.py -q'
