#!/bin/sh
# Staging-only acceptance: do not deploy, mint production permits, or contact agents.
set -eu
cd "$(dirname "$0")/.."
export PYTHONPATH="$PWD/apps/server"
for suite in test_collaboration_agent_draft_order.py test_collaboration_authorization.py test_collaboration_confirmed_delivery.py test_collaboration_human_assertion.py test_collaboration_mcp_permit_boundary.py test_collaboration_permit_issuer.py test_collaboration_review_challenge.py test_collaboration_review_session.py test_collaboration_trusted_dispatch.py test_collaboration_trusted_preview.py test_collaboration_webauthn_assertion.py test_collaboration_webauthn_credentials.py test_collaboration_webauthn_review.py test_collaboration_registration_preflight.py; do
  python3 -m unittest discover -s tests -p "$suite" -q
done
# Standards-library WebAuthn checks use an isolated test dependency directory.
# Never treat this as production dependency provisioning.
FIDO2_TEST_PATH="${COMMANDCORE_STAGING_FIDO2_PATH:-/tmp/cc-webauthn-fido2}"
if [ -d "$FIDO2_TEST_PATH/fido2" ]; then
  FIDO2_PYTHONPATH="$FIDO2_TEST_PATH:$PYTHONPATH"
else
  FIDO2_PYTHONPATH="$PYTHONPATH"
fi
if ! PYTHONPATH="$FIDO2_PYTHONPATH" python3 -c 'import fido2.server' 2>/dev/null; then
  echo "STAGING_ERROR: python-fido2 unavailable (set COMMANDCORE_STAGING_FIDO2_PATH or install in test environment)" >&2
  exit 1
fi
for suite in test_collaboration_registration_fido2.py test_collaboration_registration_ceremony.py test_collaboration_registration_to_review.py; do
  PYTHONPATH="$FIDO2_PYTHONPATH" python3 -m unittest discover -s tests -p "$suite" -q
done
docker run --rm --network none -v "$PWD":/work:ro -w /work/apps/server -e PYTHONPATH=/work/apps/server tiangolo/uvicorn-gunicorn-fastapi:python3.11 python /work/tests/test_collaboration_review_routes.py
docker run --rm --network none -v "$PWD":/work:ro -w /work/apps/server -e PYTHONPATH=/work/apps/server tiangolo/uvicorn-gunicorn-fastapi:python3.11 python /work/tests/test_collaboration_preview_http.py
# Exercise the actual browser JS in isolated headless Chrome on the staging host.
NODE_BIN="${COMMANDCORE_STAGING_NODE:-}"
if [ -z "$NODE_BIN" ]; then
  NODE_BIN=$(command -v node || true)
fi
if [ -z "$NODE_BIN" ] && [ -x /home/bazobehram/.nvm/versions/node/v24.13.0/bin/node ]; then
  NODE_BIN=/home/bazobehram/.nvm/versions/node/v24.13.0/bin/node
fi
if [ ! -x "$NODE_BIN" ]; then
  echo "STAGING_ERROR: browser QA Node runtime missing" >&2
  exit 1
fi
"$NODE_BIN" tests/ui/test_webauthn_enroll.cjs
"$NODE_BIN" tests/ui/test_webauthn_enroll_success.cjs
"$NODE_BIN" tests/ui/test_webauthn_review.cjs
"$NODE_BIN" tests/ui/test_webauthn_review_page.cjs
NATIVE_FIXTURE_DIR=$(mktemp -d)
trap 'rm -rf "$NATIVE_FIXTURE_DIR"' EXIT
export COMMANDCORE_NATIVE_ASSERTION_FIXTURE="$NATIVE_FIXTURE_DIR/assertion.json"
"$NODE_BIN" tests/ui/test_webauthn_virtual_authenticator.cjs
PYTHONPATH=apps/server python3 tests/ui/verify_webauthn_native_assertion.py
# End-to-end native browser registration against the actual staging ceremony.
NATIVE_REG_DIR=$(mktemp -d)
trap 'rm -rf "$NATIVE_FIXTURE_DIR" "$NATIVE_REG_DIR"' EXIT
export CC_NATIVE_REG_DB="$NATIVE_REG_DIR/state.sqlite"
export CC_NATIVE_REG_OPTIONS="$NATIVE_REG_DIR/options.json"
export CC_NATIVE_REG_RESULT="$NATIVE_REG_DIR/result.json"
PYTHONPATH="$FIDO2_PYTHONPATH" python3 tests/ui/native_registration_begin.py > "$CC_NATIVE_REG_OPTIONS"
"$NODE_BIN" tests/ui/native_registration_chrome.cjs
PYTHONPATH="$FIDO2_PYTHONPATH" python3 tests/ui/native_registration_finish.py
echo 'COLLABORATION_STAGED_ACCEPTANCE_PASS (production approval remains disabled)'
