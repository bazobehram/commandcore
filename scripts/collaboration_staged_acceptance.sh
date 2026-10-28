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
if [ -d /tmp/cc-webauthn-fido2/fido2 ]; then
  PYTHONPATH="/tmp/cc-webauthn-fido2:$PYTHONPATH" python3 -m unittest discover -s tests -p test_collaboration_registration_fido2.py -q
  PYTHONPATH="/tmp/cc-webauthn-fido2:$PYTHONPATH" python3 -m unittest discover -s tests -p test_collaboration_registration_ceremony.py -q
  PYTHONPATH="/tmp/cc-webauthn-fido2:$PYTHONPATH" python3 -m unittest discover -s tests -p test_collaboration_registration_to_review.py -q
else
  echo "STAGING_ERROR: missing isolated python-fido2 dependency" >&2
  exit 1
fi
docker run --rm --network none -v "$PWD":/work:ro -w /work/apps/server -e PYTHONPATH=/work/apps/server tiangolo/uvicorn-gunicorn-fastapi:python3.11 python /work/tests/test_collaboration_review_routes.py
docker run --rm --network none -v "$PWD":/work:ro -w /work/apps/server -e PYTHONPATH=/work/apps/server tiangolo/uvicorn-gunicorn-fastapi:python3.11 python /work/tests/test_collaboration_preview_http.py
# Exercise the actual browser JS in isolated headless Chrome on the staging host.
NODE_BIN="${COMMANDCORE_STAGING_NODE:-/home/bazobehram/.nvm/versions/node/v24.13.0/bin/node}"
if [ ! -x "$NODE_BIN" ]; then
  echo "STAGING_ERROR: browser QA Node runtime missing" >&2
  exit 1
fi
"$NODE_BIN" tests/ui/test_webauthn_enroll.cjs
"$NODE_BIN" tests/ui/test_webauthn_enroll_success.cjs
"$NODE_BIN" tests/ui/test_webauthn_review.cjs
echo 'COLLABORATION_STAGED_ACCEPTANCE_PASS (production approval remains disabled)'
