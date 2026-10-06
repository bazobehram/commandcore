#!/usr/bin/env bash
python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(48))
PY
