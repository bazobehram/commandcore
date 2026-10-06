#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="$(cat "$ROOT/VERSION")"
OUT="${1:-$ROOT/../commandcore-v${VERSION}.zip}"
SHA_OUT="${OUT%.zip}.sha256"
PREFIX="commandcore-v${VERSION}/"
rm -f "$OUT" "$SHA_OUT"

if git -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1 \
  && git -C "$ROOT" diff --quiet --ignore-submodules HEAD -- \
  && [[ -z "$(git -C "$ROOT" status --porcelain --untracked-files=normal)" ]]; then
  git -C "$ROOT" archive --format=zip --prefix="$PREFIX" HEAD >"$OUT"
else
  # Source-ZIP fallback for a tree without .git. Exclude deployment state and
  # local credentials explicitly.
  PARENT="$(dirname "$ROOT")"
  BASE="$(basename "$ROOT")"
  (
    cd "$PARENT"
    zip -X -qr "$OUT" "$BASE" \
      -x '*/__pycache__/*' '*/.pytest_cache/*' '*/.git/*' '*/.git' \
         '*/.venv/*' '*/venv/*' '*/commandcore.sqlite3' '*/.env' \
         '*/agent.json' '*/agent-state.json' '*/helper.key' '*.pyc' '*.pyo' \
      -x '*/target/*' '*/.ruff_cache/*' '*/enrollment.pending.json' '*.egg-info/*'
  )
fi
python3 "$ROOT/scripts/release_check.py" "$OUT"
(
  cd "$(dirname "$OUT")"
  sha256sum "$(basename "$OUT")" >"$(basename "$SHA_OUT")"
)
printf '%s\n%s\n' "$OUT" "$SHA_OUT"
