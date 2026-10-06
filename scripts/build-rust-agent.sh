#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:-$ROOT/dist}"
cd "$ROOT"
command -v cargo >/dev/null || { echo "cargo is required" >&2; exit 1; }
cargo test --manifest-path agent/rust/Cargo.toml
cargo build --release --manifest-path agent/rust/Cargo.toml
mkdir -p "$OUT"
install -m 0755 agent/rust/target/release/commandcore-agent-rust "$OUT/commandcore-agent"
sha256sum "$OUT/commandcore-agent" > "$OUT/commandcore-agent.sha256"
"$OUT/commandcore-agent" --version
"$OUT/commandcore-agent" capabilities >/dev/null
printf 'Built %s\n' "$OUT/commandcore-agent"
