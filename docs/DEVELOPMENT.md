# Development

## Requirements

- Python 3.11+
- Rust toolchain pinned by `rust-toolchain.toml`
- Node.js for web-panel syntax checks
- Docker for container/release acceptance work
- dependencies in `requirements-dev.txt`

## Run server

```bash
export COMMANDCORE_API_TOKEN=$(./scripts/generate-secret.sh)
export COMMANDCORE_DB=/tmp/commandcore-dev.sqlite3
PYTHONPATH=apps/server python -m commandcore_server.main
```

## Verification

```bash
make lint
make format-check
PYTHONPATH=apps/server:agent pytest -q tests
PYTHONPATH=apps/server:agent python scripts/integration_smoke.py
cargo fmt --manifest-path agent/rust/Cargo.toml --check
cargo clippy --locked --manifest-path agent/rust/Cargo.toml --all-targets --all-features -- -D warnings
cargo test --locked --manifest-path agent/rust/Cargo.toml
python scripts/public_repo_check.py
python scripts/secret_scan.py --history
```

The repository treats Pyflakes-class Ruff rules (`F`) as a whole-tree correctness
gate and `ruff format` as the canonical Python formatter. Use `make format` before
submitting Python changes and keep formatting-only changes separate from behavior
changes when practical.

## Code boundaries

Do not put provider/client-specific behavior into device registry, job dispatcher, policy or Agent protocol. Client integration belongs under `docs/clients/` and future northbound adapter packages.

Do not add privileged operations to the network-facing Agent merely because `FULL_CONTROL` is desired. Privileged operations belong in the helper boundary.

## Versioning

Version independently when evolution requires it:

- product/server version: `VERSION`
- Agent version: Agent package version
- Agent protocol: currently `1`
- MCP protocol: external standards revision
- individual capability versions: Agent advertisement fields
