#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

python3 scripts/static-preflight.py
python3 scripts/dependency-policy.py
python3 scripts/verify-manifest.py

for cmd in cargo rustc; do
  command -v "$cmd" >/dev/null || {
    echo "missing required command: $cmd" >&2
    exit 2
  }
done

cargo fmt --all -- --check
if [[ ! -f Cargo.lock ]]; then
  cargo metadata --format-version 1 >/dev/null
fi
cargo check --workspace --all-targets --locked
cargo test --workspace --all-targets --locked

if [[ "${JEND_RUN_DB_SMOKE:-0}" == "1" ]]; then
  command -v curl >/dev/null || {
    echo "missing required command for DB smoke: curl" >&2
    exit 2
  }
  bash scripts/ci-headless-smoke.sh
else
  echo "compile/tests finished; set JEND_RUN_DB_SMOKE=1 to run PostgreSQL smoke"
fi
