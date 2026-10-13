#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
if [[ ! -f Cargo.lock ]]; then
  echo "Cargo.lock is missing. Copy the previous verified Cargo.lock into this checkout first." >&2
  exit 1
fi
if grep -q '^name = "lz4_flex"$' Cargo.lock; then
  echo "Jend M8.5.5 lockfile already contains lz4_flex: PASS"
  exit 0
fi
echo "Extending the existing lockfile with pinned lz4_flex = 0.13.1 (one-time, intentionally without --locked)..."
cargo check -p jend-cli --bin jend-xet-xorb-decode-smoke
grep -q '^name = "lz4_flex"$' Cargo.lock
echo "Jend M8.5.5 lockfile extension: PASS"
