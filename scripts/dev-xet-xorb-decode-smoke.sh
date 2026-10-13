#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
cargo test -p jend-cli --bin jend-xet-xorb-decode-smoke --locked
cargo run -p jend-cli --bin jend-xet-xorb-decode-smoke --locked
