#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
cargo test -p jend-cli --bin jend-xet-signed-page-admission-smoke --locked
cargo run -p jend-cli --bin jend-xet-signed-page-admission-smoke --locked
