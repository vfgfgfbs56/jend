#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
cargo test -p jend-model-store --lib runtime_feasibility --locked
cargo run -p jend-model-store --bin jend-runtime-feasibility-smoke --locked
