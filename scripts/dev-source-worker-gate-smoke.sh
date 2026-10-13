#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
cargo run -p jend-model-store --bin jend-source-worker-gate-smoke --locked
