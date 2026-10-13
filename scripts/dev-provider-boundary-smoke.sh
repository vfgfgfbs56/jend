#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

cargo run -p jend-model-store --bin jend-execution-route-smoke --locked
cargo run -p jend-net-broker --bin jend-provider-broker-smoke --locked
