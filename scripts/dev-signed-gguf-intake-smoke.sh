#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

cargo test -p jend-model-store --lib signed_gguf --locked
cargo run -p jend-model-store --bin jend-signed-gguf-intake-smoke --locked
