#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
cargo run -p jend-cli --bin jend-hf-xet-decode-live-smoke --locked
