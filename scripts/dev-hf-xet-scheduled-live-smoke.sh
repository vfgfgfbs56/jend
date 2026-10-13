#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
# No shell tracing. Token is supplied in environment after explicit opt-in.
cargo run -p jend-cli --bin jend-hf-xet-scheduled-live-smoke --locked
