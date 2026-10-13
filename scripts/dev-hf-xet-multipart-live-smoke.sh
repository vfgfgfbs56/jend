#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
# Explicit opt-in required by the binary; never print token or signed URLs.
cargo run -p jend-cli --bin jend-hf-xet-multipart-live-smoke --locked
