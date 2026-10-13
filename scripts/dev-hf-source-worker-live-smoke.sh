#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
: "${JEND_ALLOW_LIVE_HF:?set JEND_ALLOW_LIVE_HF=1 to permit the explicit live Hugging Face request}"
if [[ "$JEND_ALLOW_LIVE_HF" != "1" ]]; then
  echo "JEND_ALLOW_LIVE_HF must equal 1" >&2
  exit 2
fi
cargo run -p jend-cli --bin jend-hf-source-worker-live-smoke --locked
