#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ "${JEND_ALLOW_LIVE_HF_XORB:-}" != "1" ]]; then
  echo "Refusing live xorb fetch: set JEND_ALLOW_LIVE_HF_XORB=1 explicitly" >&2
  exit 2
fi
if [[ -z "${JEND_HF_TOKEN:-}" ]]; then
  echo "Refusing live xorb fetch: set JEND_HF_TOKEN to a read token" >&2
  exit 2
fi
cargo run -p jend-cli --bin jend-hf-xet-single-range-live-smoke --locked
