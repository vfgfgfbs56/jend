#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

python3 scripts/static-preflight.py
python3 scripts/dependency-policy.py
python3 scripts/verify-manifest.py

for cmd in cargo rustc; do
  command -v "$cmd" >/dev/null || {
    echo "missing required command: $cmd" >&2
    exit 2
  }
done

if [[ ! -f Cargo.lock ]]; then
  cargo generate-lockfile
fi

# Fastest high-value path: prove the OPAQUE API and crypto suite compile and
# complete a real registration/login exchange before compiling the whole tree.
cargo test -p jend-auth --test opaque_roundtrip --locked

# Compile and exercise the request-proof protocol independently.
cargo test -p jend-jreq --locked

# Compile gateway handlers and run DB-independent startup/security unit tests.
cargo test -p jend-gateway --bin jend-gateway --locked

# Compile Store delivery contracts before the local runtime.
cargo test -p jend-model-store --locked
cargo check -p jend-model-store --bin jend-clean-room-smoke --locked
cargo check -p jend-model-store --bin jend-model-access-smoke --locked
cargo check -p jend-model-store --bin jend-model-ingest-smoke --locked
cargo check -p jend-model-store --bin jend-zero-install-smoke --locked
cargo check -p jend-model-store --bin jend-aid --locked
cargo check -p jend-model-store --bin jend-ai-smoke --locked
cargo check -p jend-model-store --bin jend-execution-route-smoke --locked
cargo check -p jend-model-store --bin jend-native-blueprint-smoke --locked
cargo check -p jend-model-store --bin jend-weightvm-smoke --locked
cargo check -p jend-model-store --bin jend-weight-store-smoke --locked
cargo check -p jend-model-store --bin jend-virtual-map-smoke --locked
cargo check -p jend-model-store --bin jend-source-protocol-smoke --locked
cargo check -p jend-model-store --bin jend-hf-xet-adapter-smoke --locked
cargo check -p jend-model-store --bin jend-source-worker-gate-smoke --locked
cargo check -p jend-model-store --bin jend-verified-page-ingest-smoke --locked
cargo check -p jend-cli --bin jend-xet-metadata-smoke --locked
cargo check -p jend-cli --bin jend-xet-single-range-plan-smoke --locked
cargo check -p jend-cli --bin jend-hf-xet-single-range-live-smoke --locked
cargo check -p jend-cli --bin jend-xet-xorb-decode-smoke --locked
cargo check -p jend-cli --bin jend-hf-xet-decode-live-smoke --locked
cargo check -p jend-cli --bin jend-hf-xet-reconstruction-live-smoke --locked
cargo check -p jend-cli --bin jend-source-worker-transport-policy-smoke --locked
cargo check -p jend-cli --bin jend-hf-source-worker-live-smoke --locked

# Compile the generic Network Broker security primitives independently.
# Provider-tunnel experiment code remains non-product and is not a Store path.
cargo test -p jend-net-broker --locked

# Compile the Vault library, IPC/process code, and local runtime scheduler.
cargo test -p jend-vault --locked
cargo check -p jend-vault --bin jend-runtime-smoke --locked
cargo check -p jend-vault --bin jend-performance-smoke --locked
cargo check -p jend-vault --bin jend-governor-smoke --locked

# Only after the focused gates pass, compile every target in the workspace.
cargo check --workspace --all-targets --locked

echo "Jend first-test ladder: PASS"
echo "Next: JEND_DEV_CLEANUP=1 bash scripts/dev-headless-smoke.sh"
