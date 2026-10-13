#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
build_dir="$(mktemp -d)"
trap 'rm -rf "$build_dir"' EXIT
cmake -S native/jend-gguf-worker -B "$build_dir" -DJEND_BUILD_EXPERIMENTAL_LLAMA=OFF
cmake --build "$build_dir" --target jend-gguf-cpu-worker -j 2
cargo test -p jend-cli --bin jend-native-worker-integrity-smoke --locked
cargo run -p jend-cli --bin jend-native-worker-integrity-smoke --locked \
  -- "$build_dir/jend-gguf-cpu-worker"
