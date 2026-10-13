#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

build_dir="$(mktemp -d)"
trap 'rm -rf "$build_dir"' EXIT

cmake -S native/jend-gguf-worker -B "$build_dir" \
  -DJEND_BUILD_EXPERIMENTAL_LLAMA=OFF
cmake --build "$build_dir" --target jend-gguf-cpu-worker -j 2

python3 - "$build_dir/jend-gguf-cpu-worker" <<'PY'
import struct
import subprocess
import sys
exe = sys.argv[1]
prompt = b"safe offline"
body = struct.pack(">I", len(prompt)) + prompt
for invalid in [body + b"x", body + struct.pack(">I", 1) + b"y"]:
    result = subprocess.run(
        [exe, "--protocol-smoke"],
        input=invalid,
        capture_output=True,
        timeout=5,
    )
    assert result.returncode != 0 and result.stdout == b""
print("Jend C++ native one-shot trailing-data and second-frame refusal: PASS")
PY

cargo test -p jend-cli --bin jend-native-gguf-ipc-smoke --locked
cargo run -p jend-cli --bin jend-native-gguf-ipc-smoke --locked \
  -- "$build_dir/jend-gguf-cpu-worker"
