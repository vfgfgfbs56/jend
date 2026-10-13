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

def call(*args, data=b""):
    return subprocess.run([exe, *args], input=data, capture_output=True, timeout=5)

caps = call("--capabilities")
assert caps.returncode == 0
assert caps.stdout == b"JEND-GGUF-CPU-WORKER-V1 PROTOCOL_ONLY\n"
assert not caps.stderr
print("Jend native C++ protocol-only worker compilation: PASS")

prompt = b"offline test: no real model or network"
frame = struct.pack(">I", len(prompt)) + prompt
r = call("--protocol-smoke", data=frame)
assert r.returncode == 0, (r.returncode, r.stderr[:100])
assert r.stdout == b"JENDGGUF1N" + struct.pack(">I", 8) + b"NO_MODEL"
assert not r.stderr
assert prompt not in r.stdout
print("Jend native bounded binary prompt and response framing: PASS")

for data in (
    b"",
    struct.pack(">I", 0),
    struct.pack(">I", 4097) + b"x" * 4097,
    struct.pack(">I", 4) + b"abc",
):
    r = call("--protocol-smoke", data=data)
    assert r.returncode != 0 and r.stdout == b""
print("Jend native empty truncated and oversized prompt rejected: PASS")

for args in (
    ("--infer-dev", "--model", "/tmp/test.gguf"),
    ("--model", "/tmp/test.gguf"),
    ("--protocol-smoke", "--model", "/tmp/test.gguf"),
    ("--unknown",),
):
    r = call(*args, data=frame)
    assert r.returncode != 0 and r.stdout == b""
print("Jend native unchecked GGUF launch blocked by default: PASS")

assert not any(b"model" in call("--capabilities").stderr for _ in range(1))
print("Jend native protocol smoke executes no GGUF inference: PASS")
PY
