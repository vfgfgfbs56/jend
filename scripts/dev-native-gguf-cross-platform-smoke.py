#!/usr/bin/env python3
"""Model-free Rust/C++ one-shot protocol compatibility on host OS/CPU.

No model downloads, no Hugging Face token, no privileged sandbox claims.
Standalone rustc avoids building unrelated server/client workspace crates.
"""
from __future__ import annotations

import os
from pathlib import Path
import platform
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
NATIVE = ROOT / "native" / "jend-gguf-worker"
RUST_SRC = ROOT / "client" / "jend-cli" / "src" / "native_gguf_ipc.rs"
RUST_SMOKE = ROOT / "client" / "jend-cli" / "src" / "bin" / "jend-native-gguf-ipc-smoke.rs"
SUFFIX = ".exe" if os.name == "nt" else ""


def check(*args: str, timeout: int = 180) -> subprocess.CompletedProcess[bytes]:
    completed = subprocess.run(args, check=True, capture_output=True, timeout=timeout)
    return completed


def run_worker(executable: Path, args: tuple[str, ...], body: bytes = b""):
    return subprocess.run(
        [str(executable), *args], input=body, capture_output=True, timeout=8
    )


def executable_from(build: Path) -> Path:
    for candidate in (
        build / ("jend-gguf-cpu-worker" + SUFFIX),
        build / "Debug" / ("jend-gguf-cpu-worker" + SUFFIX),
        build / "Release" / ("jend-gguf-cpu-worker" + SUFFIX),
    ):
        if candidate.is_file():
            return candidate.resolve()
    raise RuntimeError("CMake did not create a native worker executable")


def main() -> None:
    print(
        "Jend cross-platform host:",
        platform.system(),
        platform.machine(),
        "Python",
        platform.python_version(),
        flush=True,
    )
    with tempfile.TemporaryDirectory(prefix="jend-native-portable-") as directory:
        tmp = Path(directory).resolve()
        build = tmp / "build"
        check(
            "cmake", "-S", str(NATIVE), "-B", str(build),
            "-DJEND_BUILD_EXPERIMENTAL_LLAMA=OFF",
            "-DCMAKE_BUILD_TYPE=Debug",
        )
        check(
            "cmake", "--build", str(build),
            "--config", "Debug", "--target", "jend-gguf-cpu-worker",
            "--parallel", "2",
        )
        worker = executable_from(build)
        caps = run_worker(worker, ("--capabilities",))
        assert caps.returncode == 0 and caps.stdout == (
            b"JEND-GGUF-CPU-WORKER-V1 PROTOCOL_ONLY\n"
        ) and caps.stderr == b"", (caps.returncode, caps.stdout, caps.stderr)
        print("Jend portable C++ worker compiled on actual host: PASS", flush=True)

        # The Windows CRT must NOT rewrite CRLF or treat 0x1A as EOF.
        prompt = b"Jend portable offline worker\\r\\nline\\x1a"
        payload = struct.pack(">I", len(prompt)) + prompt
        response = run_worker(worker, ("--protocol-smoke",), payload)
        expected = b"JENDGGUF1N" + struct.pack(">I", 8) + b"NO_MODEL"
        assert response.returncode == 0 and response.stdout == expected, (response.returncode, response.stdout, response.stderr)
        assert response.stderr == b"" and prompt not in response.stdout
        print("Jend portable C++ framed IPC is byte-identical: PASS", flush=True)

        for malformed in (
            b"",
            struct.pack(">I", 0),
            struct.pack(">I", 4097) + b"a" * 4097,
            struct.pack(">I", 4) + b"abc",
            payload + b"tail",
            payload + struct.pack(">I", 1) + b"x",
        ):
            result = run_worker(worker, ("--protocol-smoke",), malformed)
            assert result.returncode != 0 and result.stdout == b"", (result.returncode, result.stdout, result.stderr)
        print("Jend portable C++ rejects truncation and second frames: PASS", flush=True)

        for args in (
            ("--infer-dev", "--model", str(tmp / "untrusted.gguf")),
            ("--model", str(tmp / "untrusted.gguf")),
            ("--protocol-smoke", "--model", str(tmp / "untrusted.gguf")),
        ):
            result = run_worker(worker, args, payload)
            assert result.returncode != 0 and result.stdout == b""
        print("Jend portable native inference disabled by default: PASS", flush=True)

        tests = tmp / ("jend-native-ipc-tests" + SUFFIX)
        smoke = tmp / ("jend-native-ipc-rust-smoke" + SUFFIX)
        rustc = ("rustup", "run", "1.99.0", "rustc")
        check(*rustc, "--edition=2024", "--test", str(RUST_SRC), "-o", str(tests))
        test_result = check(str(tests), "--quiet", timeout=30)
        if b"4 passed" not in test_result.stdout:
            raise RuntimeError("Rust IPC tests did not report exactly four passed cases")
        print("Jend portable Rust wire parser unit tests: PASS", flush=True)

        check(*rustc, "--edition=2024", str(RUST_SMOKE), "-o", str(smoke))
        result = check(str(smoke), str(worker), timeout=30)
        for expected_line in (
            b"Jend Rust supervised C++ worker handshake: PASS",
            b"Jend Rust prompt length preflight gate: PASS",
            b"Jend Rust invalid deadline and executable path rejected: PASS",
            b"Jend Rust C++ worker stdout bounded and stderr suppressed: PASS",
            b"Jend Rust parser denies malformed or untrusted native frames: PASS",
            b"Jend native worker supervisor remains model-free and dev-only: PASS",
        ):
            if expected_line not in result.stdout:
                raise RuntimeError("missing native smoke assertion: " + expected_line.decode())
        print("Jend portable Rust-to-C++ one-shot supervisor handshake: PASS", flush=True)
        print("Jend cross-platform proof is protocol-only; no model inference: PASS", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (OSError, AssertionError, subprocess.SubprocessError, RuntimeError) as exc:
        print("Jend portable native protocol smoke FAILED:", str(exc), file=sys.stderr)
        sys.exit(1)
