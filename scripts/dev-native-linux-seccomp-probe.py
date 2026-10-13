#!/usr/bin/env python3
"""Platform-truthful native restriction proof. NEVER runs a GGUF model.

Linux (x86_64 / aarch64): worker itself applies seccomp BPF, no_new_privs,
RLIMITs and tests socket denial. macOS/Windows: must fail closed and cannot
claim OS sandbox support. No HF token, user messages or downloaded models.
"""
from __future__ import annotations

from pathlib import Path
import os
import platform
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
SUFFIX = ".exe" if os.name == "nt" else ""
EXPECTED = b"JEND-LINUX-RESTRICTED-PROBE-V1\n"


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="jend-native-restricted-") as directory:
        build = Path(directory) / "build"
        subprocess.run(
            ["cmake", "-S", str(ROOT / "native/jend-gguf-worker"),
             "-B", str(build), "-DJEND_BUILD_EXPERIMENTAL_LLAMA=OFF"],
            check=True, capture_output=True, timeout=90,
        )
        subprocess.run(
            ["cmake", "--build", str(build), "--config", "Debug",
             "--target", "jend-gguf-cpu-worker", "--parallel", "2"],
            check=True, capture_output=True, timeout=120,
        )
        worker = None
        for p in (
            build / ("jend-gguf-cpu-worker" + SUFFIX),
            build / "Debug" / ("jend-gguf-cpu-worker" + SUFFIX),
            build / "Release" / ("jend-gguf-cpu-worker" + SUFFIX),
        ):
            if p.is_file():
                worker = p.resolve()
                break
        if worker is None:
            raise RuntimeError("missing compiled protocol worker")
        print("Jend native security probe compiles on host: PASS")

        result = subprocess.run(
            [str(worker), "--sandbox-probe"],
            input=b"", capture_output=True, timeout=8,
        )
        is_supported_linux = (
            platform.system() == "Linux"
            and platform.machine().lower() in ("x86_64", "aarch64", "arm64")
        )
        if is_supported_linux:
            if result.returncode != 0 or result.stdout != EXPECTED or result.stderr:
                raise RuntimeError(
                    "Linux seccomp kernel attestation failed; no unsupported fallback: "
                    + repr((result.returncode, result.stdout, result.stderr))
                )
            print("Jend Linux seccomp no-new-privs and network denial: PASS")
            print("Jend Linux finite CPU RAM open-files and core limits: PASS")
        else:
            if result.returncode == 0 or result.stdout != b"":
                raise RuntimeError(
                    "unsupported OS/ISA incorrectly reported a native sandbox"
                )
            print("Jend unsupported desktop OS native sandbox refused: PASS")

        # This probe is a separate development entrypoint. The normal native
        # worker still must NOT accept model inference without other gates.
        rejected = subprocess.run(
            [str(worker), "--infer-dev", "--model", str(build / "no.gguf")],
            input=b"", capture_output=True, timeout=5,
        )
        if rejected.returncode == 0 or rejected.stdout:
            raise RuntimeError("native GGUF inference incorrectly activated")
        print("Jend native probe leaves production model execution disabled: PASS")
        print("Jend native probe proves NO filesystem or E2EE isolation: PASS")


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        print("Jend restricted native probe FAILED:", str(exc), file=sys.stderr)
        sys.exit(1)
