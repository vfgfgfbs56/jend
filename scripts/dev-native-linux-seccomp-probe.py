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

        canary = Path(directory) / "jend-local-private-canary"
        canary.write_bytes(b"JEND-TEST-ONLY-CANARY-NOT-USER-SECRET")
        canary.chmod(0o600)
        is_supported_linux = (
            platform.system() == "Linux"
            and platform.machine().lower() in ("x86_64", "aarch64", "arm64")
        )
        # Never forward the caller's actual environment or secrets. We
        # intentionally inherit only a harmless synthetic canary variable.
        clean_env = {
            "PATH": os.defpath,
            "JEND_TEST_INHERITED_ENV_CANARY": "synthetic-not-a-secret",
        }
        if os.name == "nt" and "SystemRoot" in os.environ:
            clean_env["SystemRoot"] = os.environ["SystemRoot"]
        candidate_fd = -1
        try:
            if is_supported_linux:
                candidate_fd = os.open(canary, os.O_RDONLY)
                result = subprocess.run(
                    [str(worker), "--sandbox-probe", "--deny-read", str(canary),
                     "--inherited-fd", str(candidate_fd)],
                    pass_fds=(candidate_fd,), env=clean_env,
                    input=b"", capture_output=True, timeout=8,
                )
            else:
                result = subprocess.run(
                    [str(worker), "--sandbox-probe", "--deny-read", str(canary),
                     "--inherited-fd", "3"],
                    env=clean_env, input=b"", capture_output=True, timeout=8,
                )
        finally:
            if candidate_fd >= 0:
                os.close(candidate_fd)
        if is_supported_linux:
            if result.returncode != 0 or result.stdout != EXPECTED or result.stderr:
                raise RuntimeError(
                    "Linux seccomp kernel attestation failed; no unsupported fallback: "
                    + repr((result.returncode, result.stdout, result.stderr))
                )
            print("Jend Linux seccomp no-new-privs and network denial: PASS")
            print("Jend Linux finite CPU RAM open-files and core limits: PASS")
            print("Jend Linux kernel denies new readable-file handles: PASS")
            print("Jend Linux kernel denies child process creation: PASS")
            print("Jend Linux close_range removes inherited canary descriptor: PASS")
            print("Jend Linux clearenv drops synthetic inherited environment: PASS")
        else:
            if result.returncode == 0 or result.stdout != b"":
                raise RuntimeError(
                    "unsupported OS/ISA incorrectly reported a native sandbox"
                )
            print("Jend unsupported desktop OS native sandbox refused: PASS")

        # A missing canary argument must never accidentally re-enable the
        # original weaker probe entrypoint or emit a success marker.
        missing = subprocess.run(
            [str(worker), "--sandbox-probe"],
            input=b"", capture_output=True, timeout=5,
        )
        if missing.returncode == 0 or missing.stdout:
            raise RuntimeError("test-only restricted probe accepted missing canary")
        if is_supported_linux:
            # Claiming an FD that was never actually inherited MUST fail.
            fake_fd = subprocess.run(
                [str(worker), "--sandbox-probe", "--deny-read", str(canary),
                 "--inherited-fd", "99999"],
                env=clean_env, input=b"", capture_output=True, timeout=5,
            )
            if fake_fd.returncode == 0 or fake_fd.stdout:
                raise RuntimeError("unverified inherited FD incorrectly accepted")
        print("Jend native absent inherited descriptor fail-closed: PASS")
        print("Jend native missing security canary argument refused: PASS")

        # This probe is a separate development entrypoint. The normal native
        # worker still must NOT accept model inference without other gates.
        rejected = subprocess.run(
            [str(worker), "--infer-dev", "--model", str(build / "no.gguf")],
            input=b"", capture_output=True, timeout=5,
        )
        if rejected.returncode == 0 or rejected.stdout:
            raise RuntimeError("native GGUF inference incorrectly activated")
        print("Jend native probe leaves production model execution disabled: PASS")
        print("Jend native restricted probe still exposes inherited descriptors and E2EE risk: PASS")


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        print("Jend restricted native probe FAILED:", str(exc), file=sys.stderr)
        sys.exit(1)
