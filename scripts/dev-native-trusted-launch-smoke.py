#!/usr/bin/env python3
"""Offline trusted-launch fixture; no downloaded model, credentials or chat."""
from __future__ import annotations

import os
import json
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def run(argv: list[str], **kwargs) -> None:
    subprocess.run(argv, cwd=ROOT, check=True, timeout=300, **kwargs)


def main() -> None:
    run(["cargo", "test", "-p", "jend-cli", "--bin", "jend-native-trusted-launch-smoke", "--locked"])
    command = ["cargo", "run", "-p", "jend-cli", "--bin", "jend-native-trusted-launch-smoke", "--locked", "--"]
    if platform.system() != "Linux" or platform.machine().lower() not in {"x86_64", "amd64", "aarch64", "arm64"}:
        run(command)
        return
    compiler = shutil.which("c++")
    if not compiler:
        raise SystemExit("trusted launch fixture requires local C++ compiler")
    with tempfile.TemporaryDirectory(prefix="jend-trusted-launch-") as temp:
        folder = Path(temp)
        fixture, protocol, dynamic, canary = [folder / name for name in ("fixture", "protocol", "dynamic", "canary")]
        canary.write_bytes(b"SYNTHETIC-PRIVATE-CANARY-NO-USER-DATA")
        define = '-DJEND_PRIVATE_CANARY_PATH=' + json.dumps(str(canary))
        flags = [compiler, "-std=c++17", "-Wall", "-Wextra", "-Werror", "-O2"]
        run(flags + ["-static", "-no-pie", define, "native/jend-gguf-worker/preexec_attack_fixture.cpp", "-o", str(fixture)])
        run(flags + ["-static", "-no-pie", "native/jend-gguf-worker/worker.cpp", "-o", str(protocol)])
        # ET_EXEC + PT_INTERP: tests interpreter rejection independently of PIE.
        run(flags + ["-no-pie", "native/jend-gguf-worker/worker.cpp", "-o", str(dynamic)])
        env = os.environ.copy()
        env["JEND_TEST_SECRET_CANARY"] = "SYNTHETIC-ENV-NO-USER-SECRET"
        # Control: the hostile constructor cannot produce PASS outside confinement.
        control = subprocess.run([str(fixture), "--constructor-probe"], cwd=ROOT,
            env={"JEND_TEST_SECRET_CANARY": "SYNTHETIC-ENV-NO-USER-SECRET"},
            capture_output=True, timeout=5)
        if control.returncode != 97 or control.stdout:
            raise SystemExit("constructor fixture failed its unsandboxed negative control")
        print("Jend trusted launch adversarial constructor negative control: PASS", flush=True)
        run(command + [str(fixture), str(protocol), str(dynamic), str(canary)], env=env)


if __name__ == "__main__":
    main()
