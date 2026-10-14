#!/usr/bin/env python3
"""Synthetic signed/sealed GGUF DATA handoff; no downloaded or executed model."""
from __future__ import annotations

import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def run(argv: list[str], **kwargs) -> None:
    subprocess.run(argv, cwd=ROOT, check=True, timeout=300, **kwargs)


def main() -> None:
    run(["cargo", "test", "-p", "jend-cli", "--bin", "jend-native-sealed-model-smoke", "--locked"])
    cmd = ["cargo", "run", "-p", "jend-cli", "--bin", "jend-native-sealed-model-smoke", "--locked", "--"]
    if platform.system() != "Linux" or platform.machine().lower() not in {"x86_64", "amd64", "aarch64", "arm64"}:
        run(cmd)
        return
    compiler = shutil.which("c++")
    if not compiler:
        raise SystemExit("sealed data fixture requires local C++ compiler")
    with tempfile.TemporaryDirectory(prefix="jend-sealed-data-") as tmp:
        folder = Path(tmp)
        canary = folder / "ungranted-private-canary"
        canary.write_bytes(b"SYNTHETIC-CANARY-NO-USER-KEY")
        fixture = folder / "fixture"
        run([compiler, "-std=c++17", "-Wall", "-Wextra", "-Werror", "-O2", "-static", "-no-pie",
            "-DJEND_WITH_SEALED_MODEL_PROBE=1", "-DJEND_PRIVATE_CANARY_PATH=" + json.dumps(str(canary)),
            "native/jend-gguf-worker/preexec_attack_fixture.cpp", "-o", str(fixture)])
        control = subprocess.run([str(fixture), "--model-handle-probe"], cwd=ROOT,
            env={"JEND_TEST_SECRET_CANARY": "SYNTHETIC"}, capture_output=True, timeout=5)
        if control.returncode != 97 or control.stdout:
            raise SystemExit("sealed data constructor negative control failed")
        print("Jend sealed GGUF unconfined constructor cannot report success: PASS", flush=True)
        parent_env = os.environ.copy()
        parent_env["JEND_TEST_SECRET_CANARY"] = "SYNTHETIC-NO-USER-SECRET"
        run(cmd + [str(fixture)], env=parent_env)


if __name__ == "__main__":
    main()
