#!/usr/bin/env python3
from __future__ import annotations

import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ALLOWED: dict[str, set[str]] = {
    "axum": {"0.8"},
    "base64": {"0.22"},
    "chacha20poly1305": {"0.11.0"},
    "ed25519-dalek": {"3.0.0"},
    "getrandom": {"0.4.3"},
    "hex": {"0.4"},
    "hkdf": {"0.13.0"},
    "hmac": {"0.12"},
    "lz4_flex": {"=0.13.1"},
    "libc": {"=0.2.190"},
    "opaque-ke": {"4.0.1"},
    "rand": {"0.8.5"},
    "reqwest": {"0.12"},
    "rpassword": {"7"},
    "serde": {"1"},
    "serde_json": {"1"},
    "sha2": {"0.10.9", "0.11.0"},
    "sqlx": {"=0.8.6"},
    "subtle": {"2.6.1"},
    "thiserror": {"2.0.21"},
    "tokio": {"1"},
    "tower-http": {"0.6"},
    "tracing": {"0.1"},
    "tracing-subscriber": {"0.3"},
    "url": {"2.5.7"},
    "x25519-dalek": {"2.0.1"},
    "zeroize": {"1.9", "1.9.0"},
}
FAILURES: list[str] = []
seen_external: dict[str, set[str]] = {}


def fail(msg: str) -> None:
    FAILURES.append(msg)


def inside_workspace(path: Path) -> bool:
    try:
        path.resolve().relative_to(ROOT.resolve())
        return True
    except ValueError:
        return False

for manifest in sorted(ROOT.rglob("Cargo.toml")):
    data = tomllib.loads(manifest.read_text(encoding="utf-8"))
    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        for name, spec in data.get(section, {}).items():
            where = f"{manifest.relative_to(ROOT)} [{section}] {name}"
            if isinstance(spec, str):
                version = spec
                meta = {}
            elif isinstance(spec, dict):
                meta = spec
                if "git" in meta:
                    fail(f"git dependency forbidden: {where}")
                if "registry" in meta:
                    fail(f"custom registry dependency forbidden: {where}")
                if "path" in meta:
                    dep = (manifest.parent / str(meta["path"])).resolve()
                    if not inside_workspace(dep):
                        fail(f"path dependency escapes workspace: {where} -> {dep}")
                    if not (dep / "Cargo.toml").is_file():
                        fail(f"path dependency missing Cargo.toml: {where} -> {dep}")
                    continue
                version = str(meta.get("version", ""))
            else:
                fail(f"unsupported dependency syntax: {where}")
                continue

            if not version or version == "*":
                fail(f"unbounded registry dependency forbidden: {where}")
                continue
            package_name = str(meta.get("package", name)) if isinstance(meta, dict) else name
            seen_external.setdefault(package_name, set()).add(version)
            allowed = ALLOWED.get(package_name)
            if allowed is None:
                fail(f"registry dependency not allowlisted: {where} (package={package_name}) = {version}")
            elif version not in allowed:
                fail(
                    f"dependency requirement drift: {where} (package={package_name}) = {version}; "
                    f"allowed={sorted(allowed)}"
                )

for name in sorted(ALLOWED):
    if name not in seen_external:
        fail(f"stale dependency allowlist entry: {name}")

if FAILURES:
    for item in FAILURES:
        print(f"FAIL: {item}", file=sys.stderr)
    raise SystemExit(1)

count=sum(len(v) for v in seen_external.values())
print(f"dependency policy PASS: {len(seen_external)} registry crates, {count} approved requirements, no git/custom-registry dependencies")
