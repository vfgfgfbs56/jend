#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ ! -f Cargo.lock ]]; then
  echo "Cargo.lock is missing. Copy the previous verified Cargo.lock into this checkout first." >&2
  exit 1
fi

has_model_store_subtle() {
  python3 - <<'PY'
import tomllib
from pathlib import Path
lock = tomllib.loads(Path("Cargo.lock").read_text(encoding="utf-8"))
for package in lock.get("package", []):
    if package.get("name") == "jend-model-store" and package.get("source") is None:
        deps = package.get("dependencies", [])
        raise SystemExit(0 if any(d == "subtle" or d.startswith("subtle ") for d in deps) else 1)
raise SystemExit(1)
PY
}

if has_model_store_subtle; then
  echo "Jend M8.5.6 lockfile already binds jend-model-store -> subtle: PASS"
  exit 0
fi

echo "Extending the existing lockfile with jend-model-store -> subtle 2.6.1 (one-time, intentionally without --locked)..."
cargo check -p jend-model-store --lib
has_model_store_subtle
echo "Jend M8.5.6 lockfile extension: PASS"
