#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

python3 scripts/static-preflight.py
python3 scripts/dependency-policy.py
python3 scripts/verify-manifest.py

missing=0
for cmd in rustc cargo curl docker; do
  if command -v "$cmd" >/dev/null 2>&1; then
    printf '%-8s %s\n' "$cmd" "$(command -v "$cmd")"
  else
    echo "missing: $cmd" >&2
    missing=1
  fi
done

if [[ "$missing" != "0" ]]; then
  echo "headless doctor: missing required tooling" >&2
  exit 2
fi

echo "rustc: $(rustc --version)"
echo "cargo: $(cargo --version)"
expected_toolchain="$(python3 - <<'PYTOOL'
import tomllib
print(tomllib.load(open('rust-toolchain.toml','rb'))['toolchain']['channel'])
PYTOOL
)"
actual_rust="$(rustc --version | awk '{print $2}')"
if [[ "$actual_rust" != "$expected_toolchain" ]]; then
  echo "wrong rustc version: expected $expected_toolchain, got $actual_rust" >&2
  exit 2
fi
docker compose version

docker compose -f deployment/docker-compose.headless.yml config >/dev/null

echo "headless doctor: PASS"
