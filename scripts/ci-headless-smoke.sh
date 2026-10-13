#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

python3 scripts/static-preflight.py
python3 scripts/verify-manifest.py

: "${DATABASE_URL:=postgres://jend_dev:jend_dev_ci@127.0.0.1:5432/jend}"
: "${JEND_SMOKE_PASSWORD:=ci-only-password-123456789}"
: "${JEND_SMOKE_USERNAME:=ci_$(date +%s)_${RANDOM}}"
: "${JEND_SMOKE_ADDR:=127.0.0.1:18080}"

TMP_DIR="$(mktemp -d)"
DIAG_DIR="$ROOT/target/jend-ci"
mkdir -p "$DIAG_DIR"
GATEWAY_PID=""

cleanup() {
  cp "$TMP_DIR/gateway.log" "$DIAG_DIR/gateway.log" 2>/dev/null || true
  cp "$TMP_DIR/public-bind.log" "$DIAG_DIR/public-bind.log" 2>/dev/null || true
  if [[ -n "$GATEWAY_PID" ]]; then
    kill "$GATEWAY_PID" 2>/dev/null || true
    wait "$GATEWAY_PID" 2>/dev/null || true
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

if [[ ! -f Cargo.lock ]]; then
  cargo metadata --format-version 1 >/dev/null
fi
cargo build --locked -p jend-migrate -p jend-keygen -p jend-gateway -p jend-cli

DATABASE_URL="$DATABASE_URL" "$ROOT/target/debug/jend-migrate"
"$ROOT/target/debug/jend-keygen" "$TMP_DIR/secrets"

# The headless binary speaks plain HTTP. It must fail closed if an operator
# accidentally exposes it on a non-loopback interface without explicit opt-in.
if DATABASE_URL="$DATABASE_URL" \
   JEND_SECRET_DIR="$TMP_DIR/secrets" \
   JEND_GATEWAY_ADDR="0.0.0.0:18081" \
   "$ROOT/target/debug/jend-gateway" >"$TMP_DIR/public-bind.log" 2>&1; then
  echo "security regression: gateway accepted non-loopback plain-HTTP bind" >&2
  exit 1
fi

DATABASE_URL="$DATABASE_URL" \
JEND_SECRET_DIR="$TMP_DIR/secrets" \
JEND_GATEWAY_ADDR="$JEND_SMOKE_ADDR" \
RUST_LOG="jend_gateway=info" \
"$ROOT/target/debug/jend-gateway" >"$TMP_DIR/gateway.log" 2>&1 &
GATEWAY_PID="$!"

BASE_URL="http://$JEND_SMOKE_ADDR"
ready=0
for _ in $(seq 1 60); do
  if curl --fail --silent --show-error "$BASE_URL/readyz" >/dev/null 2>&1; then
    ready=1
    break
  fi
  if ! kill -0 "$GATEWAY_PID" 2>/dev/null; then
    echo "gateway exited before readiness" >&2
    cat "$TMP_DIR/gateway.log" >&2
    exit 1
  fi
  sleep 1
done

if [[ "$ready" != "1" ]]; then
  echo "gateway did not become ready" >&2
  cat "$TMP_DIR/gateway.log" >&2
  exit 1
fi

printf '%s\n%s\n' "$JEND_SMOKE_PASSWORD" "$JEND_SMOKE_PASSWORD" | \
  "$ROOT/target/debug/jend-cli" \
  smoke-register "$BASE_URL" "$JEND_SMOKE_USERNAME" --password-stdin

echo "Jend headless security smoke: PASS"
