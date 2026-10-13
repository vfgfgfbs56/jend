#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

bash scripts/doctor-headless.sh

COMPOSE=(docker compose -f deployment/docker-compose.headless.yml)
cleanup() {
  if [[ "${JEND_DEV_CLEANUP:-0}" == "1" ]]; then
    "${COMPOSE[@]}" down -v
  fi
}
trap cleanup EXIT

"${COMPOSE[@]}" up -d postgres

ready=0
for _ in $(seq 1 60); do
  if "${COMPOSE[@]}" exec -T postgres pg_isready -U jend_dev -d jend >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done
if [[ "$ready" != "1" ]]; then
  echo "PostgreSQL did not become ready" >&2
  "${COMPOSE[@]}" logs postgres >&2 || true
  exit 1
fi

export DATABASE_URL='postgres://jend_dev:jend_dev_only_change_me@127.0.0.1:54329/jend'
export JEND_SMOKE_PASSWORD="${JEND_SMOKE_PASSWORD:-dev-only-password-123456789}"
export JEND_SMOKE_USERNAME="${JEND_SMOKE_USERNAME:-dev_$(date +%s)_${RANDOM}}"

bash scripts/ci-headless-smoke.sh

echo "Local Jend headless registration/login smoke: PASS"
echo "PostgreSQL remains running. Set JEND_DEV_CLEANUP=1 to remove it automatically next run."
