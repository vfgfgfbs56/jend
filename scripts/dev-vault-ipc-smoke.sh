#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

TMP="$(mktemp -d)"
PID=""
cleanup() {
  if [[ -n "${PID}" ]] && kill -0 "${PID}" 2>/dev/null; then
    kill "${PID}" 2>/dev/null || true
    wait "${PID}" 2>/dev/null || true
  fi
  rm -rf "${TMP}"
}
trap cleanup EXIT INT TERM

IPC_DIR="${TMP}/ipc"
STATE_DIR="${TMP}/state"
SECRET_DIR="${TMP}/secrets"
SOCKET="${IPC_DIR}/vault.sock"
AUTH="${IPC_DIR}/vault.auth"
mkdir -p "${IPC_DIR}"
chmod 700 "${IPC_DIR}"

export JEND_VAULT_SOCKET="${SOCKET}"
export JEND_VAULT_STATE_DIR="${STATE_DIR}"
export JEND_VAULT_SECRET_DIR="${SECRET_DIR}"

cargo build -p jend-vault --bin jend-vaultd --bin jend-vault-smoke --locked
VAULTD="${ROOT}/target/debug/jend-vaultd"
SMOKE="${ROOT}/target/debug/jend-vault-smoke"

wait_for_socket() {
  local i
  for i in {1..100}; do
    [[ -S "${SOCKET}" && -f "${AUTH}" ]] && return 0
    if [[ -n "${PID}" ]] && ! kill -0 "${PID}" 2>/dev/null; then
      echo "jend-vaultd exited before creating its socket" >&2
      cat "${TMP}/vault.log" >&2 || true
      return 1
    fi
    sleep 0.05
  done
  echo "timed out waiting for Vault socket" >&2
  return 1
}

start_vault() {
  : > "${TMP}/vault.log"
  "${VAULTD}" >"${TMP}/vault.log" 2>&1 &
  PID=$!
  wait_for_socket
}

stop_vault() {
  kill "${PID}"
  wait "${PID}" 2>/dev/null || true
  PID=""
  [[ -S "${SOCKET}" && -f "${AUTH}" ]] || {
    echo "Vault IPC artifacts unexpectedly disappeared before verified cleanup" >&2
    exit 1
  }
  rm "${SOCKET}" "${AUTH}"
}

start_vault

# A client with the wrong 256-bit IPC capability must be rejected before any
# Vault operation. Keep the daemon's in-memory token unchanged, temporarily
# replace only the client-visible file, then restore it.
cp "${AUTH}" "${TMP}/auth.good"
python3 - "${AUTH}" <<'PY'
from pathlib import Path
import sys
Path(sys.argv[1]).write_bytes(b"\x00" * 32)
PY
chmod 600 "${AUTH}"
if "${SMOKE}" roundtrip "${SOCKET}" >"${TMP}/unauthorized.out" 2>"${TMP}/unauthorized.err"; then
  echo "security regression: wrong Vault IPC capability was accepted" >&2
  exit 1
fi
mv "${TMP}/auth.good" "${AUTH}"
chmod 600 "${AUTH}"

# A second Vault must fail closed instead of stealing/replacing the live path.
if "${VAULTD}" >"${TMP}/second.log" 2>&1; then
  echo "security regression: second Vault replaced an existing socket" >&2
  exit 1
fi
grep -q "Vault IPC path already exists" "${TMP}/second.log" || {
  echo "second Vault failed for an unexpected reason" >&2
  cat "${TMP}/second.log" >&2
  exit 1
}

ROUNDTRIP="$("${SMOKE}" roundtrip "${SOCKET}")"
CONVERSATION="$(printf '%s\n' "${ROUNDTRIP}" | sed -n 's/^conversation=//p')"
DEVICE_PUBLIC="$(printf '%s\n' "${ROUNDTRIP}" | sed -n 's/^device_public=//p')"
[[ -n "${CONVERSATION}" && -n "${DEVICE_PUBLIC}" ]] || {
  echo "Vault smoke did not return durable identifiers" >&2
  exit 1
}

stop_vault

# Same encrypted state + same secret store must reproduce both history and key.
start_vault
"${SMOKE}" verify "${SOCKET}" "${CONVERSATION}" "${DEVICE_PUBLIC}"
stop_vault

# A public socket directory is rejected before listening.
BAD_IPC="${TMP}/bad-ipc"
mkdir -p "${BAD_IPC}"
chmod 755 "${BAD_IPC}"
if JEND_VAULT_SOCKET="${BAD_IPC}/vault.sock" "${VAULTD}" >"${TMP}/bad-perms.log" 2>&1; then
  echo "security regression: Vault accepted a public IPC directory" >&2
  exit 1
fi
grep -q "Vault IPC directory must be a private" "${TMP}/bad-perms.log" || {
  echo "public-directory check failed for an unexpected reason" >&2
  cat "${TMP}/bad-perms.log" >&2
  exit 1
}

echo "Jend Vault IPC process smoke: PASS"
