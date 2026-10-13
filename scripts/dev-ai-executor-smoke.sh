#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

TMP="$(mktemp -d "${TMPDIR:-/tmp}/jend-ai-smoke.XXXXXX")"
IPC_DIR="$TMP/ipc"
SOCKET="$IPC_DIR/ai.sock"
AUTH="$IPC_DIR/ai.auth"
mkdir -p "$IPC_DIR"
chmod 700 "$IPC_DIR"
PID=""
cleanup() {
  if [[ -n "$PID" ]]; then kill "$PID" 2>/dev/null || true; wait "$PID" 2>/dev/null || true; fi
  rm -rf "$TMP"
}
trap cleanup EXIT INT TERM

cargo build -p jend-model-store --bin jend-aid --bin jend-ai-smoke --locked
"$ROOT/target/debug/jend-aid" "$SOCKET" >"$TMP/aid.log" 2>&1 &
PID=$!
for _ in $(seq 1 100); do
  [[ -S "$SOCKET" && -f "$AUTH" ]] && break
  kill -0 "$PID" 2>/dev/null || { cat "$TMP/aid.log" >&2; exit 1; }
  sleep 0.05
done
[[ -S "$SOCKET" && -f "$AUTH" ]] || { cat "$TMP/aid.log" >&2; echo "AI daemon did not create IPC files" >&2; exit 1; }

# macOS/BSD and GNU stat compatibility.
mode_dir="$(stat -f '%Lp' "$IPC_DIR" 2>/dev/null || stat -c '%a' "$IPC_DIR")"
mode_socket="$(stat -f '%Lp' "$SOCKET" 2>/dev/null || stat -c '%a' "$SOCKET")"
mode_auth="$(stat -f '%Lp' "$AUTH" 2>/dev/null || stat -c '%a' "$AUTH")"
[[ "$mode_dir" == "700" ]] || { echo "AI IPC dir mode is $mode_dir, expected 700" >&2; exit 1; }
[[ "$mode_socket" == "600" ]] || { echo "AI IPC socket mode is $mode_socket, expected 600" >&2; exit 1; }
[[ "$mode_auth" == "600" ]] || { echo "AI IPC auth mode is $mode_auth, expected 600" >&2; exit 1; }

"$ROOT/target/debug/jend-ai-smoke" wrong-auth "$SOCKET"
"$ROOT/target/debug/jend-ai-smoke" roundtrip "$SOCKET"

# A second daemon must fail closed instead of replacing a live endpoint/token.
if "$ROOT/target/debug/jend-aid" "$SOCKET" >"$TMP/second.log" 2>&1; then
  echo "second AI daemon unexpectedly replaced live IPC state" >&2
  exit 1
fi

# The prompt must not have been persisted to the IPC/state directory.
if grep -R -a -F 'jend-ai-boundary-smoke-plaintext' "$TMP" --exclude='*.log' >/dev/null 2>&1; then
  echo "AI prompt plaintext was persisted outside process memory" >&2
  exit 1
fi

echo "Jend AI executor process smoke: PASS"
